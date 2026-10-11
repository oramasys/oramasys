"""T1: the Oramasys implementation of Core's neutral ``DispatchGate``.

One ``AdmissionGate`` is bound to one invocation (run, lease epoch, admission decision)
and is asked by Core's single scheduler before every executable boundary and every
commit. At each boundary it checks, in this fixed order:

1. authority and lease -- the admission decision still covers this exact artifact
   binding, has not expired by the injected clock, every owner decision is still
   current according to its owner (revocation), and this holder's lease epoch has
   not been fenced by a newer holder;
2. stop state -- an operator or system stop request ends the run cooperatively;
3. delivery health -- T1 has no delivery sinks, so the default reports healthy;
   T2-A replaces it with real sink health;
4. budget -- node and fan-out dispatches reserve steps in the single-writer ledger,
   a whole fan-out batch in one transaction (all or nothing). Routers, joins,
   reducers and commits reserve nothing; commits re-check 1-3 only.

Honest limits: a refusal stops future work and commits; it cannot undo an effect a
callable already caused. SQLite cannot make remote revocation atomic: revocation is
observed at the next boundary, never mid-call. Core's ``max_steps`` stays a
structural limit; the ledger enforces the admitted bound without double charging.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from orama.graph.admission import (
    AdmissionDecision,
    AdmissionProviders,
    AdmissionRefused,
    ArtifactBinding,
    Clock,
    _utc_now,
)

try:  # The seam exists only in Core revisions that include R4 T1.
    from perpetua_core.graph.gate import CommitRequest, DispatchRequest, GateDecision

    CORE_GATE_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised on the pre-T1 production pin
    CORE_GATE_AVAILABLE = False


class LeaseFenced(RuntimeError):
    """This holder's lease epoch is no longer current (a newer holder took it)."""


UnknownCause = Literal[
    "crash_before_intent",
    "crash_before_publish",
    "crash_before_settle",
    "critical_delivery_failure",
    "stop_timeout",
]
StopState = Literal["none", "requested", "acknowledged"]
SettlementState = Literal["unsettled", "settled", "irrelevant"]


@dataclass(frozen=True, slots=True)
class AttemptHold:
    """The immutable durable budget hold for one scheduler attempt."""

    run_id: str
    attempt_id: str
    hold_id: str
    fence_epoch: int
    units: int


@dataclass(frozen=True, slots=True)
class UnknownDisposition:
    """The version-one, conservative terminal record shared by REV3 streams."""

    attempt_id: str
    hold_id: str
    fence_epoch: int
    cause: UnknownCause
    stop_state: StopState
    settlement_state: SettlementState
    schema_version: Literal[1] = 1

    def __post_init__(self) -> None:
        """Reject unversioned terminal vocabulary before it reaches SQLite."""
        if (
            not isinstance(self.attempt_id, str)
            or not self.attempt_id
            or not isinstance(self.hold_id, str)
            or not self.hold_id
            or isinstance(self.fence_epoch, bool)
            or not isinstance(self.fence_epoch, int)
            or self.fence_epoch < 1
            or self.cause not in {
                "crash_before_intent",
                "crash_before_publish",
                "crash_before_settle",
                "critical_delivery_failure",
                "stop_timeout",
            }
            or self.stop_state not in {"none", "requested", "acknowledged"}
            or self.settlement_state not in {"unsettled", "settled", "irrelevant"}
            or self.schema_version != 1
        ):
            raise ValueError("unknown disposition has invalid version-one fields")


class StepLedger:
    """Single-writer SQLite step ledger with lease fencing (T1 foundation; T2-B extends).

    Every write runs in one ``BEGIN IMMEDIATE`` transaction, so reservations are atomic
    across processes. WAL with ``synchronous=FULL``. Integer units only.
    """

    def __init__(self, path: Path | str) -> None:
        """Open the durable ledger (WAL, synchronous FULL) at the given path."""
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS leases ("
            " run_id TEXT PRIMARY KEY,"
            " epoch INTEGER NOT NULL CHECK (epoch >= 1),"
            " max_steps INTEGER NOT NULL CHECK (max_steps >= 1),"
            " used INTEGER NOT NULL CHECK (used >= 0 AND used <= max_steps))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS attempt_holds ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL,"
            " hold_id TEXT NOT NULL UNIQUE, epoch INTEGER NOT NULL,"
            " units INTEGER NOT NULL CHECK (units >= 1),"
            " state TEXT NOT NULL CHECK (state IN ('held', 'unknown', 'settled', 'released')) ,"
            " PRIMARY KEY (run_id, attempt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS commit_intents ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, hold_id TEXT NOT NULL,"
            " epoch INTEGER NOT NULL, result_digest TEXT NOT NULL,"
            " PRIMARY KEY (run_id, attempt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS batch_reservations ("
            " run_id TEXT NOT NULL, batch_id TEXT NOT NULL, payload_digest TEXT NOT NULL,"
            " PRIMARY KEY (run_id, batch_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS batch_attempts ("
            " run_id TEXT NOT NULL, batch_id TEXT NOT NULL, attempt_id TEXT NOT NULL,"
            " PRIMARY KEY (run_id, batch_id, attempt_id),"
            " UNIQUE (run_id, attempt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS unknown_dispositions ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, hold_id TEXT NOT NULL,"
            " epoch INTEGER NOT NULL, cause TEXT NOT NULL, stop_state TEXT NOT NULL,"
            " settlement_state TEXT NOT NULL, schema_version INTEGER NOT NULL,"
            " PRIMARY KEY (run_id, attempt_id))"
        )

    def close(self) -> None:
        """Close the underlying database connection."""
        self._db.close()

    def pragmas(self) -> tuple[str, int]:
        """Return the journal mode and synchronous level in force."""
        mode = self._db.execute("PRAGMA journal_mode").fetchone()[0]
        sync = self._db.execute("PRAGMA synchronous").fetchone()[0]
        return str(mode).lower(), int(sync)

    def _tx(self):
        """Open an immediate write transaction guarded by the single-writer lock."""
        return _Immediate(self._db, self._lock)

    def open_lease(self, run_id: str, *, max_steps: int) -> int:
        """Take (or take over) the lease; returns the new epoch, fencing older holders.

        Steps already used stay charged across a take-over: a new holder never gets a
        fresh allowance for the same run.
        """
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError("max_steps must be a positive integer")
        with self._tx() as db:
            row = db.execute("SELECT epoch, used FROM leases WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO leases (run_id, epoch, max_steps, used) VALUES (?, 1, ?, 0)",
                    (run_id, max_steps),
                )
                return 1
            epoch = row[0] + 1
            db.execute(
                "UPDATE leases SET epoch = ?, max_steps = ? WHERE run_id = ?",
                (epoch, max(max_steps, row[1]), run_id),
            )
            return epoch

    def check(self, run_id: str, epoch: int) -> None:
        """Raise LeaseFenced unless the epoch is the current lease epoch."""
        row = self._db.execute("SELECT epoch FROM leases WHERE run_id = ?", (run_id,)).fetchone()
        if row is None or row[0] != epoch:
            raise LeaseFenced(run_id)

    def reserve(self, run_id: str, epoch: int, steps: int) -> bool:
        """Atomically charge ``steps`` under ``epoch``. False (and no charge) if it does
        not fit; ``LeaseFenced`` if the epoch is stale."""
        if isinstance(steps, bool) or not isinstance(steps, int) or steps < 1:
            raise ValueError("steps must be a positive integer")
        with self._tx() as db:
            row = db.execute(
                "SELECT epoch, max_steps, used FROM leases WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None or row[0] != epoch:
                raise LeaseFenced(run_id)
            if row[2] + steps > row[1]:
                return False
            db.execute("UPDATE leases SET used = used + ? WHERE run_id = ?", (steps, run_id))
            return True

    def limit(self, run_id: str) -> int | None:
        """The stored step limit for ``run_id``'s lease, or None if there is no lease."""
        row = self._db.execute("SELECT max_steps FROM leases WHERE run_id = ?", (run_id,)).fetchone()
        return None if row is None else int(row[0])

    def used(self, run_id: str) -> int:
        """Return the steps already charged for the run."""
        row = self._db.execute("SELECT used FROM leases WHERE run_id = ?", (run_id,)).fetchone()
        return 0 if row is None else int(row[0])

    def reserve_attempt(
        self, run_id: str, epoch: int, attempt_id: str, *, units: int
    ) -> AttemptHold:
        """Reserve one idempotent attempt hold inside the lease transaction."""
        self._validate_attempt_inputs(run_id, epoch, attempt_id, units)
        with self._tx() as db:
            existing = db.execute(
                "SELECT hold_id, epoch, units FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if int(existing[1]) != epoch or int(existing[2]) != units:
                    raise ValueError("attempt reservation conflicts with its existing hold")
                return AttemptHold(run_id, attempt_id, str(existing[0]), epoch, units)
            row = self._lease_row(db, run_id, epoch)
            if int(row[2]) + units > int(row[1]):
                raise ValueError("budget exhausted")
            hold_id = self._hold_id(run_id, attempt_id)
            db.execute(
                "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) "
                "VALUES (?, ?, ?, ?, ?, 'held')",
                (run_id, attempt_id, hold_id, epoch, units),
            )
            db.execute("UPDATE leases SET used = used + ? WHERE run_id = ?", (units, run_id))
            return AttemptHold(run_id, attempt_id, hold_id, epoch, units)

    def reserve_batch(
        self,
        run_id: str,
        epoch: int,
        batch_id: str,
        attempts: tuple[tuple[str, int], ...],
    ) -> tuple[AttemptHold, ...]:
        """Reserve all fan-out attempts or none, with payload-stable replay."""
        if not isinstance(batch_id, str) or not batch_id:
            raise ValueError("batch_id must be a non-empty string")
        if not attempts:
            raise ValueError("a batch needs at least one attempt")
        if len({attempt_id for attempt_id, _ in attempts}) != len(attempts):
            raise ValueError("batch attempt ids must be unique")
        for attempt_id, units in attempts:
            self._validate_attempt_inputs(run_id, epoch, attempt_id, units)
        payload = hashlib.sha256(
            json.dumps(sorted(attempts), separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self._tx() as db:
            existing = db.execute(
                "SELECT payload_digest FROM batch_reservations WHERE run_id = ? AND batch_id = ?",
                (run_id, batch_id),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != payload:
                    raise ValueError("batch_id payload conflicts with existing reservation")
                # Databases created before batch membership was materialized
                # retain only the verified payload digest. A matching replay is
                # enough to safely backfill the missing member index.
                for attempt_id, _ in attempts:
                    db.execute(
                        "INSERT OR IGNORE INTO batch_attempts (run_id, batch_id, attempt_id) "
                        "VALUES (?, ?, ?)",
                        (run_id, batch_id, attempt_id),
                    )
                return tuple(self._hold_for(db, run_id, attempt_id) for attempt_id, _ in attempts)
            row = self._lease_row(db, run_id, epoch)
            total = sum(units for _, units in attempts)
            if int(row[2]) + total > int(row[1]):
                raise ValueError("budget exhausted")
            db.execute(
                "INSERT INTO batch_reservations (run_id, batch_id, payload_digest) VALUES (?, ?, ?)",
                (run_id, batch_id, payload),
            )
            holds: list[AttemptHold] = []
            for attempt_id, units in attempts:
                hold_id = self._hold_id(run_id, attempt_id)
                db.execute(
                    "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) "
                    "VALUES (?, ?, ?, ?, ?, 'held')",
                    (run_id, attempt_id, hold_id, epoch, units),
                )
                db.execute(
                    "INSERT INTO batch_attempts (run_id, batch_id, attempt_id) VALUES (?, ?, ?)",
                    (run_id, batch_id, attempt_id),
                )
                holds.append(AttemptHold(run_id, attempt_id, hold_id, epoch, units))
            db.execute("UPDATE leases SET used = used + ? WHERE run_id = ?", (total, run_id))
            return tuple(holds)

    def prepare_commit(
        self, run_id: str, attempt_id: str, hold_id: str, epoch: int, result_digest: str
    ) -> bool:
        """Durably record an exact commit intent before publication.

        True means this call inserted the intent. False is an identical retry.
        """
        if not isinstance(result_digest, str) or not result_digest:
            raise ValueError("result digest must be a non-empty string")
        with self._tx() as db:
            hold = self._hold_for(db, run_id, attempt_id)
            if hold.hold_id != hold_id or hold.fence_epoch != epoch or self._hold_state(db, run_id, attempt_id) != "held":
                raise ValueError("commit intent does not match a current held attempt")
            existing = db.execute(
                "SELECT hold_id, epoch, result_digest FROM commit_intents WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != (hold_id, epoch, result_digest):
                    raise ValueError("commit intent digest conflicts with existing intent")
                return False
            db.execute(
                "INSERT INTO commit_intents (run_id, attempt_id, hold_id, epoch, result_digest) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, attempt_id, hold_id, epoch, result_digest),
            )
            return True

    def settle_commit(self, run_id: str, attempt_id: str, result_digest: str) -> bool:
        """Settle a prepared commit once; an identical retry is a no-op."""
        with self._tx() as db:
            intent = db.execute(
                "SELECT result_digest FROM commit_intents WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if intent is None or str(intent[0]) != result_digest:
                raise ValueError("settlement lacks a matching commit intent")
            state = self._hold_state(db, run_id, attempt_id)
            if state == "settled":
                return False
            if state != "held":
                raise ValueError("only a held attempt may settle")
            db.execute(
                "UPDATE attempt_holds SET state = 'settled' WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            )
            return True

    def prepare_batch_commit(
        self,
        run_id: str,
        batch_id: str,
        attempt_ids: tuple[str, ...],
        epoch: int,
        result_digest: str,
    ) -> bool:
        """Prepare every admitted branch of a reserved batch atomically.

        A join may publish only a subset of executed branches. This binds only
        the admitted attempts to the region delta; every other hold remains
        reserved until an explicit future reconciliation path handles it.
        """
        if not isinstance(result_digest, str) or not result_digest:
            raise ValueError("result digest must be a non-empty string")
        with self._tx() as db:
            attempts = self._batch_attempt_ids(db, run_id, batch_id, attempt_ids)
            changed = False
            for attempt_id in attempts:
                hold = self._hold_for(db, run_id, attempt_id)
                if (
                    hold.fence_epoch != epoch
                    or self._hold_state(db, run_id, attempt_id) != "held"
                ):
                    raise ValueError("batch commit does not match a current held attempt")
                existing = db.execute(
                    "SELECT hold_id, epoch, result_digest FROM commit_intents "
                    "WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone()
                expected = (hold.hold_id, epoch, result_digest)
                if existing is not None:
                    if tuple(existing) != expected:
                        raise ValueError("batch commit digest conflicts with existing intent")
                    continue
                db.execute(
                    "INSERT INTO commit_intents (run_id, attempt_id, hold_id, epoch, result_digest) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (run_id, attempt_id, *expected),
                )
                changed = True
            return changed

    def settle_batch_commit(
        self,
        run_id: str,
        batch_id: str,
        attempt_ids: tuple[str, ...],
        result_digest: str,
    ) -> bool:
        """Settle every prepared admitted branch of a batch atomically."""
        with self._tx() as db:
            attempts = self._batch_attempt_ids(db, run_id, batch_id, attempt_ids)
            changed = False
            for attempt_id in attempts:
                intent = db.execute(
                    "SELECT result_digest FROM commit_intents WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone()
                if intent is None or str(intent[0]) != result_digest:
                    raise ValueError("batch settlement lacks a matching commit intent")
                state = self._hold_state(db, run_id, attempt_id)
                if state == "settled":
                    continue
                if state != "held":
                    raise ValueError("only a held attempt may settle")
                db.execute(
                    "UPDATE attempt_holds SET state = 'settled' WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                )
                changed = True
            return changed

    def mark_unknown(self, run_id: str, disposition: UnknownDisposition) -> None:
        """Persist an uncertain attempt without releasing its reserved units."""
        with self._tx() as db:
            hold = self._hold_for(db, run_id, disposition.attempt_id)
            if hold.hold_id != disposition.hold_id or hold.fence_epoch != disposition.fence_epoch:
                raise ValueError("unknown disposition does not match its hold")
            existing = db.execute(
                "SELECT hold_id, epoch, cause, stop_state, settlement_state, schema_version FROM unknown_dispositions "
                "WHERE run_id = ? AND attempt_id = ?",
                (run_id, disposition.attempt_id),
            ).fetchone()
            expected = (
                disposition.hold_id,
                disposition.fence_epoch,
                disposition.cause,
                disposition.stop_state,
                disposition.settlement_state,
                disposition.schema_version,
            )
            if existing is not None:
                if tuple(existing) != expected:
                    raise ValueError("unknown disposition conflicts with existing record")
                return
            db.execute(
                "INSERT INTO unknown_dispositions (run_id, attempt_id, hold_id, epoch, cause, stop_state, settlement_state, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, disposition.attempt_id, *expected),
            )
            db.execute(
                "UPDATE attempt_holds SET state = 'unknown' WHERE run_id = ? AND attempt_id = ?",
                (run_id, disposition.attempt_id),
            )

    def hold_state(self, run_id: str, attempt_id: str) -> str | None:
        """Return an attempt's durable state, if it exists."""
        row = self._db.execute(
            "SELECT state FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
            (run_id, attempt_id),
        ).fetchone()
        return None if row is None else str(row[0])

    def hold(self, run_id: str, attempt_id: str) -> AttemptHold:
        """Return one durable hold for an external lifecycle transition."""
        return self._hold_for(self._db, run_id, attempt_id)

    def batch_ids(self, run_id: str) -> tuple[str, ...]:
        """Return the durable fan-out batch identities for one run."""
        rows = self._db.execute(
            "SELECT batch_id FROM batch_reservations WHERE run_id = ? ORDER BY batch_id", (run_id,)
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def batch_hold_states(self, run_id: str, batch_id: str) -> dict[str, str]:
        """Return the durable member states for one fan-out batch."""
        rows = self._db.execute(
            "SELECT member.attempt_id, hold.state FROM batch_attempts AS member "
            "JOIN attempt_holds AS hold USING (run_id, attempt_id) "
            "WHERE member.run_id = ? AND member.batch_id = ? ORDER BY member.attempt_id",
            (run_id, batch_id),
        ).fetchall()
        return {str(attempt_id): str(state) for attempt_id, state in rows}

    def release_attempt(self, run_id: str, attempt_id: str, epoch: int) -> None:
        """Reject direct unknown release until a verified adjustment-grant path exists."""
        with self._tx() as db:
            hold = self._hold_for(db, run_id, attempt_id)
            if hold.fence_epoch != epoch:
                raise LeaseFenced(run_id)
            if self._hold_state(db, run_id, attempt_id) == "unknown":
                raise ValueError("unknown holds require an authenticated adjustment grant")
            raise ValueError("direct release is not an approved accounting transition")

    @staticmethod
    def _hold_id(run_id: str, attempt_id: str) -> str:
        """Build a deterministic opaque hold identity without a random retry path."""
        payload = f"{run_id}\0{attempt_id}".encode("utf-8")
        return f"hold:{hashlib.sha256(payload).hexdigest()}"

    @staticmethod
    def _validate_attempt_inputs(run_id: str, epoch: int, attempt_id: str, units: int) -> None:
        """Validate the common deterministic hold identity and charge fields."""
        if not isinstance(run_id, str) or not run_id or not isinstance(attempt_id, str) or not attempt_id:
            raise ValueError("run_id and attempt_id must be non-empty strings")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise ValueError("epoch must be a positive integer")
        if isinstance(units, bool) or not isinstance(units, int) or units < 1:
            raise ValueError("units must be a positive integer")

    @staticmethod
    def _lease_row(db: sqlite3.Connection, run_id: str, epoch: int) -> tuple[int, int, int]:
        """Return the current lease row or fence a stale/unknown holder."""
        row = db.execute(
            "SELECT epoch, max_steps, used FROM leases WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None or int(row[0]) != epoch:
            raise LeaseFenced(run_id)
        return int(row[0]), int(row[1]), int(row[2])

    @staticmethod
    def _hold_for(db: sqlite3.Connection, run_id: str, attempt_id: str) -> AttemptHold:
        """Read one immutable hold or refuse an unprepared lifecycle transition."""
        row = db.execute(
            "SELECT hold_id, epoch, units FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
            (run_id, attempt_id),
        ).fetchone()
        if row is None:
            raise ValueError("attempt has no durable hold")
        return AttemptHold(run_id, attempt_id, str(row[0]), int(row[1]), int(row[2]))

    @staticmethod
    def _hold_state(db: sqlite3.Connection, run_id: str, attempt_id: str) -> str:
        """Read the current durable hold state after existence is established."""
        row = db.execute(
            "SELECT state FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
            (run_id, attempt_id),
        ).fetchone()
        assert row is not None
        return str(row[0])

    @staticmethod
    def _batch_attempt_ids(
        db: sqlite3.Connection,
        run_id: str,
        batch_id: str,
        attempt_ids: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Validate a non-empty admitted subset against recorded batch members."""
        if not isinstance(batch_id, str) or not batch_id:
            raise ValueError("batch_id must be a non-empty string")
        if not attempt_ids or len(set(attempt_ids)) != len(attempt_ids):
            raise ValueError("batch commit needs unique admitted attempts")
        members = {
            str(row[0])
            for row in db.execute(
                "SELECT attempt_id FROM batch_attempts WHERE run_id = ? AND batch_id = ?",
                (run_id, batch_id),
            )
        }
        if not members or not set(attempt_ids).issubset(members):
            raise ValueError("batch commit attempts do not match the reservation")
        return attempt_ids


class _Immediate:
    """Context manager running a BEGIN IMMEDIATE transaction under a lock."""
    def __init__(self, db: sqlite3.Connection, lock: threading.Lock) -> None:
        """Keep the connection and the lock for the transaction."""
        self._db, self._lock = db, lock

    def __enter__(self) -> sqlite3.Connection:
        """Enter the context and return the managed resource."""
        self._lock.acquire()
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._lock.release()
            raise
        return self._db

    def __exit__(self, exc_type, exc, tb) -> None:
        """Leave the context, committing on success and rolling back on error."""
        try:
            self._db.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self._lock.release()


@dataclass
class StopSignal:
    """Cooperative stop request; the gate turns it into a Core ``stop`` decision."""

    reason: str | None = None

    def request(self, reason: str) -> None:
        """Record a stop request with its reason code."""
        if not reason:
            raise ValueError("a stop needs a reason code")
        if self.reason is None:
            self.reason = reason


class DeliveryHealth(Protocol):
    """Reports whether result delivery sinks are healthy."""
    def healthy(self) -> bool:
        """Report whether delivery is healthy."""


class NoDeliverySinks:
    """T1 has no observation delivery, so nothing can be behind. T2-A replaces this."""

    def healthy(self) -> bool:
        """Report healthy: with no sinks configured there is nothing to fail."""
        return True


@dataclass
class AdmissionGate:
    """Core DispatchGate enforcing admission, stop, delivery health and budget."""
    decision: AdmissionDecision
    binding: ArtifactBinding
    providers: AdmissionProviders
    ledger: StepLedger
    run_id: str
    lease_epoch: int
    stop: StopSignal
    clock: Clock
    delivery: DeliveryHealth = field(default_factory=NoDeliverySinks)

    def __post_init__(self) -> None:
        """Fail closed unless Core's gate seam exists and the lease matches admission."""
        if not CORE_GATE_AVAILABLE:
            raise AdmissionRefused("gate.core_seam_unavailable")
        if self.decision.outcome != "allow":
            raise AdmissionRefused("gate.decision_not_allowed")
        # The ledger must enforce no more than admission granted. A missing lease, or one
        # opened (or taken over) with a wider limit, is refused at construction.
        limit = self.ledger.limit(self.run_id)
        if limit is None or limit > self.decision.max_steps:
            raise AdmissionRefused("gate.ledger_bound_exceeds_admission")

    # Core DispatchGate protocol -------------------------------------------------

    async def before_dispatch(self, request: DispatchRequest) -> GateDecision:
        """Check authority, stop, delivery and reserve budget before the call."""
        early = self._common()
        if early is not None:
            return early
        if request.boundary == "node":
            try:
                self.ledger.reserve_attempt(
                    self.run_id,
                    self.lease_epoch,
                    self._attempt_id(request.boundary, request.nodes, request.steps, request.source),
                    units=len(request.nodes),
                )
            except LeaseFenced:
                return GateDecision.refuse("authority.lease_fenced")
            except ValueError as error:
                if str(error) == "budget exhausted":
                    return GateDecision.refuse("budget.steps_exhausted")
                return GateDecision.refuse("ledger.attempt_invalid")
        elif request.boundary == "fanout":
            try:
                if not isinstance(request.batch_id, str) or not request.batch_id:
                    return GateDecision.refuse("ledger.batch_id_missing")
                self.ledger.reserve_batch(
                    self.run_id,
                    self.lease_epoch,
                    request.batch_id,
                    tuple((f"{request.batch_id}:{name}", 1) for name in request.nodes),
                )
            except LeaseFenced:
                return GateDecision.refuse("authority.lease_fenced")
            except ValueError as error:
                if str(error) == "budget exhausted":
                    return GateDecision.refuse("budget.steps_exhausted")
                return GateDecision.refuse("ledger.batch_invalid")
        return GateDecision.allow()

    async def before_commit(self, request: CommitRequest) -> GateDecision:
        """Prepare a durable node intent before Core synchronously publishes it."""
        early = self._common()
        if early is not None:
            return early
        if request.boundary not in {"node", "region"}:
            return GateDecision.allow()
        if not isinstance(request.result_digest, str) or not request.result_digest:
            return GateDecision.refuse("ledger.commit_digest_missing")
        if request.boundary == "region":
            if not isinstance(request.batch_id, str) or not request.batch_id:
                return GateDecision.refuse("ledger.batch_id_missing")
            try:
                self.ledger.prepare_batch_commit(
                    self.run_id,
                    request.batch_id,
                    tuple(f"{request.batch_id}:{name}" for name in request.nodes),
                    self.lease_epoch,
                    request.result_digest,
                )
            except LeaseFenced:
                return GateDecision.refuse("authority.lease_fenced")
            except ValueError:
                return GateDecision.refuse("ledger.commit_unprepared")
            return GateDecision.allow()
        attempt_id = self._attempt_id(request.boundary, request.nodes, request.steps, request.source)
        try:
            hold = self.ledger.hold(self.run_id, attempt_id)
            self.ledger.prepare_commit(
                self.run_id,
                attempt_id,
                hold.hold_id,
                self.lease_epoch,
                request.result_digest,
            )
        except LeaseFenced:
            return GateDecision.refuse("authority.lease_fenced")
        except ValueError:
            return GateDecision.refuse("ledger.commit_unprepared")
        return GateDecision.allow()

    async def after_commit(self, request: CommitRequest) -> None:
        """Settle the matching node hold after Core has published its delta."""
        if request.boundary not in {"node", "region"}:
            return
        if not isinstance(request.result_digest, str) or not request.result_digest:
            raise AdmissionRefused("ledger.commit_digest_missing")
        if request.boundary == "region":
            if not isinstance(request.batch_id, str) or not request.batch_id:
                raise AdmissionRefused("ledger.batch_id_missing")
            self.ledger.settle_batch_commit(
                self.run_id,
                request.batch_id,
                tuple(f"{request.batch_id}:{name}" for name in request.nodes),
                request.result_digest,
            )
            return
        attempt_id = self._attempt_id(request.boundary, request.nodes, request.steps, request.source)
        self.ledger.settle_commit(self.run_id, attempt_id, request.result_digest)

    # Fixed order: authority and lease, stop, delivery ---------------------------

    def _common(self) -> GateDecision | None:
        """Run the authority, stop and delivery checks shared by every boundary."""
        reason = self._authority()
        if reason is not None:
            return GateDecision.refuse(reason)
        if self.stop.reason is not None:
            return GateDecision.stop(self.stop.reason)
        if not self.delivery.healthy():
            return GateDecision.refuse("delivery.unhealthy")
        return None

    def _authority(self) -> str | None:
        """Return a refusal reason if admission is stale, revoked, expired or fenced."""
        if not self.decision.covers(self.binding):
            return "authority.binding_changed"
        try:
            now = _utc_now(self.clock)
        except AdmissionRefused:
            return "authority.clock_invalid"
        if self.decision.expires_at is None or now >= self.decision.expires_at:
            return "authority.expired"
        for owner_decision in self.decision.owner_decisions:
            is_current = self.providers.checker(owner_decision.owner)
            if is_current is None:
                return "authority.owner_unavailable"
            try:
                current = is_current(owner_decision)
            except Exception:  # noqa: BLE001 - an owner that cannot answer refuses
                return "authority.owner_unavailable"
            if not current:
                return "authority.owner_decision_stale"
        try:
            self.ledger.check(self.run_id, self.lease_epoch)
        except LeaseFenced:
            return "authority.lease_fenced"
        return None

    @staticmethod
    def _attempt_id(
        boundary: str, nodes: tuple[str, ...], steps: int, source: str | None
    ) -> str:
        """Derive a deterministic per-run attempt key from the neutral Core request."""
        parts = [boundary, *nodes, str(steps)]
        if source is not None:
            parts.append(source)
        return "::".join(parts)
