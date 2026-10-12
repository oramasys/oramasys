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
   a whole fan-out batch in one transaction (all or nothing). The optional T2
   start seam also reserves actual callable routers, joins and custom reducers.
   Historical Core without that seam retains the T1 step-only behavior; explicit
   multi-unit opt-in requires the start seam and caller-supplied limits/allowances.

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
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from orama.graph.accounting_types import ChargeUnits

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


def core_start_seam_available() -> bool:
    """Report whether the installed Core exposes the durable callable-start seam."""
    try:
        from perpetua_core.graph.engine import CompiledGraph
    except ImportError:  # pragma: no cover - Core absent entirely
        return False
    return hasattr(CompiledGraph, "_before_start")


class LeaseFenced(RuntimeError):
    """This holder's lease epoch is no longer current (a newer holder took it)."""


class DurableStopRequested(RuntimeError):
    """A persisted stop won the transaction order before a commit intent."""

    def __init__(self, reason: str) -> None:
        """Expose the stable reason for conversion into a Core stop decision."""
        super().__init__(reason)
        self.reason = reason


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


@dataclass(frozen=True, slots=True)
class AccountingEvent:
    """One immutable schema-v2 accounting event in insertion order."""

    sequence: int
    schema_version: int
    run_id: str
    operation_id: str
    event_type: str
    epoch: int
    payload_digest: str
    payload_json: str


@dataclass(frozen=True, slots=True)
class AccountingRecovery:
    """Durable takeover result; recovery classifies attempts and never replays them."""

    released: tuple[str, ...]
    unknown: tuple[str, ...]
    preserved_unknown: tuple[str, ...]


class StepLedger:
    """Single-writer SQLite step ledger with lease fencing (T1 foundation; T2-B extends).

    Every write runs in one ``BEGIN IMMEDIATE`` transaction, so reservations are atomic
    across processes. WAL with ``synchronous=FULL``. Integer units only.
    """

    SCHEMA_VERSION = 2
    SQLITE_MAX_INT = 2**63 - 1
    LEGACY_COST_BASIS = "legacy_step_only"

    def __init__(self, path: Path | str) -> None:
        """Open the durable ledger (WAL, synchronous FULL) at the given path."""
        from orama.graph.private_store import prepare_private_store

        path = prepare_private_store(path)
        self._store_path = str(path.resolve())
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
            "CREATE TABLE IF NOT EXISTS stop_requests ("
            " run_id TEXT PRIMARY KEY, principal TEXT NOT NULL, reason TEXT NOT NULL)"
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
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS accounting_schema ("
            " singleton INTEGER PRIMARY KEY CHECK (singleton = 1),"
            " version INTEGER NOT NULL)"
        )
        self._db.execute(
            "INSERT OR IGNORE INTO accounting_schema (singleton, version) VALUES (1, 2)"
        )
        version = self._db.execute(
            "SELECT version FROM accounting_schema WHERE singleton = 1"
        ).fetchone()
        if version is None or int(version[0]) != self.SCHEMA_VERSION:
            raise ValueError("unsupported accounting schema version")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS charge_limits ("
            " run_id TEXT PRIMARY KEY, cost_basis TEXT NOT NULL,"
            " steps INTEGER NOT NULL, elapsed_ms INTEGER NOT NULL,"
            " cost_microunits INTEGER NOT NULL, effect_attempts INTEGER NOT NULL,"
            " payload_digest TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS charge_projection ("
            " run_id TEXT PRIMARY KEY, cost_basis TEXT NOT NULL,"
            " elapsed_ms INTEGER NOT NULL CHECK (elapsed_ms >= 0),"
            " cost_microunits INTEGER NOT NULL CHECK (cost_microunits >= 0),"
            " effect_attempts INTEGER NOT NULL CHECK (effect_attempts >= 0))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS charge_reservations ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, hold_id TEXT NOT NULL UNIQUE,"
            " epoch INTEGER NOT NULL, cost_basis TEXT NOT NULL,"
            " steps INTEGER NOT NULL, elapsed_ms INTEGER NOT NULL,"
            " cost_microunits INTEGER NOT NULL, effect_attempts INTEGER NOT NULL,"
            " payload_digest TEXT NOT NULL, PRIMARY KEY (run_id, attempt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS charge_batches ("
            " run_id TEXT NOT NULL, batch_id TEXT NOT NULL, payload_digest TEXT NOT NULL,"
            " PRIMARY KEY (run_id, batch_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS accounting_starts ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, epoch INTEGER NOT NULL,"
            " PRIMARY KEY (run_id, attempt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS accounting_outcomes ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, epoch INTEGER NOT NULL,"
            " result_digest TEXT NOT NULL, PRIMARY KEY (run_id, attempt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS usage_receipts ("
            " run_id TEXT NOT NULL, attempt_id TEXT NOT NULL, epoch INTEGER NOT NULL,"
            " receipt_id TEXT NOT NULL, usage_known INTEGER NOT NULL, cost_basis TEXT,"
            " steps INTEGER, elapsed_ms INTEGER, cost_microunits INTEGER,"
            " effect_attempts INTEGER, payload_digest TEXT NOT NULL,"
            " PRIMARY KEY (run_id, attempt_id), UNIQUE (run_id, receipt_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS accounting_time_highwater ("
            " run_id TEXT PRIMARY KEY, observed_utc TEXT NOT NULL, epoch INTEGER NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS accounting_events ("
            " sequence INTEGER PRIMARY KEY AUTOINCREMENT, schema_version INTEGER NOT NULL,"
            " run_id TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,"
            " event_type TEXT NOT NULL, epoch INTEGER NOT NULL,"
            " payload_digest TEXT NOT NULL, payload_json TEXT NOT NULL)"
        )

    def close(self) -> None:
        """Close the underlying database connection."""
        self._db.close()

    @property
    def database_path(self) -> str:
        """Return SQLite's canonical file path for shared-authority checks."""
        row = self._db.execute("PRAGMA database_list").fetchone()
        return "" if row is None else str(row[2])

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
        if (
            isinstance(max_steps, bool)
            or not isinstance(max_steps, int)
            or max_steps < 1
            or max_steps > self.SQLITE_MAX_INT
        ):
            raise ValueError("max_steps must be a positive integer")
        with self._tx() as db:
            self._assert_run_not_terminal(db, run_id)
            row = db.execute("SELECT epoch, used FROM leases WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO leases (run_id, epoch, max_steps, used) VALUES (?, 1, ?, 0)",
                    (run_id, max_steps),
                )
                return 1
            configured = db.execute(
                "SELECT steps FROM charge_limits WHERE run_id = ?", (run_id,)
            ).fetchone()
            if configured is not None and int(configured[0]) != max_steps:
                raise ValueError("configured charge step limit is immutable")
            if int(row[0]) >= self.SQLITE_MAX_INT:
                raise ValueError("lease epoch exceeds SQLite integer range")
            epoch = int(row[0]) + 1
            db.execute(
                "UPDATE leases SET epoch = ?, max_steps = ? WHERE run_id = ?",
                (epoch, max(max_steps, row[1]), run_id),
            )
            return epoch

    def check(self, run_id: str, epoch: int) -> None:
        """Raise LeaseFenced unless the epoch is the current lease epoch."""
        self._assert_run_not_terminal(self._db, run_id)
        row = self._db.execute("SELECT epoch FROM leases WHERE run_id = ?", (run_id,)).fetchone()
        if row is None or row[0] != epoch:
            raise LeaseFenced(run_id)

    def reserve(self, run_id: str, epoch: int, steps: int) -> bool:
        """Atomically charge ``steps`` under ``epoch``. False (and no charge) if it does
        not fit; ``LeaseFenced`` if the epoch is stale."""
        if (
            isinstance(steps, bool)
            or not isinstance(steps, int)
            or steps < 1
            or steps > self.SQLITE_MAX_INT
        ):
            raise ValueError("steps must be a positive integer")
        with self._tx() as db:
            _, max_steps, used = self._lease_row(db, run_id, epoch)
            if db.execute(
                "SELECT 1 FROM charge_limits WHERE run_id = ?", (run_id,)
            ).fetchone() is not None:
                raise ValueError("configured runs must use reserve_charge")
            if used + steps > max_steps:
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

    def configure_limits(self, run_id: str, epoch: int, limits: ChargeUnits) -> bool:
        """Opt a run into immutable multi-unit limits without creating a second step limit."""
        self._validate_charge(limits, allow_zero_steps=True)
        payload_json, payload_digest = self._canonical_payload(limits.to_dict())
        with self._tx() as db:
            _, max_steps, _ = self._lease_row(db, run_id, epoch)
            if limits.steps != max_steps:
                raise ValueError("charge step limit must equal the lease step limit")
            existing = db.execute(
                "SELECT payload_digest FROM charge_limits WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != payload_digest:
                    raise ValueError("charge limits conflict with existing limits")
                return False
            db.execute(
                "INSERT INTO charge_limits (run_id, cost_basis, steps, elapsed_ms, "
                "cost_microunits, effect_attempts, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    limits.cost_basis,
                    limits.steps,
                    limits.elapsed_ms,
                    limits.cost_microunits,
                    limits.effect_attempts,
                    payload_digest,
                ),
            )
            db.execute(
                "INSERT INTO charge_projection (run_id, cost_basis, elapsed_ms, "
                "cost_microunits, effect_attempts) VALUES (?, ?, 0, 0, 0)",
                (run_id, limits.cost_basis),
            )
            self._append_event(
                db,
                run_id=run_id,
                operation_id=self._operation_id("limits", run_id),
                event_type="limits_configured",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return True

    def usage(self, run_id: str) -> ChargeUnits:
        """Return the durable projection; lease ``used`` is the sole steps authority."""
        lease = self._db.execute("SELECT used FROM leases WHERE run_id = ?", (run_id,)).fetchone()
        limits = self._db.execute(
            "SELECT cost_basis FROM charge_limits WHERE run_id = ?", (run_id,)
        ).fetchone()
        projection = self._db.execute(
            "SELECT elapsed_ms, cost_microunits, effect_attempts FROM charge_projection "
            "WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return ChargeUnits(
            0 if lease is None else int(lease[0]),
            0 if projection is None else int(projection[0]),
            0 if projection is None else int(projection[1]),
            0 if projection is None else int(projection[2]),
            cost_basis=self.LEGACY_COST_BASIS if limits is None else str(limits[0]),
        )

    def events(self, run_id: str) -> tuple[AccountingEvent, ...]:
        """Return immutable schema-v2 accounting events in durable insertion order."""
        rows = self._db.execute(
            "SELECT sequence, schema_version, run_id, operation_id, event_type, epoch, "
            "payload_digest, payload_json FROM accounting_events "
            "WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        ).fetchall()
        return tuple(
            AccountingEvent(
                sequence=int(row[0]),
                schema_version=int(row[1]),
                run_id=str(row[2]),
                operation_id=str(row[3]),
                event_type=str(row[4]),
                epoch=int(row[5]),
                payload_digest=str(row[6]),
                payload_json=str(row[7]),
            )
            for row in rows
        )

    def reserve_charge(
        self, run_id: str, epoch: int, attempt_id: str, charge: ChargeUnits
    ) -> AttemptHold:
        """Reserve one multi-unit hold atomically under configured limits."""
        self._validate_charge(charge)
        self._validate_attempt_inputs(run_id, epoch, attempt_id, charge.steps)
        hold_id = self._hold_id(run_id, attempt_id)
        payload = {
            "attempt_id": attempt_id,
            "hold_id": hold_id,
            "charge": charge.to_dict(),
            "marker_required": True,
        }
        payload_json, payload_digest = self._canonical_payload(payload)
        with self._tx() as db:
            _, max_steps, used = self._lease_row(db, run_id, epoch)
            limits = self._charge_for(db, "charge_limits", run_id)
            if limits is None:
                raise ValueError("charge limits are not configured")
            if charge.cost_basis != limits.cost_basis:
                raise ValueError("cost_basis must match configured limits")
            existing = db.execute(
                "SELECT payload_digest FROM charge_reservations "
                "WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != payload_digest:
                    raise ValueError("attempt charge conflicts with existing reservation")
                return self._hold_for(db, run_id, attempt_id)
            if db.execute(
                "SELECT 1 FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone() is not None:
                raise ValueError("attempt charge conflicts with existing hold")
            current = self._projection_for(db, run_id, limits.cost_basis)
            if (
                used + charge.steps > max_steps
                or used + charge.steps > limits.steps
                or not (current + charge).fits_within(limits)
            ):
                raise ValueError("budget exhausted")
            db.execute(
                "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) "
                "VALUES (?, ?, ?, ?, ?, 'held')",
                (run_id, attempt_id, hold_id, epoch, charge.steps),
            )
            db.execute(
                "INSERT INTO charge_reservations (run_id, attempt_id, hold_id, epoch, "
                "cost_basis, steps, elapsed_ms, cost_microunits, effect_attempts, payload_digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    attempt_id,
                    hold_id,
                    epoch,
                    charge.cost_basis,
                    charge.steps,
                    charge.elapsed_ms,
                    charge.cost_microunits,
                    charge.effect_attempts,
                    payload_digest,
                ),
            )
            self._increase_projection(db, run_id, charge)
            db.execute("UPDATE leases SET used = used + ? WHERE run_id = ?", (charge.steps, run_id))
            self._append_event(
                db,
                run_id=run_id,
                operation_id=self._reservation_operation_id(run_id, attempt_id),
                event_type="reservation_tracked",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return AttemptHold(run_id, attempt_id, hold_id, epoch, charge.steps)

    def reserve_charge_batch(
        self,
        run_id: str,
        epoch: int,
        batch_id: str,
        attempts: tuple[tuple[str, ChargeUnits], ...],
    ) -> tuple[AttemptHold, ...]:
        """Reserve a multi-unit fan-out atomically with payload-stable retries."""
        if not isinstance(batch_id, str) or not batch_id:
            raise ValueError("batch_id must be a non-empty string")
        if not attempts:
            raise ValueError("a batch needs at least one attempt")
        if len({attempt_id for attempt_id, _ in attempts}) != len(attempts):
            raise ValueError("batch attempt ids must be unique")
        for attempt_id, charge in attempts:
            self._validate_charge(charge)
            self._validate_attempt_inputs(run_id, epoch, attempt_id, charge.steps)
        payload_items = [
            {"attempt_id": attempt_id, "charge": charge.to_dict()}
            for attempt_id, charge in sorted(attempts, key=lambda item: item[0])
        ]
        _, batch_digest = self._canonical_payload({"attempts": payload_items})
        with self._tx() as db:
            _, max_steps, used = self._lease_row(db, run_id, epoch)
            limits = self._charge_for(db, "charge_limits", run_id)
            if limits is None:
                raise ValueError("charge limits are not configured")
            existing_batch = db.execute(
                "SELECT payload_digest FROM charge_batches WHERE run_id = ? AND batch_id = ?",
                (run_id, batch_id),
            ).fetchone()
            if existing_batch is not None:
                if str(existing_batch[0]) != batch_digest:
                    raise ValueError("batch_id payload conflicts with existing reservation")
                return tuple(self._hold_for(db, run_id, attempt_id) for attempt_id, _ in attempts)
            total_values = {
                name: sum(getattr(charge, name) for _, charge in attempts)
                for name in ChargeUnits._QUANTITY_FIELDS
            }
            total = ChargeUnits(**total_values, cost_basis=limits.cost_basis)
            self._validate_charge(total)
            if any(charge.cost_basis != limits.cost_basis for _, charge in attempts):
                raise ValueError("cost_basis must match configured limits")
            current = self._projection_for(db, run_id, limits.cost_basis)
            if (
                used + total.steps > max_steps
                or used + total.steps > limits.steps
                or not (current + total).fits_within(limits)
            ):
                raise ValueError("budget exhausted")
            for attempt_id, _ in attempts:
                if db.execute(
                    "SELECT 1 FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone() is not None:
                    raise ValueError("batch attempt conflicts with existing hold")
            db.execute(
                "INSERT INTO charge_batches (run_id, batch_id, payload_digest) VALUES (?, ?, ?)",
                (run_id, batch_id, batch_digest),
            )
            db.execute(
                "INSERT INTO batch_reservations (run_id, batch_id, payload_digest) "
                "VALUES (?, ?, ?)",
                (run_id, batch_id, batch_digest),
            )
            holds: list[AttemptHold] = []
            for attempt_id, charge in attempts:
                hold_id = self._hold_id(run_id, attempt_id)
                payload_json, payload_digest = self._canonical_payload(
                    {
                        "attempt_id": attempt_id,
                        "hold_id": hold_id,
                        "charge": charge.to_dict(),
                        "marker_required": True,
                    }
                )
                db.execute(
                    "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) "
                    "VALUES (?, ?, ?, ?, ?, 'held')",
                    (run_id, attempt_id, hold_id, epoch, charge.steps),
                )
                db.execute(
                    "INSERT INTO batch_attempts (run_id, batch_id, attempt_id) VALUES (?, ?, ?)",
                    (run_id, batch_id, attempt_id),
                )
                db.execute(
                    "INSERT INTO charge_reservations (run_id, attempt_id, hold_id, epoch, "
                    "cost_basis, steps, elapsed_ms, cost_microunits, effect_attempts, payload_digest) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        attempt_id,
                        hold_id,
                        epoch,
                        charge.cost_basis,
                        charge.steps,
                        charge.elapsed_ms,
                        charge.cost_microunits,
                        charge.effect_attempts,
                        payload_digest,
                    ),
                )
                self._append_event(
                    db,
                    run_id=run_id,
                    operation_id=self._reservation_operation_id(run_id, attempt_id),
                    event_type="reservation_tracked",
                    epoch=epoch,
                    payload_json=payload_json,
                    payload_digest=payload_digest,
                )
                holds.append(AttemptHold(run_id, attempt_id, hold_id, epoch, charge.steps))
            self._increase_projection(db, run_id, total)
            db.execute("UPDATE leases SET used = used + ? WHERE run_id = ?", (total.steps, run_id))
            return tuple(holds)

    def mark_started(self, run_id: str, attempt_id: str, epoch: int) -> bool:
        """Persist the immutable start marker for a currently fenced tracked hold."""
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            hold = self._hold_for(db, run_id, attempt_id)
            existing = db.execute(
                "SELECT epoch FROM accounting_starts WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if int(existing[0]) != epoch:
                    raise ValueError("start conflicts with existing marker")
                return False
            if hold.fence_epoch != epoch or self._hold_state(db, run_id, attempt_id) != "held":
                raise ValueError("start does not match a current held attempt")
            stop = db.execute(
                "SELECT reason FROM stop_requests WHERE run_id = ?", (run_id,)
            ).fetchone()
            if stop is not None:
                raise DurableStopRequested(str(stop[0]))
            if not self._has_reservation_evidence(db, run_id, attempt_id):
                raise ValueError("start requires schema-v2 reservation evidence")
            payload_json, payload_digest = self._canonical_payload({"attempt_id": attempt_id})
            db.execute(
                "INSERT INTO accounting_starts (run_id, attempt_id, epoch) VALUES (?, ?, ?)",
                (run_id, attempt_id, epoch),
            )
            self._append_event(
                db,
                run_id=run_id,
                operation_id=self._operation_id("start", run_id, attempt_id),
                event_type="attempt_started",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return True

    def record_outcome(
        self, run_id: str, attempt_id: str, epoch: int, result_digest: str
    ) -> bool:
        """Persist one immutable result digest after a recorded start."""
        if not isinstance(result_digest, str) or not result_digest:
            raise ValueError("result digest must be a non-empty string")
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            hold = self._hold_for(db, run_id, attempt_id)
            if hold.fence_epoch != epoch:
                raise LeaseFenced(run_id)
            if db.execute(
                "SELECT 1 FROM accounting_starts WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone() is None:
                raise ValueError("outcome requires a durable start marker")
            existing = db.execute(
                "SELECT epoch, result_digest FROM accounting_outcomes "
                "WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != (epoch, result_digest):
                    raise ValueError("outcome conflicts with existing record")
                return False
            if self._hold_state(db, run_id, attempt_id) != "held":
                raise ValueError("outcome requires a current held attempt")
            payload_json, payload_digest = self._canonical_payload(
                {"attempt_id": attempt_id, "result_digest": result_digest}
            )
            db.execute(
                "INSERT INTO accounting_outcomes (run_id, attempt_id, epoch, result_digest) "
                "VALUES (?, ?, ?, ?)",
                (run_id, attempt_id, epoch, result_digest),
            )
            self._append_event(
                db,
                run_id=run_id,
                operation_id=self._operation_id("outcome", run_id, attempt_id),
                event_type="outcome_recorded",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return True

    def settle_usage(
        self,
        run_id: str,
        attempt_id: str,
        epoch: int,
        receipt_id: str,
        usage: ChargeUnits | None,
    ) -> bool:
        """Settle measured usage, or conservatively retain the full hold when unknown."""
        if not isinstance(receipt_id, str) or not receipt_id:
            raise ValueError("receipt_id must be a non-empty string")
        if usage is not None:
            self._validate_charge(usage)
        payload_json, payload_digest = self._canonical_payload(
            {"attempt_id": attempt_id, "receipt_id": receipt_id, "usage": None if usage is None else usage.to_dict()}
        )
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            hold = self._hold_for(db, run_id, attempt_id)
            if hold.fence_epoch != epoch:
                raise LeaseFenced(run_id)
            existing = db.execute(
                "SELECT receipt_id, payload_digest FROM usage_receipts "
                "WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != receipt_id:
                    raise ValueError("attempt already has a different usage receipt")
                if str(existing[1]) != payload_digest:
                    raise ValueError("usage receipt payload conflicts with existing receipt")
                return False
            duplicate_receipt = db.execute(
                "SELECT attempt_id FROM usage_receipts WHERE run_id = ? AND receipt_id = ?",
                (run_id, receipt_id),
            ).fetchone()
            if duplicate_receipt is not None:
                raise ValueError("receipt_id is already bound to another attempt")
            reserved = self._charge_for(db, "charge_reservations", run_id, attempt_id)
            if reserved is None:
                raise ValueError("usage settlement requires a multi-unit charge hold")
            if db.execute(
                "SELECT 1 FROM accounting_starts WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone() is None:
                raise ValueError("usage settlement requires start evidence")
            state = self._hold_state(db, run_id, attempt_id)
            if state == "unknown":
                raise ValueError("unknown usage cannot release its hold")
            if state not in {"held", "settled"}:
                raise ValueError("usage settlement requires an active hold")
            if usage is not None:
                if db.execute(
                    "SELECT 1 FROM accounting_outcomes WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone() is None:
                    raise ValueError("verified usage requires outcome evidence")
                if usage.cost_basis != reserved.cost_basis:
                    raise ValueError("cost_basis must match the reserved hold")
                if not usage.fits_within(reserved):
                    raise ValueError("verified usage exceeds its hold")
                refund = reserved - usage
                db.execute(
                    "UPDATE leases SET used = used - ? WHERE run_id = ?",
                    (refund.steps, run_id),
                )
                self._decrease_projection(db, run_id, refund)
                db.execute(
                    "UPDATE attempt_holds SET state = 'settled' "
                    "WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                )
            else:
                self._insert_unknown(
                    db,
                    run_id,
                    hold,
                    cause=(
                        "crash_before_settle"
                        if db.execute(
                            "SELECT 1 FROM commit_intents WHERE run_id = ? AND attempt_id = ?",
                            (run_id, attempt_id),
                        ).fetchone()
                        else "crash_before_intent"
                    ),
                )
            values = (None, None, None, None, None) if usage is None else (
                usage.cost_basis,
                usage.steps,
                usage.elapsed_ms,
                usage.cost_microunits,
                usage.effect_attempts,
            )
            db.execute(
                "INSERT INTO usage_receipts (run_id, attempt_id, epoch, receipt_id, "
                "usage_known, cost_basis, steps, elapsed_ms, cost_microunits, "
                "effect_attempts, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    attempt_id,
                    epoch,
                    receipt_id,
                    int(usage is not None),
                    *values,
                    payload_digest,
                ),
            )
            self._append_event(
                db,
                run_id=run_id,
                operation_id=self._operation_id("settle", run_id, receipt_id),
                event_type="usage_settled" if usage is not None else "usage_unknown",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return True

    def recover_accounting(self, run_id: str, epoch: int) -> AccountingRecovery:
        """Classify old unresolved holds after fencing, without replaying execution."""
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            operation_id = self._operation_id("recover", run_id, str(epoch))
            prior = db.execute(
                "SELECT payload_json FROM accounting_events WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if prior is not None:
                payload = json.loads(str(prior[0]))
                return AccountingRecovery(
                    released=tuple(payload["released"]),
                    unknown=tuple(payload["unknown"]),
                    preserved_unknown=tuple(payload["preserved_unknown"]),
                )
            rows = db.execute(
                "SELECT attempt_id, hold_id, epoch, units, state FROM attempt_holds "
                "WHERE run_id = ? AND state IN ('held', 'unknown') ORDER BY attempt_id",
                (run_id,),
            ).fetchall()
            if not rows:
                return AccountingRecovery((), (), ())
            if any(int(row[2]) >= epoch for row in rows):
                raise ValueError("accounting recovery requires lease takeover")
            released: list[str] = []
            unknown: list[str] = []
            preserved: list[str] = []
            evidence: dict[str, dict[str, bool]] = {}
            released_steps = 0
            for attempt_id_raw, hold_id_raw, hold_epoch_raw, units_raw, state_raw in rows:
                attempt_id = str(attempt_id_raw)
                hold = AttemptHold(
                    run_id,
                    attempt_id,
                    str(hold_id_raw),
                    int(hold_epoch_raw),
                    int(units_raw),
                )
                state = str(state_raw)
                started = db.execute(
                    "SELECT 1 FROM accounting_starts WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone() is not None
                outcome = db.execute(
                    "SELECT 1 FROM accounting_outcomes WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone() is not None
                intent = db.execute(
                    "SELECT 1 FROM commit_intents WHERE run_id = ? AND attempt_id = ?",
                    (run_id, attempt_id),
                ).fetchone() is not None
                evidence[attempt_id] = {
                    "start": started,
                    "outcome": outcome,
                    "intent": intent,
                }
                if state == "unknown":
                    preserved.append(attempt_id)
                    continue
                tracked = self._has_reservation_evidence(db, run_id, attempt_id)
                if tracked and not started:
                    db.execute(
                        "UPDATE attempt_holds SET state = 'released' "
                        "WHERE run_id = ? AND attempt_id = ?",
                        (run_id, attempt_id),
                    )
                    reserved = self._charge_for(db, "charge_reservations", run_id, attempt_id)
                    if reserved is not None:
                        self._decrease_projection(db, run_id, reserved)
                    released_steps += hold.units
                    released.append(attempt_id)
                    continue
                self._insert_unknown(
                    db,
                    run_id,
                    hold,
                    cause="crash_before_settle" if intent else "crash_before_intent",
                )
                unknown.append(attempt_id)
            if released_steps:
                db.execute(
                    "UPDATE leases SET used = used - ? WHERE run_id = ?",
                    (released_steps, run_id),
                )
            result = AccountingRecovery(tuple(released), tuple(unknown), tuple(preserved))
            payload_json, payload_digest = self._canonical_payload(
                {
                    "released": list(result.released),
                    "unknown": list(result.unknown),
                    "preserved_unknown": list(result.preserved_unknown),
                    "evidence": evidence,
                }
            )
            self._append_event(
                db,
                run_id=run_id,
                operation_id=operation_id,
                event_type="accounting_recovered",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return result

    def observe_time(self, run_id: str, epoch: int, observed_at: datetime) -> bool:
        """Advance one run's durable UTC high-water mark and refuse clock rollback."""
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("observed time must be timezone-aware")
        observed_utc = observed_at.astimezone(UTC).isoformat(timespec="microseconds")
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            existing = db.execute(
                "SELECT observed_utc FROM accounting_time_highwater WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if existing is not None:
                highwater = datetime.fromisoformat(str(existing[0]))
                normalized = datetime.fromisoformat(observed_utc)
                if normalized < highwater:
                    raise ValueError("clock rollback refused")
                if normalized == highwater:
                    return False
                db.execute(
                    "UPDATE accounting_time_highwater SET observed_utc = ?, epoch = ? "
                    "WHERE run_id = ?",
                    (observed_utc, epoch, run_id),
                )
            else:
                db.execute(
                    "INSERT INTO accounting_time_highwater (run_id, observed_utc, epoch) "
                    "VALUES (?, ?, ?)",
                    (run_id, observed_utc, epoch),
                )
                # Only the first observation anchors the timeline in the event
                # log. Later advances touch the high-water row alone: it is all
                # the rollback check reads, and one event per boundary would
                # grow events(run_id) without bound.
                payload_json, payload_digest = self._canonical_payload(
                    {"observed_utc": observed_utc}
                )
                self._append_event(
                    db,
                    run_id=run_id,
                    operation_id=self._operation_id("time", run_id, observed_utc),
                    event_type="time_observed",
                    epoch=epoch,
                    payload_json=payload_json,
                    payload_digest=payload_digest,
                )
            return True

    def reserve_attempt(
        self,
        run_id: str,
        epoch: int,
        attempt_id: str,
        *,
        units: int,
        requires_start_marker: bool = False,
    ) -> AttemptHold:
        """Reserve one idempotent attempt hold inside the lease transaction."""
        self._validate_attempt_inputs(run_id, epoch, attempt_id, units)
        if type(requires_start_marker) is not bool:
            raise TypeError("requires_start_marker must be a bool")
        hold_id = self._hold_id(run_id, attempt_id)
        payload_json, payload_digest = self._canonical_payload(
            {
                "attempt_id": attempt_id,
                "hold_id": hold_id,
                "steps": units,
                "marker_required": requires_start_marker,
            }
        )
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            if db.execute(
                "SELECT 1 FROM charge_limits WHERE run_id = ?", (run_id,)
            ).fetchone() is not None:
                raise ValueError("configured runs must use reserve_charge")
            existing = db.execute(
                "SELECT hold_id, epoch, units FROM attempt_holds WHERE run_id = ? AND attempt_id = ?",
                (run_id, attempt_id),
            ).fetchone()
            if existing is not None:
                if int(existing[1]) != epoch or int(existing[2]) != units:
                    raise ValueError("attempt reservation conflicts with its existing hold")
                tracked = db.execute(
                    "SELECT 1 FROM accounting_events WHERE operation_id = ?",
                    (self._reservation_operation_id(run_id, attempt_id),),
                ).fetchone()
                if tracked is None:
                    if requires_start_marker:
                        raise ValueError("pre-v2 attempt cannot acquire marker evidence by retry")
                else:
                    self._append_event(
                        db,
                        run_id=run_id,
                        operation_id=self._reservation_operation_id(run_id, attempt_id),
                        event_type="reservation_tracked",
                        epoch=epoch,
                        payload_json=payload_json,
                        payload_digest=payload_digest,
                    )
                return AttemptHold(run_id, attempt_id, str(existing[0]), epoch, units)
            row = self._lease_row(db, run_id, epoch)
            if int(row[2]) + units > int(row[1]):
                raise ValueError("budget exhausted")
            db.execute(
                "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) "
                "VALUES (?, ?, ?, ?, ?, 'held')",
                (run_id, attempt_id, hold_id, epoch, units),
            )
            db.execute("UPDATE leases SET used = used + ? WHERE run_id = ?", (units, run_id))
            self._append_event(
                db,
                run_id=run_id,
                operation_id=self._reservation_operation_id(run_id, attempt_id),
                event_type="reservation_tracked",
                epoch=epoch,
                payload_json=payload_json,
                payload_digest=payload_digest,
            )
            return AttemptHold(run_id, attempt_id, hold_id, epoch, units)

    def reserve_batch(
        self,
        run_id: str,
        epoch: int,
        batch_id: str,
        attempts: tuple[tuple[str, int], ...],
        *,
        requires_start_marker: bool = False,
    ) -> tuple[AttemptHold, ...]:
        """Reserve all fan-out attempts or none, with payload-stable replay."""
        if not isinstance(batch_id, str) or not batch_id:
            raise ValueError("batch_id must be a non-empty string")
        if not attempts:
            raise ValueError("a batch needs at least one attempt")
        if len({attempt_id for attempt_id, _ in attempts}) != len(attempts):
            raise ValueError("batch attempt ids must be unique")
        if type(requires_start_marker) is not bool:
            raise TypeError("requires_start_marker must be a bool")
        for attempt_id, units in attempts:
            self._validate_attempt_inputs(run_id, epoch, attempt_id, units)
        payload = hashlib.sha256(
            json.dumps(sorted(attempts), separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self._tx() as db:
            self._lease_row(db, run_id, epoch)
            if db.execute(
                "SELECT 1 FROM charge_limits WHERE run_id = ?", (run_id,)
            ).fetchone() is not None:
                raise ValueError("configured runs must use reserve_charge_batch")
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
                for attempt_id, units in attempts:
                    hold = self._hold_for(db, run_id, attempt_id)
                    event_json, event_digest = self._canonical_payload(
                        {
                            "attempt_id": attempt_id,
                            "hold_id": hold.hold_id,
                            "steps": units,
                            "marker_required": requires_start_marker,
                        }
                    )
                    tracked = db.execute(
                        "SELECT 1 FROM accounting_events WHERE operation_id = ?",
                        (self._reservation_operation_id(run_id, attempt_id),),
                    ).fetchone()
                    if tracked is None:
                        if requires_start_marker:
                            raise ValueError("pre-v2 batch cannot acquire marker evidence by retry")
                    else:
                        self._append_event(
                            db,
                            run_id=run_id,
                            operation_id=self._reservation_operation_id(run_id, attempt_id),
                            event_type="reservation_tracked",
                            epoch=epoch,
                            payload_json=event_json,
                            payload_digest=event_digest,
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
                event_json, event_digest = self._canonical_payload(
                    {
                        "attempt_id": attempt_id,
                        "hold_id": hold_id,
                        "steps": units,
                        "marker_required": requires_start_marker,
                    }
                )
                self._append_event(
                    db,
                    run_id=run_id,
                    operation_id=self._reservation_operation_id(run_id, attempt_id),
                    event_type="reservation_tracked",
                    epoch=epoch,
                    payload_json=event_json,
                    payload_digest=event_digest,
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
            self._lease_row(db, run_id, epoch)
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
            stop = db.execute(
                "SELECT reason FROM stop_requests WHERE run_id = ?", (run_id,)
            ).fetchone()
            if stop is not None:
                raise DurableStopRequested(str(stop[0]))
            db.execute(
                "INSERT INTO commit_intents (run_id, attempt_id, hold_id, epoch, result_digest) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, attempt_id, hold_id, epoch, result_digest),
            )
            return True

    def settle_commit(self, run_id: str, attempt_id: str, result_digest: str) -> bool:
        """Settle a prepared commit once; an identical retry is a no-op."""
        with self._tx() as db:
            hold = self._hold_for(db, run_id, attempt_id)
            self._lease_row(db, run_id, hold.fence_epoch)
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
            self._lease_row(db, run_id, epoch)
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
                stop = db.execute(
                    "SELECT reason FROM stop_requests WHERE run_id = ?", (run_id,)
                ).fetchone()
                if stop is not None:
                    raise DurableStopRequested(str(stop[0]))
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
            first_hold = self._hold_for(db, run_id, attempts[0])
            self._lease_row(db, run_id, first_hold.fence_epoch)
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
            self._lease_row(db, run_id, disposition.fence_epoch)
            hold = self._hold_for(db, run_id, disposition.attempt_id)
            if hold.hold_id != disposition.hold_id or hold.fence_epoch != disposition.fence_epoch:
                raise ValueError("unknown disposition does not match its hold")
            receipt = db.execute(
                "SELECT usage_known FROM usage_receipts WHERE run_id = ? AND attempt_id = ?",
                (run_id, disposition.attempt_id),
            ).fetchone()
            if receipt is not None and int(receipt[0]) == 1:
                raise ValueError("known usage receipt is canonical and cannot become unknown")
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
            self._lease_row(db, run_id, epoch)
            hold = self._hold_for(db, run_id, attempt_id)
            if hold.fence_epoch != epoch:
                raise LeaseFenced(run_id)
            if self._hold_state(db, run_id, attempt_id) == "unknown":
                raise ValueError("unknown holds require an authenticated adjustment grant")
            raise ValueError("direct release is not an approved accounting transition")

    @classmethod
    def _validate_charge(cls, charge: ChargeUnits, *, allow_zero_steps: bool = False) -> None:
        if not isinstance(charge, ChargeUnits):
            raise TypeError("charge must be ChargeUnits")
        if not allow_zero_steps and charge.steps < 1:
            raise ValueError("charge steps must be positive")
        for name in ChargeUnits._QUANTITY_FIELDS:
            if getattr(charge, name) > cls.SQLITE_MAX_INT:
                raise ValueError(f"{name} exceeds SQLite integer range")

    @staticmethod
    def _canonical_payload(payload: object) -> tuple[str, str]:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return payload_json, hashlib.sha256(payload_json.encode("ascii")).hexdigest()

    @staticmethod
    def _operation_id(kind: str, run_id: str, key: str = "") -> str:
        digest = hashlib.sha256(f"{kind}\0{run_id}\0{key}".encode("utf-8")).hexdigest()
        return f"accounting:{kind}:{digest}"

    @classmethod
    def _reservation_operation_id(cls, run_id: str, attempt_id: str) -> str:
        return cls._operation_id("reservation", run_id, attempt_id)

    @classmethod
    def _append_event(
        cls,
        db: sqlite3.Connection,
        *,
        run_id: str,
        operation_id: str,
        event_type: str,
        epoch: int,
        payload_json: str,
        payload_digest: str,
    ) -> bool:
        existing = db.execute(
            "SELECT schema_version, run_id, event_type, epoch, payload_digest, payload_json "
            "FROM accounting_events WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        expected = (
            cls.SCHEMA_VERSION,
            run_id,
            event_type,
            epoch,
            payload_digest,
            payload_json,
        )
        if existing is not None:
            if tuple(existing) != expected:
                raise ValueError("operation_id payload conflicts with existing event")
            return False
        db.execute(
            "INSERT INTO accounting_events (schema_version, run_id, operation_id, "
            "event_type, epoch, payload_digest, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                cls.SCHEMA_VERSION,
                run_id,
                operation_id,
                event_type,
                epoch,
                payload_digest,
                payload_json,
            ),
        )
        return True

    @staticmethod
    def _charge_for(
        db: sqlite3.Connection,
        table: str,
        run_id: str,
        attempt_id: str | None = None,
    ) -> ChargeUnits | None:
        if table not in {"charge_limits", "charge_reservations"}:
            raise ValueError("unsupported charge table")
        where = "run_id = ?" if attempt_id is None else "run_id = ? AND attempt_id = ?"
        params = (run_id,) if attempt_id is None else (run_id, attempt_id)
        row = db.execute(
            f"SELECT steps, elapsed_ms, cost_microunits, effect_attempts, cost_basis "
            f"FROM {table} WHERE {where}",
            params,
        ).fetchone()
        if row is None:
            return None
        return ChargeUnits(
            int(row[0]),
            int(row[1]),
            int(row[2]),
            int(row[3]),
            cost_basis=str(row[4]),
        )

    @staticmethod
    def _projection_for(
        db: sqlite3.Connection, run_id: str, cost_basis: str
    ) -> ChargeUnits:
        row = db.execute(
            "SELECT elapsed_ms, cost_microunits, effect_attempts, cost_basis "
            "FROM charge_projection WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None or str(row[3]) != cost_basis:
            raise ValueError("charge projection is missing or has incompatible cost_basis")
        return ChargeUnits(0, int(row[0]), int(row[1]), int(row[2]), cost_basis=cost_basis)

    @classmethod
    def _increase_projection(
        cls, db: sqlite3.Connection, run_id: str, charge: ChargeUnits
    ) -> None:
        current = cls._projection_for(db, run_id, charge.cost_basis)
        updated = current + ChargeUnits(
            0,
            charge.elapsed_ms,
            charge.cost_microunits,
            charge.effect_attempts,
            cost_basis=charge.cost_basis,
        )
        cls._validate_charge(updated, allow_zero_steps=True)
        db.execute(
            "UPDATE charge_projection SET elapsed_ms = ?, cost_microunits = ?, "
            "effect_attempts = ? WHERE run_id = ?",
            (updated.elapsed_ms, updated.cost_microunits, updated.effect_attempts, run_id),
        )

    @classmethod
    def _decrease_projection(
        cls, db: sqlite3.Connection, run_id: str, charge: ChargeUnits
    ) -> None:
        current = cls._projection_for(db, run_id, charge.cost_basis)
        reduction = ChargeUnits(
            0,
            charge.elapsed_ms,
            charge.cost_microunits,
            charge.effect_attempts,
            cost_basis=charge.cost_basis,
        )
        updated = current - reduction
        db.execute(
            "UPDATE charge_projection SET elapsed_ms = ?, cost_microunits = ?, "
            "effect_attempts = ? WHERE run_id = ?",
            (updated.elapsed_ms, updated.cost_microunits, updated.effect_attempts, run_id),
        )

    @classmethod
    def _has_reservation_evidence(
        cls, db: sqlite3.Connection, run_id: str, attempt_id: str
    ) -> bool:
        row = db.execute(
            "SELECT payload_json FROM accounting_events WHERE operation_id = ? AND run_id = ? "
            "AND event_type = 'reservation_tracked'",
            (cls._reservation_operation_id(run_id, attempt_id), run_id),
        ).fetchone()
        if row is None:
            return False
        payload = json.loads(str(row[0]))
        return payload.get("marker_required") is True

    @staticmethod
    def _insert_unknown(
        db: sqlite3.Connection,
        run_id: str,
        hold: AttemptHold,
        *,
        cause: UnknownCause,
    ) -> None:
        expected = (hold.hold_id, hold.fence_epoch, cause, "none", "unsettled", 1)
        existing = db.execute(
            "SELECT hold_id, epoch, cause, stop_state, settlement_state, schema_version "
            "FROM unknown_dispositions WHERE run_id = ? AND attempt_id = ?",
            (run_id, hold.attempt_id),
        ).fetchone()
        if existing is not None and tuple(existing) != expected:
            raise ValueError("unknown disposition conflicts with existing record")
        if existing is None:
            db.execute(
                "INSERT INTO unknown_dispositions (run_id, attempt_id, hold_id, epoch, "
                "cause, stop_state, settlement_state, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, hold.attempt_id, *expected),
            )
        db.execute(
            "UPDATE attempt_holds SET state = 'unknown' WHERE run_id = ? AND attempt_id = ?",
            (run_id, hold.attempt_id),
        )

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
        if epoch > StepLedger.SQLITE_MAX_INT:
            raise ValueError("epoch exceeds SQLite integer range")
        if (
            isinstance(units, bool)
            or not isinstance(units, int)
            or units < 1
            or units > StepLedger.SQLITE_MAX_INT
        ):
            raise ValueError("units must be a positive integer")

    @staticmethod
    def _assert_run_not_terminal(db: sqlite3.Connection, run_id: str) -> None:
        """Fence ledger operations after lifecycle evidence closes the run."""
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'terminal_receipts'"
        ).fetchone()
        if table is not None and db.execute(
            "SELECT 1 FROM terminal_receipts WHERE run_id = ?", (run_id,)
        ).fetchone() is not None:
            raise LeaseFenced(run_id)

    @staticmethod
    def _lease_row(db: sqlite3.Connection, run_id: str, epoch: int) -> tuple[int, int, int]:
        """Return the current lease row or fence a stale/unknown holder."""
        StepLedger._assert_run_not_terminal(db, run_id)
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
    _charge_allowance: ChargeUnits | None = field(default=None, init=False, repr=False)
    _started_attempts: set[str] = field(default_factory=set, init=False, repr=False)
    _open_callables: list[str] = field(default_factory=list, init=False, repr=False)

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

    def configure_accounting(self, *, limits: ChargeUnits, allowance: ChargeUnits) -> None:
        """Opt into explicit multi-unit bounds without widening owner admission."""
        if not core_start_seam_available():
            raise AdmissionRefused("gate.core_start_seam_unavailable")
        if limits.steps > self.decision.max_steps or allowance.steps < 1:
            raise AdmissionRefused("gate.accounting_bound_invalid")
        if not allowance.fits_within(limits):
            raise AdmissionRefused("gate.accounting_allowance_exceeds_limit")
        self.ledger.configure_limits(self.run_id, self.lease_epoch, limits)
        self._charge_allowance = allowance

    def _reserve_callable(self, attempt_id: str, units: int = 1) -> AttemptHold:
        """Reserve one explicit allowance, or the compatible step-only hold."""
        if self._charge_allowance is not None:
            return self.ledger.reserve_charge(
                self.run_id, self.lease_epoch, attempt_id, self._charge_allowance,
            )
        return self.ledger.reserve_attempt(
            self.run_id, self.lease_epoch, attempt_id, units=units,
            requires_start_marker=self._has_start_protocol(),
        )

    @staticmethod
    def _has_start_protocol() -> bool:
        """Identify the candidate start seam, never infer it from new storage."""
        return core_start_seam_available()

    async def before_start(self, request: DispatchRequest) -> None:
        """Persist a fenced marker immediately before every actual callable."""
        from perpetua_core.graph.gate import GateRefused

        early = self._common()
        if early is not None:
            raise GateRefused(early, request)
        if request.boundary == "node" and request.batch_id is not None:
            attempt_id = f"{request.batch_id}:{request.nodes[0]}"
        else:
            attempt_id = self._attempt_id(
                request.boundary, request.nodes, request.steps, request.source,
            )
        try:
            if request.boundary != "node":
                self._reserve_callable(attempt_id)
            if not self.ledger.mark_started(self.run_id, attempt_id, self.lease_epoch):
                raise ValueError("an existing start marker never authorizes callable replay")
            self._started_attempts.add(attempt_id)
            if request.boundary != "node":
                self._open_callables.append(attempt_id)
        except LeaseFenced as error:
            raise GateRefused(GateDecision.refuse("authority.lease_fenced"), request) from error
        except ValueError as error:
            reason = "budget.steps_exhausted" if str(error) == "budget exhausted" else "ledger.start_invalid"
            raise GateRefused(GateDecision.refuse(reason), request) from error

    def _finish_open_callables(self) -> str | None:
        """Settle router/join/reducer holds whose callable has returned.

        Core is sequential between boundaries, so reaching the next boundary
        proves the previous callable returned. A callable that raised never
        reaches one, so its hold stays held and surfaces as unknown, never as
        completed work. Returns a refusal reason, or None when all settled.
        """
        while self._open_callables:
            attempt_id = self._open_callables[0]
            digest = hashlib.sha256(f"callable-returned\0{attempt_id}".encode()).hexdigest()
            try:
                hold = self.ledger.hold(self.run_id, attempt_id)
                self.ledger.record_outcome(self.run_id, attempt_id, self.lease_epoch, digest)
                self.ledger.prepare_commit(
                    self.run_id, attempt_id, hold.hold_id, self.lease_epoch, digest,
                )
                self.ledger.settle_commit(self.run_id, attempt_id, digest)
            except LeaseFenced:
                return "authority.lease_fenced"
            except ValueError:
                return "ledger.commit_unprepared"
            self._open_callables.pop(0)
        return None

    def finish_run(self) -> None:
        """Best-effort settlement of trailing callables after a successful run.

        A failure leaves the hold held; the terminal receipt then reports the
        run as unknown rather than overstating completion.
        """
        if self._common() is None:
            self._finish_open_callables()

    async def before_dispatch(self, request: DispatchRequest) -> GateDecision:
        """Check authority, stop, delivery and reserve budget before the call."""
        early = self._common()
        if early is not None:
            return early
        pending = self._finish_open_callables()
        if pending is not None:
            return GateDecision.refuse(pending)
        if request.boundary == "node":
            try:
                self._reserve_callable(
                    self._attempt_id(request.boundary, request.nodes, request.steps, request.source),
                    len(request.nodes),
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
                if self._charge_allowance is None:
                    self.ledger.reserve_batch(
                        self.run_id, self.lease_epoch, request.batch_id,
                        tuple((f"{request.batch_id}:{name}", 1) for name in request.nodes),
                        requires_start_marker=self._has_start_protocol(),
                    )
                else:
                    self.ledger.reserve_charge_batch(
                        self.run_id, self.lease_epoch, request.batch_id,
                        tuple((f"{request.batch_id}:{name}", self._charge_allowance)
                              for name in request.nodes),
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
        pending = self._finish_open_callables()
        if pending is not None:
            return GateDecision.refuse(pending)
        if request.boundary not in {"node", "region"}:
            return GateDecision.allow()
        if not isinstance(request.result_digest, str) or not request.result_digest:
            return GateDecision.refuse("ledger.commit_digest_missing")
        if request.boundary == "region":
            if not isinstance(request.batch_id, str) or not request.batch_id:
                return GateDecision.refuse("ledger.batch_id_missing")
            try:
                for name in request.nodes:
                    attempt_id = f"{request.batch_id}:{name}"
                    if attempt_id in self._started_attempts:
                        self.ledger.record_outcome(
                            self.run_id, attempt_id, self.lease_epoch, request.result_digest,
                        )
                self.ledger.prepare_batch_commit(
                    self.run_id,
                    request.batch_id,
                    tuple(f"{request.batch_id}:{name}" for name in request.nodes),
                    self.lease_epoch,
                    request.result_digest,
                )
            except DurableStopRequested as error:
                return GateDecision.stop(error.reason)
            except LeaseFenced:
                return GateDecision.refuse("authority.lease_fenced")
            except ValueError:
                return GateDecision.refuse("ledger.commit_unprepared")
            return GateDecision.allow()
        attempt_id = self._attempt_id(request.boundary, request.nodes, request.steps, request.source)
        try:
            hold = self.ledger.hold(self.run_id, attempt_id)
            if attempt_id in self._started_attempts:
                self.ledger.record_outcome(
                    self.run_id, attempt_id, self.lease_epoch, request.result_digest,
                )
            self.ledger.prepare_commit(
                self.run_id,
                attempt_id,
                hold.hold_id,
                self.lease_epoch,
                request.result_digest,
            )
        except DurableStopRequested as error:
            return GateDecision.stop(error.reason)
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
        try:
            self.ledger.observe_time(self.run_id, self.lease_epoch, now)
        except LeaseFenced:
            return "authority.lease_fenced"
        except ValueError:
            return "authority.clock_regressed"
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
        if any("::" in part for part in parts):
            payload = json.dumps(
                [boundary, nodes, steps, source], separators=(",", ":"), ensure_ascii=True,
            )
            return "v2::" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return "::".join(parts)
