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

import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

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


class StepLedger:
    """Single-writer SQLite step ledger with lease fencing (T1 foundation; T2-B extends).

    Every write runs in one ``BEGIN IMMEDIATE`` transaction, so reservations are atomic
    across processes. WAL with ``synchronous=FULL``. Integer units only.
    """

    def __init__(self, path: Path | str) -> None:
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

    def close(self) -> None:
        self._db.close()

    def pragmas(self) -> tuple[str, int]:
        mode = self._db.execute("PRAGMA journal_mode").fetchone()[0]
        sync = self._db.execute("PRAGMA synchronous").fetchone()[0]
        return str(mode).lower(), int(sync)

    def _tx(self):
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

    def used(self, run_id: str) -> int:
        row = self._db.execute("SELECT used FROM leases WHERE run_id = ?", (run_id,)).fetchone()
        return 0 if row is None else int(row[0])


class _Immediate:
    def __init__(self, db: sqlite3.Connection, lock: threading.Lock) -> None:
        self._db, self._lock = db, lock

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._lock.release()
            raise
        return self._db

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self._db.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self._lock.release()


@dataclass
class StopSignal:
    """Cooperative stop request; the gate turns it into a Core ``stop`` decision."""

    reason: str | None = None

    def request(self, reason: str) -> None:
        if not reason:
            raise ValueError("a stop needs a reason code")
        if self.reason is None:
            self.reason = reason


class DeliveryHealth(Protocol):
    def healthy(self) -> bool: ...


class NoDeliverySinks:
    """T1 has no observation delivery, so nothing can be behind. T2-A replaces this."""

    def healthy(self) -> bool:
        return True


@dataclass
class AdmissionGate:
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
        if not CORE_GATE_AVAILABLE:
            raise AdmissionRefused("gate.core_seam_unavailable")
        if self.decision.outcome != "allow":
            raise AdmissionRefused("gate.decision_not_allowed")

    # Core DispatchGate protocol -------------------------------------------------

    async def before_dispatch(self, request: DispatchRequest) -> GateDecision:
        early = self._common()
        if early is not None:
            return early
        if request.boundary in ("node", "fanout"):
            try:
                fits = self.ledger.reserve(self.run_id, self.lease_epoch, len(request.nodes))
            except LeaseFenced:
                return GateDecision.refuse("authority.lease_fenced")
            if not fits:
                return GateDecision.refuse("budget.steps_exhausted")
        return GateDecision.allow()

    async def before_commit(self, request: CommitRequest) -> GateDecision:
        early = self._common()
        return early if early is not None else GateDecision.allow()

    # Fixed order: authority and lease, stop, delivery ---------------------------

    def _common(self) -> GateDecision | None:
        reason = self._authority()
        if reason is not None:
            return GateDecision.refuse(reason)
        if self.stop.reason is not None:
            return GateDecision.stop(self.stop.reason)
        if not self.delivery.healthy():
            return GateDecision.refuse("delivery.unhealthy")
        return None

    def _authority(self) -> str | None:
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
