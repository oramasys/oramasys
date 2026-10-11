"""Durable stop control and terminal evidence for authenticated graph runs."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from orama.graph.private_store import prepare_private_store


@dataclass(frozen=True, slots=True)
class StopRequest:
    """An authenticated principal's request to cooperatively stop one run."""

    run_id: str
    principal: str
    reason: str = "operator_request"

    def __post_init__(self) -> None:
        """Reject empty identifiers before they enter the durable store."""
        for field in ("run_id", "principal", "reason"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be a non-empty string")


TerminalOutcome = Literal[
    "completed",
    "interrupted",
    "cancelled",
    "refused",
    "budget",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class TerminalReceipt:
    """Canonical terminal evidence binding outcome and run context."""

    run_id: str
    epoch: int
    outcome: TerminalOutcome
    reason: str
    unresolved_attempts: tuple[str, ...] = ()
    charge_summary: tuple[tuple[str, int], ...] = ()
    evidence_digest: str | None = None
    cost_basis: str = "legacy_step_only"
    schema_version: int = 2

    def __post_init__(self) -> None:
        """Validate taxonomy and invariants."""
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("epoch must be a positive integer")
        if not isinstance(self.outcome, str) or self.outcome not in {
            "completed",
            "interrupted",
            "cancelled",
            "refused",
            "budget",
            "unknown",
        }:
            raise ValueError(f"invalid outcome: {self.outcome}")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string")
        if type(self.unresolved_attempts) is not tuple:
            raise ValueError("unresolved_attempts must be a tuple")
        if any(
            not isinstance(attempt_id, str) or not attempt_id.strip()
            for attempt_id in self.unresolved_attempts
        ):
            raise ValueError("unresolved_attempts must contain non-empty strings")
        if len(set(self.unresolved_attempts)) != len(self.unresolved_attempts):
            raise ValueError("unresolved_attempts must be unique")
        if self.unresolved_attempts and self.outcome != "unknown":
            raise ValueError("unresolved_attempts require an unknown outcome")
        if type(self.charge_summary) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0]
            or type(item[1]) is not int
            or item[1] < 0
            for item in self.charge_summary
        ):
            raise ValueError("charge_summary must contain named non-negative integer units")
        if len({name for name, _ in self.charge_summary}) != len(self.charge_summary):
            raise ValueError("charge_summary dimensions must be unique")
        if self.evidence_digest is not None and (
            not isinstance(self.evidence_digest, str)
            or len(self.evidence_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.evidence_digest)
        ):
            raise ValueError("evidence_digest must be a lowercase SHA-256 digest")
        if not isinstance(self.cost_basis, str) or not self.cost_basis.strip():
            raise ValueError("cost_basis must be a non-empty string")
        if type(self.schema_version) is not int or self.schema_version not in {1, 2}:
            raise ValueError("schema_version must be integer 1 or 2")
        if self.schema_version == 1 and (
            self.charge_summary
            or self.evidence_digest is not None
            or self.cost_basis != "legacy_step_only"
        ):
            raise ValueError("schema_version 1 cannot carry schema-v2 evidence")


class StopNotAuthorized(PermissionError):
    """Raised when a principal is not the trusted owner of a run."""


class RunControl:
    """One durable stop source per store, with owner-only stop authority.

    Runtime composition requires the ledger and control components to resolve
    to the same SQLite database file.
    """

    def __init__(
        self,
        *,
        store_path: Path | str,
        notifier: Callable[[StopRequest], None] | None = None,
    ) -> None:
        """Open a durable stop store and optionally configure a local notifier."""
        self._lock = threading.Lock()
        self._notifier = notifier
        resolved_store = prepare_private_store(store_path)
        self._db = sqlite3.connect(
            str(resolved_store.resolve()), isolation_level=None, check_same_thread=False
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS run_owners ("
            " run_id TEXT PRIMARY KEY, owner_principal TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS stop_requests ("
            " run_id TEXT PRIMARY KEY, principal TEXT NOT NULL, reason TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS terminal_receipts ("
            " run_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, outcome TEXT NOT NULL, "
            " reason TEXT NOT NULL, unresolved_attempts TEXT NOT NULL, schema_version INTEGER NOT NULL, "
            " charge_summary TEXT NOT NULL DEFAULT '[]', evidence_digest TEXT, "
            " cost_basis TEXT NOT NULL DEFAULT 'legacy_step_only')"
        )
        columns = {str(row[1]) for row in self._db.execute("PRAGMA table_info(terminal_receipts)")}
        if "charge_summary" not in columns:
            self._db.execute(
                "ALTER TABLE terminal_receipts ADD COLUMN charge_summary TEXT NOT NULL DEFAULT '[]'"
            )
        if "evidence_digest" not in columns:
            self._db.execute("ALTER TABLE terminal_receipts ADD COLUMN evidence_digest TEXT")
        if "cost_basis" not in columns:
            self._db.execute(
                "ALTER TABLE terminal_receipts ADD COLUMN cost_basis TEXT NOT NULL DEFAULT 'legacy_step_only'"
            )

    @property
    def database_path(self) -> str:
        """Return SQLite's resolved filename for cross-component store checks."""
        row = self._db.execute("PRAGMA database_list").fetchone()
        return "" if row is None else str(row[2])

    def close(self) -> None:
        """Release the local SQLite connection."""
        self._db.close()

    def register_run(self, *, run_id: str, owner_principal: str) -> None:
        """Persist the trusted owner for a run before it can be stopped."""
        request = StopRequest(run_id=run_id, principal=owner_principal)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT owner_principal FROM run_owners WHERE run_id = ?", (request.run_id,)
                ).fetchone()
                if existing is None:
                    self._db.execute(
                        "INSERT INTO run_owners (run_id, owner_principal) VALUES (?, ?)",
                        (request.run_id, request.principal),
                    )
                elif existing[0] != request.principal:
                    raise ValueError("run owner is immutable")
                self._db.execute("COMMIT")
            finally:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")

    def request_stop(self, request: StopRequest) -> StopRequest:
        """Durably record an authorized stop before any local notification."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                owner = self._db.execute(
                    "SELECT owner_principal FROM run_owners WHERE run_id = ?", (request.run_id,)
                ).fetchone()
                if owner is None or owner[0] != request.principal:
                    raise StopNotAuthorized(request.run_id)
                if self._db.execute(
                    "SELECT 1 FROM terminal_receipts WHERE run_id = ?", (request.run_id,)
                ).fetchone() is not None:
                    raise ValueError("run is already terminal")
                existing = self._db.execute(
                    "SELECT principal, reason FROM stop_requests WHERE run_id = ?", (request.run_id,)
                ).fetchone()
                if existing is None:
                    self._db.execute(
                        "INSERT INTO stop_requests (run_id, principal, reason) VALUES (?, ?, ?)",
                        (request.run_id, request.principal, request.reason),
                    )
                    stored = request
                else:
                    stored = StopRequest(run_id=request.run_id, principal=str(existing[0]), reason=str(existing[1]))
                self._db.execute("COMMIT")
            finally:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
        if self._notifier is not None:
            self._notifier(stored)
        return stored

    def durable_signal(self, *, run_id: str, principal: str):
        """Return a gate-compatible signal backed by this run's stop row."""
        return _DurableStopSignal(self, run_id, principal)

    def stop_for(self, run_id: str) -> StopRequest | None:
        """Return the durable stop request for a run, if it has been stopped."""
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        with self._lock:
            row = self._db.execute(
                "SELECT principal, reason FROM stop_requests WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        return StopRequest(run_id=run_id, principal=str(row[0]), reason=str(row[1]))

    def is_stopped(self, run_id: str) -> bool:
        """Report whether an authorized stop request is durably registered."""
        return self.stop_for(run_id) is not None

    def record_terminal_receipt(self, receipt: TerminalReceipt) -> TerminalReceipt:
        """Durably record canonical terminal evidence. Rejects conflicting retries."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT epoch, outcome, reason, unresolved_attempts, schema_version, "
                    "charge_summary, evidence_digest, cost_basis "
                    "FROM terminal_receipts WHERE run_id = ?",
                    (receipt.run_id,),
                ).fetchone()
                if existing is None:
                    self._db.execute(
                        "INSERT INTO terminal_receipts "
                        "(run_id, epoch, outcome, reason, unresolved_attempts, schema_version, "
                        "charge_summary, evidence_digest, cost_basis) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            receipt.run_id,
                            receipt.epoch,
                            receipt.outcome,
                            receipt.reason,
                            json.dumps(list(receipt.unresolved_attempts)),
                            receipt.schema_version,
                            json.dumps(list(receipt.charge_summary), separators=(",", ":")),
                            receipt.evidence_digest,
                            receipt.cost_basis,
                        ),
                    )
                    existing = self._db.execute(
                        "SELECT epoch, outcome, reason, unresolved_attempts, schema_version, "
                        "charge_summary, evidence_digest, cost_basis "
                        "FROM terminal_receipts WHERE run_id = ?",
                        (receipt.run_id,),
                    ).fetchone()
                if existing is None:
                    raise RuntimeError("terminal receipt insert did not produce a canonical row")
                stored = TerminalReceipt(
                    run_id=receipt.run_id,
                    epoch=existing[0],
                    outcome=existing[1],  # type: ignore[arg-type]
                    reason=existing[2],
                    unresolved_attempts=tuple(json.loads(existing[3])),
                    schema_version=existing[4],
                    charge_summary=tuple(tuple(item) for item in json.loads(existing[5])),
                    evidence_digest=existing[6],
                    cost_basis=existing[7],
                )
                if stored != receipt:
                    raise ValueError(f"conflicting terminal receipt for run {receipt.run_id}")
                self._db.execute("COMMIT")
            finally:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
        return stored

    def terminal_receipt(self, run_id: str) -> TerminalReceipt | None:
        """Read the immutable terminal summary for operator/API observability."""
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, outcome, reason, unresolved_attempts, schema_version, "
                "charge_summary, evidence_digest, cost_basis "
                "FROM terminal_receipts WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return None if row is None else self._receipt_from_row(run_id, row)

    def record_runtime_terminal(
        self,
        *,
        run_id: str,
        epoch: int,
        outcome: TerminalOutcome,
        reason: str,
    ) -> TerminalReceipt:
        """Derive terminal accounting evidence and persist it in one transaction.

        RunControl and StepLedger tables must share this SQLite file. Unresolved
        holds force ``unknown``; callers cannot supply a cancellation assertion.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")
        if not isinstance(outcome, str) or outcome not in {
            "completed", "interrupted", "cancelled", "refused", "budget", "unknown"
        }:
            raise ValueError("invalid terminal outcome")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT epoch, outcome, reason, unresolved_attempts, schema_version, "
                    "charge_summary, evidence_digest, cost_basis "
                    "FROM terminal_receipts WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if existing is not None:
                    stored = self._receipt_from_row(run_id, existing)
                    if stored.epoch != epoch:
                        raise ValueError("terminal receipt epoch conflicts with existing receipt")
                    if stored.reason != reason or (
                        stored.outcome != outcome and stored.outcome != "unknown"
                    ):
                        raise ValueError("conflicting runtime terminal retry")
                    self._db.execute("COMMIT")
                    return stored

                lease = self._db.execute(
                    "SELECT epoch, used FROM leases WHERE run_id = ?", (run_id,)
                ).fetchone()
                if lease is None or int(lease[0]) != epoch:
                    raise ValueError("terminal receipt requires the current run lease")
                holds = self._db.execute(
                    "SELECT attempt_id, hold_id, epoch, units, state FROM attempt_holds "
                    "WHERE run_id = ? ORDER BY attempt_id",
                    (run_id,),
                ).fetchall()
                unresolved = tuple(
                    str(row[0]) for row in holds if str(row[4]) in {"held", "unknown"}
                )
                projection = self._db.execute(
                    "SELECT cost_basis, elapsed_ms, cost_microunits, effect_attempts "
                    "FROM charge_projection WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                limits = self._db.execute(
                    "SELECT cost_basis FROM charge_limits WHERE run_id = ?", (run_id,)
                ).fetchone()
                cost_basis = str(projection[0]) if projection is not None else (
                    str(limits[0]) if limits is not None else "legacy_step_only"
                )
                charge = (
                    ("steps", int(lease[1])),
                    ("elapsed_ms", int(projection[1]) if projection is not None else 0),
                    ("cost_microunits", int(projection[2]) if projection is not None else 0),
                    ("effect_attempts", int(projection[3]) if projection is not None else 0),
                )
                if unresolved:
                    # The outcome and unresolved list express uncertainty while
                    # preserving the observed terminal cause in `reason`.
                    outcome = "unknown"
                body = {
                    "run_id": run_id,
                    "epoch": epoch,
                    "outcome": outcome,
                    "reason": reason,
                    "unresolved_attempts": list(unresolved),
                    "cost_basis": cost_basis,
                    "charge_summary": list(charge),
                    "holds": [list(row) for row in holds],
                }
                evidence_digest = hashlib.sha256(
                    json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                receipt = TerminalReceipt(
                    run_id=run_id,
                    epoch=epoch,
                    outcome=outcome,
                    reason=reason,
                    unresolved_attempts=unresolved,
                    charge_summary=charge,
                    evidence_digest=evidence_digest,
                    cost_basis=cost_basis,
                )
                self._db.execute(
                    "INSERT INTO terminal_receipts "
                    "(run_id, epoch, outcome, reason, unresolved_attempts, schema_version, "
                    "charge_summary, evidence_digest, cost_basis) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        epoch,
                        outcome,
                        reason,
                        json.dumps(list(unresolved)),
                        2,
                        json.dumps(list(charge), separators=(",", ":")),
                        evidence_digest,
                        cost_basis,
                    ),
                )
                self._db.execute("COMMIT")
                return receipt
            finally:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")

    def _receipt_from_row(self, run_id: str, row: tuple[object, ...]) -> TerminalReceipt:
        """Decode a stored legacy or schema-v2 receipt."""
        return TerminalReceipt(
            run_id=run_id,
            epoch=int(row[0]),
            outcome=row[1],  # type: ignore[arg-type]
            reason=str(row[2]),
            unresolved_attempts=tuple(json.loads(str(row[3]))),
            schema_version=int(row[4]),
            charge_summary=tuple(tuple(item) for item in json.loads(str(row[5]))),
            evidence_digest=row[6],  # type: ignore[arg-type]
            cost_basis=str(row[7]),
        )


class _DurableStopSignal:
    """Gate adapter whose reads and writes use the durable run-control store."""

    def __init__(self, control: RunControl, run_id: str, principal: str) -> None:
        """Bind stop operations to one registered run and owner."""
        self._control = control
        self._run_id = run_id
        self._principal = principal

    @property
    def reason(self) -> str | None:
        """Read the durable stop reason whenever the gate checks a boundary."""
        request = self._control.stop_for(self._run_id)
        return None if request is None else request.reason

    def request(self, reason: str) -> None:
        """Persist a stop before invoking any configured local notifier."""
        self._control.request_stop(
            StopRequest(run_id=self._run_id, principal=self._principal, reason=reason)
        )
