"""Standalone durable stop requests keyed by an already-trusted run id.

This module deliberately has no dependency on graph invocation or gate wiring.
Those integration points must wait for the authenticated run-identity decision.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


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


from typing import Literal

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
    schema_version: int = 1

    def __post_init__(self) -> None:
        """Validate taxonomy and invariants."""
        if not self.run_id or not isinstance(self.run_id, str):
            raise ValueError("run_id must be a non-empty string")
        if self.epoch < 1:
            raise ValueError("epoch must be >= 1")
        if self.outcome not in {
            "completed",
            "interrupted",
            "cancelled",
            "refused",
            "budget",
            "unknown",
        }:
            raise ValueError(f"invalid outcome: {self.outcome}")
        if not self.reason or not isinstance(self.reason, str):
            raise ValueError("reason must be a non-empty string")
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")


class StopNotAuthorized(PermissionError):
    """Raised when a principal is not the trusted owner of a run."""


class RunControl:
    """One durable stop source per store, with owner-only stop authority.

    ``register_run`` is the narrow trusted boundary for this standalone slice:
    callers must provide the already-authenticated owning principal. Production
    invocation wiring is intentionally outside this component.
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
        self._db = sqlite3.connect(str(store_path), isolation_level=None, check_same_thread=False)
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
            " reason TEXT NOT NULL, unresolved_attempts TEXT NOT NULL, schema_version INTEGER NOT NULL)"
        )

    def close(self) -> None:
        """Release the local SQLite connection."""
        self._db.close()

    def register_run(self, *, run_id: str, owner_principal: str) -> None:
        """Persist the trusted owner for a run before it can be stopped."""
        request = StopRequest(run_id=run_id, principal=owner_principal)
        with self._lock:
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

    def request_stop(self, request: StopRequest) -> StopRequest:
        """Durably record an authorized stop before any local notification."""
        with self._lock:
            owner = self._db.execute(
                "SELECT owner_principal FROM run_owners WHERE run_id = ?", (request.run_id,)
            ).fetchone()
            if owner is None or owner[0] != request.principal:
                raise StopNotAuthorized(request.run_id)
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
        if self._notifier is not None:
            self._notifier(stored)
        return stored

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
        import json
        with self._lock:
            existing = self._db.execute(
                "SELECT epoch, outcome, reason, unresolved_attempts, schema_version "
                "FROM terminal_receipts WHERE run_id = ?",
                (receipt.run_id,),
            ).fetchone()
            if existing is not None:
                unresolved = tuple(json.loads(existing[3]))
                stored = TerminalReceipt(
                    run_id=receipt.run_id,
                    epoch=int(existing[0]),
                    outcome=existing[1],  # type: ignore
                    reason=str(existing[2]),
                    unresolved_attempts=unresolved,
                    schema_version=int(existing[4]),
                )
                if stored != receipt:
                    raise ValueError(f"conflicting terminal receipt for run {receipt.run_id}")
                return stored

            unresolved_json = json.dumps(list(receipt.unresolved_attempts))
            self._db.execute(
                "INSERT INTO terminal_receipts (run_id, epoch, outcome, reason, unresolved_attempts, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    receipt.run_id,
                    receipt.epoch,
                    receipt.outcome,
                    receipt.reason,
                    unresolved_json,
                    receipt.schema_version,
                ),
            )
            return receipt

    def classify_termination(
        self,
        run_id: str,
        epoch: int,
        confirmed_cancelled: bool,
        requested_stop_reason: str,
        unsettled_attempts: Sequence[str] = (),
    ) -> TerminalReceipt:
        """Classify terminal outcome honestly based on verifiable evidence."""
        if unsettled_attempts or not confirmed_cancelled:
            outcome: TerminalOutcome = "unknown"
        else:
            outcome = "cancelled"
        
        receipt = TerminalReceipt(
            run_id=run_id,
            epoch=epoch,
            outcome=outcome,
            reason=requested_stop_reason,
            unresolved_attempts=tuple(unsettled_attempts),
        )
        return self.record_terminal_receipt(receipt)
