"""Standalone durable stop requests keyed by an already-trusted run id.

This module deliberately has no dependency on graph invocation or gate wiring.
Those integration points must wait for the authenticated run-identity decision.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
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
