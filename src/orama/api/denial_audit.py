"""Append-only durable audit references for serving denials (DRAFT).

One SQLite table ``denial_audit(correlation_id, code, recorded_at)``. It holds no grant id, key id,
principal, path or payload: a denial can be found again by its correlation id and public code and
by nothing else. Triggers make UPDATE and DELETE abort, so the record only grows. This store is
separate from the effect attempt ledger; the verify-only surface never opens that ledger.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from orama.api.public_errors import DENY_CODES
from orama.graph.private_store import prepare_private_store

_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS denial_audit ("
    " correlation_id TEXT NOT NULL, code TEXT NOT NULL, recorded_at TEXT NOT NULL)",
    "CREATE TRIGGER IF NOT EXISTS denial_audit_no_update BEFORE UPDATE ON denial_audit"
    " BEGIN SELECT RAISE(ABORT, 'denial_audit is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS denial_audit_no_delete BEFORE DELETE ON denial_audit"
    " BEGIN SELECT RAISE(ABORT, 'denial_audit is append-only'); END",
)


def receipt_ref_for(correlation_id: str, code: str) -> str:
    """Return the opaque, non-reversible reference a client can quote for one recorded denial."""
    digest = hashlib.sha256(f"orama-denial-audit/v1|{correlation_id}|{code}".encode()).hexdigest()
    return digest[:32]


class DenialAuditLog:
    """Append-only SQLite log of (correlation_id, code, recorded_at) for public deny codes."""

    def __init__(self, path: Path | str) -> None:
        """Open (creating privately) the audit database and its append-only table."""
        self._lock = threading.Lock()
        self._db = sqlite3.connect(
            str(prepare_private_store(path)), isolation_level=None, check_same_thread=False,
            timeout=30.0,
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        for statement in _SCHEMA:
            self._db.execute(statement)

    def record(self, correlation_id: str, code: str, now: datetime | None = None) -> str:
        """Durably append one denial and return its opaque receipt reference."""
        if code not in DENY_CODES:
            raise ValueError(f"{code!r} is not a recordable denial code")
        if not isinstance(correlation_id, str) or not correlation_id.strip():
            raise ValueError("correlation_id is required")
        stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with self._lock:
            self._db.execute(
                "INSERT INTO denial_audit (correlation_id, code, recorded_at) VALUES (?, ?, ?)",
                (correlation_id, code, stamp),
            )
        return receipt_ref_for(correlation_id, code)

    def has(self, receipt_ref: str) -> bool:
        """Return True when ``receipt_ref`` names a recorded denial."""
        with self._lock:
            rows = self._db.execute("SELECT correlation_id, code FROM denial_audit").fetchall()
        return any(receipt_ref_for(c, k) == receipt_ref for c, k in rows)

    def count(self) -> int:
        """Return the number of recorded denials."""
        with self._lock:
            return self._db.execute("SELECT count(*) FROM denial_audit").fetchone()[0]

    def close(self) -> None:
        """Close the connection."""
        self._db.close()
