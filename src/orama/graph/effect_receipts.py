"""Redacted dispatch receipts for effect attempts (DRAFT).

A receipt is ``{attempt_ref, outcome, receipt_digest, recorded_at}`` and nothing else public: no
payload, no operation digest, no grant id, no key id, no principal. It is written in the same
``BEGIN IMMEDIATE`` transaction as the outcome it describes, so a receipt exists exactly when the
settlement does. Rows are never deleted or rewritten; the one allowed change is stamping
``published_at`` once the receipt has been delivered to its observer.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

RECEIPT_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS effect_receipts ("
    " attempt_id TEXT PRIMARY KEY, attempt_ref TEXT NOT NULL UNIQUE, outcome TEXT NOT NULL,"
    " receipt_digest TEXT NOT NULL, envelope_digest TEXT NOT NULL, recorded_at TEXT NOT NULL,"
    " published_at TEXT)",
    "CREATE TRIGGER IF NOT EXISTS effect_receipts_no_delete BEFORE DELETE ON effect_receipts"
    " BEGIN SELECT RAISE(ABORT, 'effect_receipts is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS effect_receipts_publish_only BEFORE UPDATE ON effect_receipts"
    " WHEN OLD.attempt_id IS NOT NEW.attempt_id OR OLD.attempt_ref IS NOT NEW.attempt_ref"
    " OR OLD.outcome IS NOT NEW.outcome OR OLD.receipt_digest IS NOT NEW.receipt_digest"
    " OR OLD.envelope_digest IS NOT NEW.envelope_digest OR OLD.recorded_at IS NOT NEW.recorded_at"
    " OR OLD.published_at IS NOT NULL"
    " BEGIN SELECT RAISE(ABORT, 'effect_receipts only allows a first publication stamp'); END",
)


@dataclass(frozen=True, slots=True)
class RedactedReceipt:
    """The public receipt record; carries no payload, grant, key or principal."""

    attempt_ref: str
    outcome: str
    receipt_digest: str
    recorded_at: str

    def as_dict(self) -> dict[str, str]:
        """Return the four public fields."""
        return {
            "attempt_ref": self.attempt_ref, "outcome": self.outcome,
            "receipt_digest": self.receipt_digest, "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True, slots=True)
class StoredReceipt:
    """A stored receipt with the envelope digest it answers and its publication stamp."""

    receipt: RedactedReceipt
    attempt_id: str
    envelope_digest: str
    published_at: str | None


def attempt_ref_for(attempt_id: str) -> str:
    """Return the opaque, non-reversible public reference for an attempt identity."""
    return hashlib.sha256(f"orama-attempt-ref/v1|{attempt_id}".encode()).hexdigest()[:32]


def receipt_digest_for(attempt_ref: str, outcome: str, envelope_digest: str) -> str:
    """Return the deterministic digest of the receipt's public facts and the envelope it answers."""
    body = {"v": 1, "attempt_ref": attempt_ref, "outcome": outcome, "envelope_digest": envelope_digest}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def insert_receipt(
    db: sqlite3.Connection, attempt_id: str, outcome: str, envelope_digest: str, now: datetime
) -> RedactedReceipt:
    """Insert the receipt for a settled attempt; a second insert for one identity is refused."""
    ref = attempt_ref_for(attempt_id)
    digest = receipt_digest_for(ref, outcome, envelope_digest)
    stamp = now.astimezone(UTC).isoformat()
    db.execute(
        "INSERT INTO effect_receipts (attempt_id, attempt_ref, outcome, receipt_digest,"
        " envelope_digest, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
        (attempt_id, ref, outcome, digest, envelope_digest, stamp),
    )
    return RedactedReceipt(ref, outcome, digest, stamp)


def _row_to_stored(row: tuple) -> StoredReceipt:
    """Build a stored receipt from a table row."""
    attempt_id, ref, outcome, digest, envelope, recorded, published = row
    return StoredReceipt(RedactedReceipt(ref, outcome, digest, recorded), attempt_id, envelope, published)


_COLUMNS: Final = (
    "attempt_id, attempt_ref, outcome, receipt_digest, envelope_digest, recorded_at, published_at"
)


def get_receipt(db: sqlite3.Connection, attempt_id: str) -> StoredReceipt | None:
    """Return the stored receipt for the attempt identity, or None."""
    row = db.execute(
        f"SELECT {_COLUMNS} FROM effect_receipts WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    return None if row is None else _row_to_stored(row)


def mark_published(db: sqlite3.Connection, attempt_id: str, now: datetime) -> bool:
    """Stamp the first publication; return False when it was already published or is unknown."""
    cursor = db.execute(
        "UPDATE effect_receipts SET published_at = ? WHERE attempt_id = ? AND published_at IS NULL",
        (now.astimezone(UTC).isoformat(), attempt_id),
    )
    return cursor.rowcount == 1


def unpublished(db: sqlite3.Connection, limit: int) -> list[StoredReceipt]:
    """Return up to ``limit`` receipts not yet delivered to the observer, oldest first."""
    rows = db.execute(
        f"SELECT {_COLUMNS} FROM effect_receipts WHERE published_at IS NULL"
        " ORDER BY recorded_at, attempt_id LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_stored(row) for row in rows]
