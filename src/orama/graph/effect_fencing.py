"""Explicit integer fencing epoch and terminal pre-dispatch refusals for effect attempts (DRAFT).

Two small pieces of durable state that live beside the E1/C2 attempt store and are written by it, in
the same ``BEGIN IMMEDIATE`` transaction as the ledger transition:

* the **fencing epoch**: the consumer's current authority epoch is a monotonic integer in one row.
  An attempt is stamped with the epoch it was authorized under. Authorizing under an epoch below the
  current one is refused, and a later send is refused when the epoch moved on (stale epoch).
* the **terminal refusal**: a pre-dispatch refusal recorded for an attempt identity. It is terminal;
  a replay with the same identity gets the same refusal back, and the table is append-only. The
  record carries the contract's public fields (``disposition``, ``refusal_code``, ``receipt_ref``,
  ``recorded_at``); the internal ``kind``, ``rule`` and ``reason`` stay beside them for logs and
  internals only and never reach a response. The row is an overlay that fences the attempt: it does
  not release the reservation or delete the outbox row, and a trigger (``outbox_no_send_after_refusal``)
  aborts any later ``send_started`` update on the attempt, so a refused attempt can never send even if
  a writer skips the store's own checks.

Functions take an open connection: the caller owns the transaction. This module holds no policy and
no I/O beyond that connection.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from orama.graph.effect_receipts import attempt_ref_for

FENCING_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS fencing_epoch_current ("
    " id INTEGER PRIMARY KEY CHECK (id = 1), epoch INTEGER NOT NULL CHECK (epoch >= 1))",
    "CREATE TABLE IF NOT EXISTS fencing_epoch_log ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT, epoch INTEGER NOT NULL, operator_ref TEXT NOT NULL,"
    " recorded_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS attempt_refusals ("
    " attempt_id TEXT PRIMARY KEY, kind TEXT NOT NULL, rule TEXT, reason TEXT NOT NULL,"
    " recorded_at TEXT NOT NULL, refusal_code TEXT, receipt_ref TEXT)",
    "CREATE TRIGGER IF NOT EXISTS attempt_refusals_no_update BEFORE UPDATE ON attempt_refusals"
    " BEGIN SELECT RAISE(ABORT, 'attempt_refusals is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS attempt_refusals_no_delete BEFORE DELETE ON attempt_refusals"
    " BEGIN SELECT RAISE(ABORT, 'attempt_refusals is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS outbox_no_send_after_refusal BEFORE UPDATE OF send_started ON outbox"
    " WHEN EXISTS (SELECT 1 FROM attempt_refusals WHERE attempt_id = NEW.attempt_id)"
    " BEGIN SELECT RAISE(ABORT, 'a refused attempt cannot start a send'); END",
    "CREATE TRIGGER IF NOT EXISTS fencing_epoch_log_no_update BEFORE UPDATE ON fencing_epoch_log"
    " BEGIN SELECT RAISE(ABORT, 'fencing_epoch_log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS fencing_epoch_log_no_delete BEFORE DELETE ON fencing_epoch_log"
    " BEGIN SELECT RAISE(ABORT, 'fencing_epoch_log is append-only'); END",
)

REFUSAL_KINDS: Final = frozenset({"authorization", "reservation", "final_boundary"})
REFUSAL_DISPOSITION: Final = "authorization_refused"
# A row written before ``refusal_code`` existed has none; it replays as the deny that never allows.
LEGACY_REFUSAL_CODE: Final = "deny.verifier_unavailable"


class FencingRefused(Exception):
    """The epoch is not admissible; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str) -> None:
        """Record the stable refusal reason."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class StoredRefusal:
    """A terminal pre-dispatch refusal recorded for one attempt identity.

    ``refusal_code`` (a public ``deny.*`` code), ``receipt_ref`` (opaque), ``disposition`` and
    ``recorded_at`` are the public fields; ``kind``, ``rule`` and ``reason`` are internal.
    """

    attempt_id: str
    kind: str
    rule: str | None
    reason: str
    recorded_at: str
    refusal_code: str
    receipt_ref: str

    @property
    def disposition(self) -> str:
        """Return the contract discriminator: a refusal is a disposition, never an outcome."""
        return REFUSAL_DISPOSITION


def require_epoch(epoch: object) -> int:
    """Return ``epoch`` when it is a real integer of at least 1; refuse bools and everything else."""
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise FencingRefused("fencing_epoch_invalid")
    return epoch


def current_epoch(db: sqlite3.Connection) -> int | None:
    """Return the store's current fencing epoch, or None before the first authorization."""
    row = db.execute("SELECT epoch FROM fencing_epoch_current WHERE id = 1").fetchone()
    return None if row is None else row[0]


def admit_epoch(db: sqlite3.Connection, epoch: int) -> None:
    """Admit an authorization under ``epoch``: refuse a stale one, raise the mark if it is higher."""
    require_epoch(epoch)
    current = current_epoch(db)
    if current is not None and epoch < current:
        raise FencingRefused("fencing_epoch_stale")
    if current is None:
        db.execute("INSERT INTO fencing_epoch_current (id, epoch) VALUES (1, ?)", (epoch,))
    elif epoch > current:
        db.execute("UPDATE fencing_epoch_current SET epoch = ? WHERE id = 1", (epoch,))


def stamp_attempt(db: sqlite3.Connection, attempt_id: str, epoch: int) -> None:
    """Record the epoch an attempt was authorized under; it can be written once."""
    cursor = db.execute(
        "UPDATE dispatch_attempts SET fencing_epoch = ? WHERE attempt_id = ?"
        " AND fencing_epoch IS NULL",
        (require_epoch(epoch), attempt_id),
    )
    if cursor.rowcount != 1:
        raise FencingRefused("fencing_epoch_already_stamped")


def attempt_epoch(db: sqlite3.Connection, attempt_id: str) -> int | None:
    """Return the epoch the attempt was authorized under, or None if it never was."""
    row = db.execute(
        "SELECT fencing_epoch FROM dispatch_attempts WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    return None if row is None else row[0]


def advance_epoch(db: sqlite3.Connection, epoch: int, operator_ref: str, now: datetime) -> None:
    """Raise the current epoch strictly (an authenticated operator action) and log it."""
    require_epoch(epoch)
    current = current_epoch(db)
    if current is not None and epoch <= current:
        raise FencingRefused("fencing_epoch_not_increasing")
    if current is None:
        db.execute("INSERT INTO fencing_epoch_current (id, epoch) VALUES (1, ?)", (epoch,))
    else:
        db.execute("UPDATE fencing_epoch_current SET epoch = ? WHERE id = 1", (epoch,))
    db.execute(
        "INSERT INTO fencing_epoch_log (epoch, operator_ref, recorded_at) VALUES (?, ?, ?)",
        (epoch, operator_ref, now.astimezone(UTC).isoformat()),
    )


def stored_refusal(db: sqlite3.Connection, attempt_id: str) -> StoredRefusal | None:
    """Return the terminal refusal recorded for the attempt identity, or None."""
    row = db.execute(
        "SELECT attempt_id, kind, rule, reason, recorded_at, refusal_code, receipt_ref"
        " FROM attempt_refusals WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        return None
    return StoredRefusal(
        row[0], row[1], row[2], row[3], row[4], row[5] or LEGACY_REFUSAL_CODE,
        row[6] or attempt_ref_for(row[0]),
    )


def record_refusal(
    db: sqlite3.Connection, attempt_id: str, kind: str, rule: str | None, reason: str, now: datetime,
    refusal_code: str = LEGACY_REFUSAL_CODE,
) -> StoredRefusal:
    """Record a terminal refusal once; the first one for an identity wins and is returned forever.

    ``refusal_code`` is the public ``deny.*`` code the refusal answers with, now and on every
    replay; the opaque ``receipt_ref`` is derived from the attempt identity and stored with it.
    """
    if kind not in REFUSAL_KINDS:
        raise ValueError(f"unknown refusal kind {kind!r}")
    db.execute(
        "INSERT OR IGNORE INTO attempt_refusals (attempt_id, kind, rule, reason, recorded_at,"
        " refusal_code, receipt_ref) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            attempt_id, kind, rule, reason, now.astimezone(UTC).isoformat(), refusal_code,
            attempt_ref_for(attempt_id),
        ),
    )
    kept = stored_refusal(db, attempt_id)
    if kept is None:  # pragma: no cover - the INSERT OR IGNORE guarantees a row
        raise RuntimeError("refusal record missing after insert")
    return kept
