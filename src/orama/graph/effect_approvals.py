"""Single-use human approval for one concrete effect attempt (DRAFT).

An approval is recorded by an authenticated operator (the store checks the injected
``OperatorAuthority``) for exactly one tuple: attempt id, principal, operation digest, target, fencing
epoch and expiry. It is consumed in the same ``BEGIN IMMEDIATE`` transaction that sets
``send_started``, so a consumed approval always has a send marker and a send marker always has a
consumed approval. It cannot be reused for a changed payload, principal, target, epoch or expiry: the
tuple must match exactly, and a changed tuple is a different attempt. Rows are never deleted; the only
permitted update is stamping ``consumed_at`` once.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Final

from orama.graph.final_boundary import FinalBoundaryBinding, FinalBoundaryRefused

APPROVAL_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS effect_approvals ("
    " approval_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE, principal TEXT NOT NULL,"
    " operation_digest TEXT NOT NULL, target TEXT NOT NULL, epoch INTEGER NOT NULL,"
    " expires_at TEXT NOT NULL, approver_ref TEXT NOT NULL, created_at TEXT NOT NULL,"
    " consumed_at TEXT)",
    "CREATE TRIGGER IF NOT EXISTS effect_approvals_no_delete BEFORE DELETE ON effect_approvals"
    " BEGIN SELECT RAISE(ABORT, 'effect_approvals is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS effect_approvals_consume_only BEFORE UPDATE ON effect_approvals"
    " WHEN OLD.approval_id IS NOT NEW.approval_id OR OLD.attempt_id IS NOT NEW.attempt_id"
    " OR OLD.principal IS NOT NEW.principal OR OLD.operation_digest IS NOT NEW.operation_digest"
    " OR OLD.target IS NOT NEW.target OR OLD.epoch IS NOT NEW.epoch"
    " OR OLD.expires_at IS NOT NEW.expires_at OR OLD.approver_ref IS NOT NEW.approver_ref"
    " OR OLD.created_at IS NOT NEW.created_at OR OLD.consumed_at IS NOT NULL"
    " BEGIN SELECT RAISE(ABORT, 'effect_approvals only allows a first consumption stamp'); END",
)

_TIME_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.%fZ"


def _digest(value: str) -> str:
    """Return the ``sha256:`` form so stored and presented digests compare alike."""
    return value if value.startswith("sha256:") else f"sha256:{value}"


def _tuple_of(binding: FinalBoundaryBinding) -> tuple[str, str, str, str, int, str]:
    """Return the comparable tuple of a binding (expiry as fixed-width UTC text)."""
    return (
        binding.attempt_id, binding.principal, _digest(binding.operation_digest), binding.target,
        binding.epoch, binding.expires_at.astimezone(UTC).strftime(_TIME_FORMAT),
    )


def create_approval(
    db: sqlite3.Connection, approval_id: str, binding: FinalBoundaryBinding, approver_ref: str,
    now: datetime,
) -> str:
    """Record the approval for the exact tuple; an identical unconsumed repeat returns the same id."""
    attempt, principal, digest, target, epoch, expires = _tuple_of(binding)
    row = db.execute(
        "SELECT approval_id, principal, operation_digest, target, epoch, expires_at, consumed_at"
        " FROM effect_approvals WHERE attempt_id = ?",
        (attempt,),
    ).fetchone()
    if row is not None:
        if row[6] is not None:
            raise FinalBoundaryRefused("approval_consumed")
        if tuple(row[1:6]) != (principal, digest, target, epoch, expires):
            raise FinalBoundaryRefused("approval_conflict")
        return row[0]
    db.execute(
        "INSERT INTO effect_approvals (approval_id, attempt_id, principal, operation_digest,"
        " target, epoch, expires_at, approver_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (approval_id, attempt, principal, digest, target, epoch, expires, approver_ref,
         now.astimezone(UTC).isoformat()),
    )
    return approval_id


def consume_approval(db: sqlite3.Connection, binding: FinalBoundaryBinding, now: datetime) -> None:
    """Consume the approval for ``binding`` once, or raise ``FinalBoundaryRefused`` naming why not."""
    attempt, principal, digest, target, epoch, expires = _tuple_of(binding)
    row = db.execute(
        "SELECT principal, operation_digest, target, epoch, expires_at, consumed_at"
        " FROM effect_approvals WHERE attempt_id = ?",
        (attempt,),
    ).fetchone()
    if row is None:
        raise FinalBoundaryRefused("approval_missing")
    if row[5] is not None:
        raise FinalBoundaryRefused("approval_consumed")
    if tuple(row[:5]) != (principal, digest, target, epoch, expires):
        raise FinalBoundaryRefused("approval_mismatch")
    if now.astimezone(UTC).strftime(_TIME_FORMAT) >= expires:
        raise FinalBoundaryRefused("approval_expired")
    db.execute(
        "UPDATE effect_approvals SET consumed_at = ? WHERE attempt_id = ? AND consumed_at IS NULL",
        (now.astimezone(UTC).isoformat(), attempt),
    )


def approval_state(db: sqlite3.Connection, attempt_id: str) -> str | None:
    """Return ``granted``, ``consumed`` or None for the attempt (no tuple data)."""
    row = db.execute(
        "SELECT consumed_at FROM effect_approvals WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is None:
        return None
    return "granted" if row[0] is None else "consumed"
