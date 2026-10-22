"""E1 C2 Part 3 section 3.3: consumer anchor floor, bootstrap and anchor quarantine.

Consumer-local only. Oramasys holds no cryptography: the anchor signature is checked through
the injected ``SignatureVerifier`` and the issuer key only through the injected
``TrustedIssuerKeys`` port. Nothing here adds a wire refusal code or a serving path.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from orama.graph.dispatch_consumer_wire import (
    SignatureVerifier,
    WireError,
    event_digest,
    validate_event_wire,
)

ANCHOR_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS issuer_anchor ("
    " issuer_id TEXT PRIMARY KEY, issuer_key_id TEXT NOT NULL, version INTEGER NOT NULL,"
    " event_digest TEXT NOT NULL, anchor_floor INTEGER NOT NULL, base_version INTEGER NOT NULL,"
    " base_digest TEXT NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0"
    " CHECK (quarantined IN (0, 1)), created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS issuer_anchor_conflicts ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT, issuer_id TEXT NOT NULL, evidence TEXT NOT NULL,"
    " recorded_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS anchor_quarantine_log ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT, issuer_id TEXT NOT NULL, previous_record TEXT NOT NULL,"
    " accepted_record TEXT NOT NULL, trusted_evidence TEXT NOT NULL, operator_reference TEXT NOT NULL,"
    " recorded_at TEXT NOT NULL)",
    "CREATE TRIGGER IF NOT EXISTS anchor_quarantine_log_no_update BEFORE UPDATE ON"
    " anchor_quarantine_log BEGIN SELECT RAISE(ABORT, 'anchor_quarantine_log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS anchor_quarantine_log_no_delete BEFORE DELETE ON"
    " anchor_quarantine_log BEGIN SELECT RAISE(ABORT, 'anchor_quarantine_log is append-only'); END",
)
FLOOR_REASON: Final = "anchor_floor.permit_below_floor"
QUARANTINE_REASON: Final = "anchor_quarantined"
_RECORD_COLUMNS: Final = (
    "issuer_id, issuer_key_id, version, event_digest, anchor_floor, base_version, base_digest,"
    " quarantined"
)


class TrustedIssuerKeys(Protocol):
    """Locally trusted key material: does ``key_id`` belong to ``issuer_id``?"""

    def key_belongs_to(self, issuer_id: str, key_id: str) -> bool:
        """Return True only for a locally trusted key of the declared issuer."""
        ...


class AnchorRefused(Exception):
    """Plain consumer-local refusal of a bootstrap; nothing is persisted."""

    def __init__(self, reason: str) -> None:
        """Record the consumer-local reason."""
        super().__init__(reason)
        self.reason = reason


class AnchorConflict(AnchorRefused):
    """A repeated bootstrap differs from the persisted record; quarantine is retained."""


class AnchorQuarantined(Exception):
    """Dispatch for the issuer is blocked by anchor quarantine (consumer-local, not wire)."""

    reason = QUARANTINE_REASON


class AnchorFloorRefused(Exception):
    """The permit's R_p is below the persisted anchor floor (consumer-local, not wire)."""

    reason = FLOOR_REASON


def _text(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def base_version(db: sqlite3.Connection, issuer_id: str) -> int | None:
    """Return the checkpoint-aware acknowledgement base version, or None without an anchor."""
    row = db.execute(
        "SELECT base_version FROM issuer_anchor WHERE issuer_id = ?", (issuer_id,)
    ).fetchone()
    return None if row is None else row[0]


def record(db: sqlite3.Connection, issuer_id: str) -> dict[str, Any] | None:
    """Return the persisted anchor record for read-only inspection."""
    row = db.execute(
        f"SELECT {_RECORD_COLUMNS} FROM issuer_anchor WHERE issuer_id = ?", (issuer_id,)
    ).fetchone()
    return None if row is None else dict(zip(_RECORD_COLUMNS.replace(" ", "").split(","), row))


def assert_not_quarantined(db: sqlite3.Connection, issuer_id: str) -> None:
    """Refuse every dispatch authorization for a quarantined issuer."""
    row = db.execute(
        "SELECT quarantined FROM issuer_anchor WHERE issuer_id = ?", (issuer_id,)
    ).fetchone()
    if row is not None and row[0]:
        raise AnchorQuarantined(QUARANTINE_REASON)


def assert_permit_at_or_above_floor(
    db: sqlite3.Connection, issuer_id: str, revocation_version: int
) -> None:
    """Refuse a permit whose R_p is below the persisted floor; an issuer without one has none."""
    row = db.execute(
        "SELECT anchor_floor FROM issuer_anchor WHERE issuer_id = ?", (issuer_id,)
    ).fetchone()
    if row is not None and revocation_version < row[0]:
        raise AnchorFloorRefused(FLOOR_REASON)


def verified_anchor(
    issuer_id: str,
    anchor_event: Mapping[str, Any],
    verifier: SignatureVerifier,
    trusted_keys: TrustedIssuerKeys,
) -> dict[str, Any]:
    """Validate shape, recompute the digest, resolve the key locally and verify the signature."""
    try:
        event = validate_event_wire(anchor_event)
    except WireError as error:
        raise AnchorRefused("malformed") from error
    computed = event_digest(
        event["version"], event["kind"], event["body"], event["previous_event_digest"]
    )
    if computed != event["event_digest"]:
        raise AnchorRefused("event_digest")
    if event["version"] < 2:
        raise AnchorRefused("anchor_version")
    if not trusted_keys.key_belongs_to(issuer_id, event["issuer_key_id"]):
        raise AnchorRefused("untrusted_key")
    if not verifier.verify_event(event["issuer_key_id"], computed, event["signature"]):
        raise AnchorRefused("event_signature")
    return dict(event)


def install_or_quarantine(
    db: sqlite3.Connection, issuer_id: str, event: Mapping[str, Any], now: datetime
) -> bool:
    """Persist the anchor atomically, no-op an identical repeat, or flag a conflict.

    Runs inside the caller's ``BEGIN IMMEDIATE`` transaction. Returns True when the repeat
    conflicted (the flag is set and the evidence kept; persisted values are never overwritten).
    """
    version, digest, key_id = event["version"], event["event_digest"], event["issuer_key_id"]
    row = db.execute(
        "SELECT issuer_key_id, version, event_digest, anchor_floor FROM issuer_anchor"
        " WHERE issuer_id = ?",
        (issuer_id,),
    ).fetchone()
    if row is None:
        if db.execute(
            "SELECT 1 FROM issuer_cascade_ack WHERE issuer_id = ?", (issuer_id,)
        ).fetchone():
            raise AnchorRefused("already_replayed")
        db.execute(
            "INSERT INTO issuer_anchor (issuer_id, issuer_key_id, version, event_digest,"
            " anchor_floor, base_version, base_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (issuer_id, key_id, version, digest, version, version, digest, _text(now)),
        )
        db.execute(
            "INSERT INTO issuer_cascade_ack (issuer_id, version, event_digest, applied_at)"
            " VALUES (?, ?, ?, ?)",
            (issuer_id, version, digest, _text(now)),
        )
        return False
    if tuple(row) == (key_id, version, digest, version):
        return False
    db.execute("UPDATE issuer_anchor SET quarantined = 1 WHERE issuer_id = ?", (issuer_id,))
    db.execute(
        "INSERT INTO issuer_anchor_conflicts (issuer_id, evidence, recorded_at) VALUES (?, ?, ?)",
        (issuer_id, json.dumps(dict(event), sort_keys=True), _text(now)),
    )
    return True


def clear(
    db: sqlite3.Connection,
    issuer_id: str,
    *,
    operator_reference: str,
    trusted_evidence: str,
    now: datetime,
) -> bool:
    """Clear an existing quarantine and append the audit row; False when none exists."""
    current = record(db, issuer_id)
    if current is None or not current["quarantined"]:
        return False
    previous = json.dumps(current, sort_keys=True)
    accepted = json.dumps({**current, "quarantined": 0}, sort_keys=True)
    db.execute(
        "INSERT INTO anchor_quarantine_log (issuer_id, previous_record, accepted_record,"
        " trusted_evidence, operator_reference, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
        (issuer_id, previous, accepted, trusted_evidence, operator_reference, _text(now)),
    )
    db.execute("UPDATE issuer_anchor SET quarantined = 0 WHERE issuer_id = ?", (issuer_id,))
    return True
