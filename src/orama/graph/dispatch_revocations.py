"""E1 C2 Part 3 Sections 1-2: consumer-local revocation and cascade authority facts.

Facts are written only in the transaction that acknowledges their event, so a refused or replayed
batch changes nothing. Step 4.3 Rule 4 reads them inside the dispatch transaction. A cascade can
only add a refusal. Reasons are consumer-local; no wire refusal code is added.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any, Final

REVOCATION_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS issuer_revocations ("
    " issuer_id TEXT NOT NULL, version INTEGER NOT NULL, subject_kind TEXT NOT NULL"
    " CHECK (subject_kind IN ('grant', 'approval', 'issuer')), subject_id TEXT NOT NULL,"
    " PRIMARY KEY (issuer_id, version))",
    "CREATE INDEX IF NOT EXISTS issuer_revocations_subject"
    " ON issuer_revocations (issuer_id, subject_kind, subject_id)",
    "CREATE TABLE IF NOT EXISTS issuer_cascades ("
    " issuer_id TEXT NOT NULL, version INTEGER NOT NULL, approval_id TEXT NOT NULL,"
    " issuer_authority_version INTEGER NOT NULL CHECK (issuer_authority_version >= 1),"
    " PRIMARY KEY (issuer_id, version))",
    "CREATE TABLE IF NOT EXISTS issuer_cascade_grants ("
    " issuer_id TEXT NOT NULL, version INTEGER NOT NULL, grant_id TEXT NOT NULL,"
    " PRIMARY KEY (issuer_id, version, grant_id))",
    "CREATE INDEX IF NOT EXISTS issuer_cascade_grants_grant"
    " ON issuer_cascade_grants (issuer_id, grant_id)",
)


def record(db: sqlite3.Connection, issuer_id: str, event: Mapping[str, Any]) -> None:
    """Record the authority fact carried by an acknowledged, validated event (idempotent)."""
    version, kind, body = event["version"], event["kind"], event["body"]
    if kind == "revocation":
        db.execute(
            "INSERT OR IGNORE INTO issuer_revocations (issuer_id, version, subject_kind, subject_id)"
            " VALUES (?, ?, ?, ?)",
            (issuer_id, version, body["subject_kind"], body["subject_id"]),
        )
    elif kind == "cascade":
        db.execute(
            "INSERT OR IGNORE INTO issuer_cascades (issuer_id, version, approval_id,"
            " issuer_authority_version) VALUES (?, ?, ?, ?)",
            (issuer_id, version, body["approval_id"], body["issuer_authority_version"]),
        )
        db.executemany(
            "INSERT OR IGNORE INTO issuer_cascade_grants (issuer_id, version, grant_id)"
            " VALUES (?, ?, ?)",
            [(issuer_id, version, grant_id) for grant_id in body["grant_ids"]],
        )


def _revoked(db: sqlite3.Connection, issuer_id: str, kind: str, subject: str) -> bool:
    """Return whether any acknowledged revocation names ``subject`` of ``kind``."""
    return db.execute(
        "SELECT 1 FROM issuer_revocations WHERE issuer_id = ? AND subject_kind = ?"
        " AND subject_id = ? LIMIT 1",
        (issuer_id, kind, subject),
    ).fetchone() is not None


def refusal_reason(
    db: sqlite3.Connection, issuer_id: str, grant_id: str, approval_ref: str | None
) -> str | None:
    """Return the consumer-local Rule 4 reason the recorded facts give, or None."""
    if _revoked(db, issuer_id, "issuer", issuer_id):
        return "issuer_revoked"
    if _revoked(db, issuer_id, "grant", grant_id):
        return "grant_revoked"
    if approval_ref is not None and _revoked(db, issuer_id, "approval", approval_ref):
        return "approval_revoked"
    if db.execute(
        "SELECT 1 FROM issuer_cascade_grants WHERE issuer_id = ? AND grant_id = ? LIMIT 1",
        (issuer_id, grant_id),
    ).fetchone() is not None:
        return "cascade_listed"
    return None


def facts(db: sqlite3.Connection, issuer_id: str) -> dict[str, list[tuple[Any, ...]]]:
    """Return the recorded revocations and cascades for an issuer, ordered by version."""
    revocations = db.execute(
        "SELECT version, subject_kind, subject_id FROM issuer_revocations WHERE issuer_id = ?"
        " ORDER BY version",
        (issuer_id,),
    ).fetchall()
    cascades = []
    for version, approval_id, authority in db.execute(
        "SELECT version, approval_id, issuer_authority_version FROM issuer_cascades"
        " WHERE issuer_id = ? ORDER BY version",
        (issuer_id,),
    ).fetchall():
        grants = [
            row[0] for row in db.execute(
                "SELECT grant_id FROM issuer_cascade_grants WHERE issuer_id = ? AND version = ?"
                " ORDER BY grant_id",
                (issuer_id, version),
            )
        ]
        cascades.append((version, approval_id, authority, grants))
    return {"revocations": [tuple(r) for r in revocations], "cascades": cascades}
