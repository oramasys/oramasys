"""E1 effect proposals and scoped single-use reservations.

A proposal records WHAT is being asked (the scope) and carries no authorization state; it exists
before any grant is looked up. A reservation binds exactly one proposal's scope to a single use
with an expiry. Consuming it happens inside the consumer's step 4.3 transaction, so a racing
second consumer, a changed scope field, a different principal or an expired reservation is
refused and the whole transaction rolls back. Functions take an open connection: the caller owns
the ``BEGIN IMMEDIATE`` transaction, so these are atomic with the dispatch transaction.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from orama.graph.dispatch_consumer_wire import WireError, parse_timestamp

SCOPE_FIELDS: Final = (
    "principal", "graph_id", "policy_hash", "operation_digest", "artifact_identity", "destination",
)

PROPOSAL_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS effect_proposals ("
    " proposal_id TEXT PRIMARY KEY, principal TEXT NOT NULL, graph_id TEXT NOT NULL,"
    " policy_hash TEXT NOT NULL, operation_digest TEXT NOT NULL,"
    " artifact_identity TEXT NOT NULL, destination TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS reservations ("
    " reservation_id TEXT PRIMARY KEY,"
    " proposal_id TEXT NOT NULL REFERENCES effect_proposals (proposal_id),"
    " scope_digest TEXT NOT NULL, expires_at TEXT NOT NULL,"
    " consumed_attempt_id TEXT UNIQUE, created_at TEXT NOT NULL)",
)


class ReservationRefused(Exception):
    """A proposal, reservation or scope check failed; ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        """Record the stable machine-readable refusal reason."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class EffectScope:
    """The six dimensions a single-use approval is bound to; cross-purpose reuse is refused.

    Two fields map onto the issuer's permit, which is how a reservation is tied to the permit that
    authorizes it: ``operation_digest`` is the permit's ``request_digest`` and ``artifact_identity``
    is the permit's ``artifact_digest`` (consumer-asserted). The other four are consumer-side scope.
    ``bind_scope_to_permit`` enforces the mapping at dispatch.
    """

    principal: str
    graph_id: str
    policy_hash: str
    operation_digest: str
    artifact_identity: str
    destination: str

    def __post_init__(self) -> None:
        """Reject blank scope dimensions before the value becomes a durable binding."""
        for name in SCOPE_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-blank text")

    def digest(self) -> str:
        """Return the SHA-256 of the canonical JSON of all six fields."""
        body = {name: getattr(self, name) for name in SCOPE_FIELDS}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stamp(moment: datetime) -> str:
    """Return the fixed-width UTC text used for stored instants (sortable, comparable)."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _load_scope(db: sqlite3.Connection, proposal_id: str) -> EffectScope:
    """Load the proposal's immutable scope or refuse an unknown proposal identifier."""
    row = db.execute(
        "SELECT principal, graph_id, policy_hash, operation_digest, artifact_identity,"
        " destination FROM effect_proposals WHERE proposal_id = ?",
        (proposal_id,),
    ).fetchone()
    if row is None:
        raise ReservationRefused("proposal_unknown")
    return EffectScope(*row)


def bind_scope_to_permit(scope: EffectScope | None, permit: Mapping[str, object]) -> None:
    """Refuse unless the reservation's scope names the operation and artifact the permit authorizes.

    The permit is already bound to the reservation by id (rule 1), so this ties the reservation's
    CONTENT to the permit: a reservation made for one operation or artifact cannot authorize a permit
    for another, even when the caller presents the reserved scope.
    """
    if (
        scope is None
        or scope.operation_digest != permit["request_digest"]
        or scope.artifact_identity != permit["artifact_digest"]
    ):
        raise ReservationRefused("scope_not_bound_to_permit")


def record_proposal(
    db: sqlite3.Connection, proposal_id: str, scope: EffectScope, now: datetime
) -> None:
    """Record a proposal (idempotent when identical; a different scope for one id is refused)."""
    existing = db.execute(
        "SELECT 1 FROM effect_proposals WHERE proposal_id = ?", (proposal_id,)
    ).fetchone()
    if existing is not None:
        if _load_scope(db, proposal_id) != scope:
            raise ReservationRefused("proposal_conflict")
        return
    db.execute(
        "INSERT INTO effect_proposals (proposal_id, principal, graph_id, policy_hash,"
        " operation_digest, artifact_identity, destination, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (proposal_id, *(getattr(scope, name) for name in SCOPE_FIELDS), _stamp(now)),
    )


def reserve(
    db: sqlite3.Connection,
    reservation_id: str,
    proposal_id: str,
    scope: EffectScope,
    expires_at: datetime,
    now: datetime,
) -> None:
    """Bind the proposal's scope to a single-use reservation that expires at ``expires_at``."""
    if _load_scope(db, proposal_id) != scope:
        raise ReservationRefused("scope_mismatch")
    if _stamp(expires_at) <= _stamp(now):
        raise ReservationRefused("reservation_expired")
    if db.execute(
        "SELECT 1 FROM reservations WHERE reservation_id = ?", (reservation_id,)
    ).fetchone() is not None:
        raise ReservationRefused("reservation_exists")
    db.execute(
        "INSERT INTO reservations (reservation_id, proposal_id, scope_digest, expires_at,"
        " created_at) VALUES (?, ?, ?, ?, ?)",
        (reservation_id, proposal_id, scope.digest(), _stamp(expires_at), _stamp(now)),
    )


def consume_reservation(
    db: sqlite3.Connection,
    reservation_id: str,
    attempt_id: str,
    scope: EffectScope | None,
    now: datetime,
) -> None:
    """Consume the reservation for ``attempt_id`` if scope matches and it is live and unused."""
    if scope is None:
        raise ReservationRefused("scope_required")
    row = db.execute(
        "SELECT scope_digest, expires_at, consumed_attempt_id FROM reservations"
        " WHERE reservation_id = ?",
        (reservation_id,),
    ).fetchone()
    if row is None:
        raise ReservationRefused("reservation_unknown")
    stored_digest, expires_at, consumed_by = row
    if consumed_by is not None:
        expired = consumed_by.startswith("expired:")  # set by a clock reconciliation
        raise ReservationRefused("reservation_expired" if expired else "reservation_consumed")
    if scope.digest() != stored_digest:
        raise ReservationRefused("scope_mismatch")
    try:
        expiry = parse_timestamp(expires_at)
    except WireError as error:  # an unreadable stored expiry is never treated as live
        raise ReservationRefused("reservation_expiry_unreadable") from error
    if parse_timestamp(_stamp(now)) >= expiry:
        raise ReservationRefused("reservation_expired")
    db.execute(
        "UPDATE reservations SET consumed_attempt_id = ? WHERE reservation_id = ?",
        (attempt_id, reservation_id),
    )
