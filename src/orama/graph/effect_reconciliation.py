"""Operator-visible reconciliation of unknown effect outcomes (DRAFT).

Two things, both observational by default:

* ``startup_reconciliation_report`` lists attempts whose send started but whose outcome was never
  proven (``unknown``). It is report-only: it reads, it never settles, retries or rewrites anything.
* A manual reconciliation is the only way an ``unknown`` becomes ``confirmed`` or ``failed`` by hand.
  It needs an authenticated operator (the injected ``OperatorAuthority``) at two points: opening a
  ticket scoped to one attempt, and spending it. A ticket expires after at most
  ``MAX_TICKET_TTL``, is single-use, and every ticket row is append-only apart from its one
  consumption stamp. Consuming it applies the same legal ``unknown`` to final transition as any other
  settlement and records the operator reference and the evidence reference. For a sealed send the
  redacted receipt is written in that same transaction.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from orama.graph.effect_outcomes import OutcomeRefused, check_transition
from orama.graph.effect_receipts import attempt_ref_for, insert_receipt, send_envelope_digest

MAX_TICKET_TTL: Final = timedelta(minutes=15)
MANUAL_EVIDENCE_PREFIX: Final = "manual-reconciliation:"
MANUAL_OUTCOMES: Final = frozenset({"confirmed", "failed"})
_TIME_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.%fZ"

RECONCILIATION_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS reconciliation_tickets ("
    " ticket_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, opened_by TEXT NOT NULL,"
    " expires_at TEXT NOT NULL, created_at TEXT NOT NULL, consumed_at TEXT,"
    " consumed_by TEXT, outcome TEXT, evidence_ref TEXT)",
    "CREATE TRIGGER IF NOT EXISTS reconciliation_tickets_no_delete BEFORE DELETE"
    " ON reconciliation_tickets"
    " BEGIN SELECT RAISE(ABORT, 'reconciliation_tickets is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS reconciliation_tickets_consume_only BEFORE UPDATE"
    " ON reconciliation_tickets"
    " WHEN OLD.ticket_id IS NOT NEW.ticket_id OR OLD.attempt_id IS NOT NEW.attempt_id"
    " OR OLD.opened_by IS NOT NEW.opened_by OR OLD.expires_at IS NOT NEW.expires_at"
    " OR OLD.created_at IS NOT NEW.created_at OR OLD.consumed_at IS NOT NULL"
    " BEGIN SELECT RAISE(ABORT, 'reconciliation_tickets only allows a first consumption'); END",
)


class ReconciliationRefused(OutcomeRefused):
    """A reconciliation step was refused; ``reason`` is a stable machine-readable code."""


class _Reportable(Protocol):
    """The slice of the attempt store the startup report needs."""

    def unknown_outbox_attempts(self) -> list[str]:
        """Return the attempt ids whose send started with an unproven outcome."""

    def unsent_outbox_count(self) -> int:
        """Return how many authorized outbox rows have not started their send."""


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """What a restart found: opaque references of in-doubt attempts and the count never sent."""

    in_doubt: tuple[str, ...]
    unsent: int

    def as_public(self) -> dict[str, object]:
        """Return the data-free form: opaque references and counts only."""
        return {"in_doubt": list(self.in_doubt), "unsent": self.unsent}


def startup_reconciliation_report(store: _Reportable) -> ReconciliationReport:
    """List unknown outbox rows for an operator; never settles, retries or alters anything."""
    refs = tuple(attempt_ref_for(a) for a in store.unknown_outbox_attempts())
    return ReconciliationReport(in_doubt=refs, unsent=store.unsent_outbox_count())


def unknown_attempts(db: sqlite3.Connection) -> list[str]:
    """Return attempt ids with ``send_started = 1`` and ``outcome = 'unknown'``, oldest id first."""
    rows = db.execute(
        "SELECT attempt_id FROM outbox WHERE send_started = 1 AND outcome = 'unknown'"
        " ORDER BY attempt_id"
    ).fetchall()
    return [r[0] for r in rows]


def unsent_count(db: sqlite3.Connection) -> int:
    """Return the number of authorized outbox rows whose send has not started."""
    return db.execute("SELECT count(*) FROM outbox WHERE send_started = 0").fetchone()[0]


def open_ticket(
    db: sqlite3.Connection, ticket_id: str, attempt_id: str, operator_ref: str, ttl: timedelta,
    now: datetime,
) -> str:
    """Open an expiring, single-use ticket scoped to one in-doubt attempt."""
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0) or ttl > MAX_TICKET_TTL:
        raise ReconciliationRefused("ticket_ttl_invalid")
    row = db.execute(
        "SELECT outcome, send_started FROM outbox WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is None:
        raise ReconciliationRefused("attempt_not_in_outbox")
    if not row[1]:
        raise ReconciliationRefused("send_not_started")
    if row[0] != "unknown":
        raise ReconciliationRefused("outcome_terminal")
    db.execute(
        "INSERT INTO reconciliation_tickets (ticket_id, attempt_id, opened_by, expires_at,"
        " created_at) VALUES (?, ?, ?, ?, ?)",
        (ticket_id, attempt_id, operator_ref, (now + ttl).astimezone(UTC).strftime(_TIME_FORMAT),
         now.astimezone(UTC).isoformat()),
    )
    return ticket_id


def _instant(stamp: object) -> datetime | None:
    """Parse a stored fixed-width UTC stamp into an aware instant, or None when it cannot be read."""
    if not isinstance(stamp, str):
        return None
    try:
        return datetime.strptime(stamp, _TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def spend_ticket(
    db: sqlite3.Connection, ticket_id: str, attempt_id: str, outcome: str, evidence_ref: str,
    operator_ref: str, now: datetime,
) -> None:
    """Spend the ticket once: settle ``unknown`` to ``outcome`` with the manual evidence reference.

    Ticket expiry compares the parsed stored instant with ``now`` (an aware datetime), never
    formatted text; a stored expiry that cannot be read counts as expired.
    """
    if outcome not in MANUAL_OUTCOMES:
        raise ReconciliationRefused("outcome_not_final")
    if not isinstance(evidence_ref, str) or not evidence_ref.strip():
        raise ReconciliationRefused("evidence_required")
    ticket = db.execute(
        "SELECT attempt_id, expires_at, consumed_at FROM reconciliation_tickets WHERE ticket_id = ?",
        (ticket_id,),
    ).fetchone()
    if ticket is None:
        raise ReconciliationRefused("ticket_unknown")
    if ticket[0] != attempt_id:
        raise ReconciliationRefused("ticket_scope_mismatch")
    if ticket[2] is not None:
        raise ReconciliationRefused("ticket_consumed")
    expires = _instant(ticket[1])
    if expires is None or now >= expires:
        raise ReconciliationRefused("ticket_expired")
    row = db.execute(
        "SELECT outcome, send_started FROM outbox WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is None:
        raise ReconciliationRefused("attempt_not_in_outbox")
    if not row[1]:
        raise ReconciliationRefused("send_not_started")
    evidence = MANUAL_EVIDENCE_PREFIX + evidence_ref.strip()
    check_transition(row[0], outcome, evidence)
    db.execute(
        "UPDATE outbox SET outcome = ?, outcome_evidence = ? WHERE attempt_id = ?",
        (outcome, evidence, attempt_id),
    )
    db.execute(
        "UPDATE reconciliation_tickets SET consumed_at = ?, consumed_by = ?, outcome = ?,"
        " evidence_ref = ? WHERE ticket_id = ? AND consumed_at IS NULL",
        (now.astimezone(UTC).isoformat(), operator_ref, outcome, evidence_ref.strip(), ticket_id),
    )
    envelope_digest = send_envelope_digest(db, attempt_id)
    if envelope_digest is not None:
        # A sealed send recorded its envelope when it started: write the receipt with the outcome
        # and the ticket consumption in this one transaction so ``publish_pending`` can deliver it.
        insert_receipt(db, attempt_id, outcome, envelope_digest, now)
