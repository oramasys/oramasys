"""Single-use human approval, authenticated manual reconciliation and the startup report (DRAFT)."""
from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.server import create_app
from orama.graph import effect_approvals
from orama.graph.dispatch_attempts import OperatorRefused, SqliteAttemptStore
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.effect_reconciliation import (
    MAX_TICKET_TTL,
    ReconciliationRefused,
    startup_reconciliation_report,
)
from orama.graph.effect_receipts import attempt_ref_for
from orama.graph.final_boundary import FinalBoundaryRefused
from orama.graph.sealed_inert_driver import SealedInertDriver
from tests.test_dispatch_attempts import ATTEMPT, ISSUER, NOW, Harness
from tests.test_effect_fencing import Operator
from tests.test_effect_seam import LIVE_UNTIL, quiet_snapshot
from tests.test_final_boundary import Approvals, binding
from tests.test_inert_effect_integration import inert_harness
from tests.test_sealed_inert_driver import Recorder, driver, envelope, send

OTHER_OPERATOR = "operator-ref-2"


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    """An authorized inert attempt with no approval yet."""
    harness = inert_harness(tmp_path)
    yield harness
    harness.store.close()


def approve(h: Harness, **changes) -> str:
    """Grant the approval for the genuine tuple, with optional changes to the presented tuple."""
    return h.store.grant_effect_approval(binding(**changes), approver=Operator(), now=NOW)


def in_doubt(h: Harness) -> None:
    """Put the attempt in the dispatched-but-unproven state."""
    h.store.begin_send(ATTEMPT, inert_only=True, now=NOW)


# ---------------------------------------------------------------- approvals


def test_no_approval_no_send(h: Harness) -> None:
    """Without the human approval the sealed send refuses and nothing is dispatched or burned."""
    sim = Recorder()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        send(driver(h, simulation=sim))
    assert excinfo.value.reason == "approval_missing" and not excinfo.value.terminal
    assert sim.calls == 0
    row = h.store.outbox_row(ATTEMPT)
    assert row["send_started"] == 0
    assert h.store.terminal_refusal(ATTEMPT) is None and h.store.approval_state(ATTEMPT) is None


def test_granting_needs_an_authenticated_operator(h: Harness) -> None:
    """A refused or blank operator reference records nothing."""
    for reference in (None, "", "  "):
        with pytest.raises(OperatorRefused):
            h.store.grant_effect_approval(binding(), approver=Operator(reference), now=NOW)
    assert h.store.approval_state(ATTEMPT) is None


def test_the_operator_is_asked_about_this_attempt(h: Harness) -> None:
    """The authority port sees the operation name and the attempt as the subject."""
    operator = Operator()
    h.store.grant_effect_approval(binding(), approver=operator, now=NOW)
    assert operator.calls == [("approve_effect", ATTEMPT)]


def test_approval_is_bound_to_the_exact_tuple_at_grant_time(h: Harness) -> None:
    """A changed principal, digest, target, epoch or expiry cannot be approved; none is recorded."""
    for changes, reason in (
        ({"principal": "mallory"}, "principal_mismatch"),
        ({"operation_digest": "sha256:" + "9" * 64}, "operation_digest_mismatch"),
        ({"target": "inert://elsewhere"}, "target_mismatch"),
        ({"epoch": 4}, "epoch_mismatch"),
        ({"expires_at": LIVE_UNTIL + timedelta(hours=1)}, "expiry_mismatch"),
    ):
        with pytest.raises(FinalBoundaryRefused) as excinfo:
            approve(h, **changes)
        assert excinfo.value.reason == reason
    assert h.store.approval_state(ATTEMPT) is None


def test_an_unauthorized_or_refused_attempt_cannot_be_approved(tmp_path: Path, h: Harness) -> None:
    """Only a durably authorized, unrefused attempt takes an approval."""
    h.store.record_terminal_refusal(ATTEMPT, "final_boundary", None, "effects_denied", NOW)
    with pytest.raises(FinalBoundaryRefused, match="effects_denied"):
        approve(h)
    prepared = inert_harness(tmp_path / "prepared", authorize_attempt=False)
    try:
        with pytest.raises(FinalBoundaryRefused, match="attempt_not_authorized"):
            approve(prepared)
    finally:
        prepared.store.close()


def test_a_repeated_grant_for_the_same_tuple_is_idempotent(h: Harness) -> None:
    """The same unconsumed tuple returns the same approval id and stays granted."""
    first, second = approve(h), approve(h)
    assert first == second and h.store.approval_state(ATTEMPT) == "granted"
    assert h.store._db.execute("SELECT count(*) FROM effect_approvals").fetchone() == (1,)


def test_the_approval_is_consumed_by_the_send_and_cannot_be_reused(h: Harness) -> None:
    """Single use: after the send it is consumed, cannot be re-granted, and replay does not need it."""
    approve(h)
    sim = Recorder()
    receipt = send(driver(h, simulation=sim))
    assert h.store.approval_state(ATTEMPT) == "consumed"
    with pytest.raises(FinalBoundaryRefused, match="send_already_started"):
        approve(h)
    assert send(driver(h, simulation=sim)) == receipt and sim.calls == 1


def test_the_approval_cannot_authorize_a_changed_payload_after_the_fact(h: Harness) -> None:
    """Post-approval substitution is refused before the approval is touched."""
    approve(h)
    sim = Recorder()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        send(driver(h, simulation=sim), envelope(operation_digest="sha256:" + "5" * 64))
    assert excinfo.value.reason == "operation_digest_mismatch"
    assert h.store.approval_state(ATTEMPT) == "granted" and sim.calls == 0


def test_consumption_and_the_send_marker_commit_together(h: Harness, monkeypatch) -> None:
    """If the send precondition fails the approval is rolled back unconsumed."""
    approve(h)

    def refuse(db, attempt_id, inert_only, now=None):
        """Refuse the send precondition (same signature as the store's ``_begin_send_in``)."""
        raise OutcomeRefused("send_precondition_failed")

    monkeypatch.setattr(h.store, "_begin_send_in", refuse)
    sim = Recorder()
    with pytest.raises(OutcomeRefused, match="send_precondition_failed"):
        send(driver(h, simulation=sim))
    assert h.store.approval_state(ATTEMPT) == "granted"
    assert h.store.outbox_row(ATTEMPT)["send_started"] == 0 and sim.calls == 0


def test_a_consumed_approval_always_has_a_send_marker(h: Harness) -> None:
    """After a send that ended unknown the approval is spent and the marker is set."""
    approve(h)
    with pytest.raises(Exception):
        send(driver(h, simulation=Recorder(error=TimeoutError("slow"))))
    assert h.store.approval_state(ATTEMPT) == "consumed"
    assert h.store.outbox_row(ATTEMPT)["send_started"] == 1


def test_approval_consume_checks_status_in_a_fixed_order(h: Harness) -> None:
    """The db-level consumption names why it refused: missing, mismatch, expired, consumed."""
    with h.store._immediate() as db:
        with pytest.raises(FinalBoundaryRefused, match="approval_missing"):
            effect_approvals.consume_approval(db, binding(), NOW)
    approve(h)
    with h.store._immediate() as db:
        with pytest.raises(FinalBoundaryRefused, match="approval_mismatch"):
            effect_approvals.consume_approval(db, binding(epoch=7), NOW)
        with pytest.raises(FinalBoundaryRefused, match="approval_expired"):
            effect_approvals.consume_approval(db, binding(), LIVE_UNTIL)
        with pytest.raises(FinalBoundaryRefused, match="approval_conflict"):
            effect_approvals.create_approval(db, "approval-x", binding(epoch=7), "ref", NOW)
        effect_approvals.consume_approval(db, binding(), NOW)
        with pytest.raises(FinalBoundaryRefused, match="approval_consumed"):
            effect_approvals.consume_approval(db, binding(), NOW)


def test_the_approval_table_is_append_only_except_the_first_consumption(h: Harness) -> None:
    """No deletes, no rewriting the bound tuple, and one consumption stamp."""
    approve(h)
    db = h.store._db
    for statement in (
        "DELETE FROM effect_approvals",
        "UPDATE effect_approvals SET principal = 'mallory'",
        "UPDATE effect_approvals SET epoch = 9",
        "UPDATE effect_approvals SET expires_at = '9999-01-01T00:00:00.000000Z'",
        "UPDATE effect_approvals SET operation_digest = 'x'",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="append-only|first consumption"):
            db.execute(statement)
    db.execute("UPDATE effect_approvals SET consumed_at = 'stamp'")
    with pytest.raises(sqlite3.DatabaseError, match="first consumption"):
        db.execute("UPDATE effect_approvals SET consumed_at = 'again'")


def test_the_approval_survives_a_restart(tmp_path: Path) -> None:
    """A granted approval is durable; the send after a reopen consumes it."""
    h = inert_harness(tmp_path)
    approve(h)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        h2 = Harness(reopened, h.path, h.verifier, h.gates, h.revocations)
        assert reopened.approval_state(ATTEMPT) == "granted"
        assert send(driver(h2)).outcome == "confirmed"
        assert reopened.approval_state(ATTEMPT) == "consumed"
    finally:
        reopened.close()


# --------------------------------------------------- manual reconciliation


def open_ticket(h: Harness, ttl: timedelta = timedelta(minutes=5), now=NOW, operator=None) -> str:
    """Open a reconciliation ticket for the in-doubt attempt."""
    return h.store.open_reconciliation(ATTEMPT, operator=operator or Operator(), ttl=ttl, now=now)


def test_a_ticket_only_exists_for_an_attempt_in_doubt(h: Harness) -> None:
    """Unsent, settled and unknown attempts cannot be reconciled."""
    with pytest.raises(ReconciliationRefused, match="send_not_started"):
        open_ticket(h)
    with pytest.raises(ReconciliationRefused, match="attempt_not_in_outbox"):
        h.store.open_reconciliation("no-such", operator=Operator(), ttl=timedelta(minutes=1), now=NOW)
    in_doubt(h)
    h.store.record_outcome(ATTEMPT, "confirmed", "evidence")
    with pytest.raises(ReconciliationRefused, match="outcome_terminal"):
        open_ticket(h)


def test_opening_and_spending_both_need_an_authenticated_operator(h: Harness) -> None:
    """A refused operator reference stops each step and leaves the outcome unknown."""
    in_doubt(h)
    with pytest.raises(OperatorRefused):
        open_ticket(h, operator=Operator(None))
    ticket = open_ticket(h)
    with pytest.raises(OperatorRefused):
        h.store.reconcile_unknown(ticket, ATTEMPT, "failed", "ev", operator=Operator(" "), now=NOW)
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"


def test_the_operator_is_asked_with_the_operation_and_the_attempt(h: Harness) -> None:
    """Authentication is scoped to the attempt at both steps."""
    in_doubt(h)
    opener, spender = Operator(), Operator(OTHER_OPERATOR)
    ticket = open_ticket(h, operator=opener)
    h.store.reconcile_unknown(ticket, ATTEMPT, "failed", "ev", operator=spender, now=NOW)
    assert opener.calls == [("open_reconciliation", ATTEMPT)]
    assert spender.calls == [("reconcile_unknown", ATTEMPT)]


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), MAX_TICKET_TTL + timedelta(seconds=1),
                                 900, None], ids=["zero", "negative", "too-long", "int", "none"])
def test_ticket_lifetime_is_bounded(h: Harness, ttl) -> None:
    """Zero, negative, over fifteen minutes and non-timedelta lifetimes are refused."""
    in_doubt(h)
    with pytest.raises(ReconciliationRefused, match="ticket_ttl_invalid"):
        open_ticket(h, ttl=ttl)


def test_a_ticket_expires(h: Harness) -> None:
    """At the expiry instant the ticket is dead; one microsecond earlier it still works."""
    in_doubt(h)
    ticket = open_ticket(h, ttl=timedelta(minutes=5))
    with pytest.raises(ReconciliationRefused, match="ticket_expired"):
        h.store.reconcile_unknown(ticket, ATTEMPT, "failed", "ev", operator=Operator(),
                                  now=NOW + timedelta(minutes=5))
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"
    h.store.reconcile_unknown(ticket, ATTEMPT, "failed", "ev", operator=Operator(),
                              now=NOW + timedelta(minutes=5) - timedelta(microseconds=1))


def test_a_ticket_is_scoped_to_its_attempt(h: Harness) -> None:
    """A ticket for one attempt cannot settle another, and an unknown ticket refuses."""
    in_doubt(h)
    ticket = open_ticket(h)
    with pytest.raises(ReconciliationRefused, match="ticket_scope_mismatch"):
        h.store.reconcile_unknown(ticket, "attempt-other", "failed", "ev", operator=Operator(), now=NOW)
    with pytest.raises(ReconciliationRefused, match="ticket_unknown"):
        h.store.reconcile_unknown("ticket-nope", ATTEMPT, "failed", "ev", operator=Operator(), now=NOW)
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"


def test_a_ticket_is_single_use_and_the_settlement_is_recorded(h: Harness) -> None:
    """One spend settles with operator and evidence references; a second spend is refused."""
    in_doubt(h)
    ticket = open_ticket(h)
    h.store.reconcile_unknown(ticket, ATTEMPT, "confirmed", "ticket-4711", operator=Operator(OTHER_OPERATOR), now=NOW)
    row = h.store.outbox_row(ATTEMPT)
    assert (row["outcome"], row["outcome_evidence"]) == ("confirmed", "manual-reconciliation:ticket-4711")
    stored = h.store._db.execute(
        "SELECT consumed_by, outcome, evidence_ref FROM reconciliation_tickets WHERE ticket_id = ?", (ticket,)
    ).fetchone()
    assert stored == (OTHER_OPERATOR, "confirmed", "ticket-4711")
    with pytest.raises(ReconciliationRefused, match="ticket_consumed"):
        h.store.reconcile_unknown(ticket, ATTEMPT, "failed", "again", operator=Operator(), now=NOW)
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "confirmed"


@pytest.mark.parametrize(("outcome", "evidence", "reason"), [
    ("unknown", "ev", "outcome_not_final"), ("refused", "ev", "outcome_not_final"),
    ("confirmed", "", "evidence_required"), ("failed", "   ", "evidence_required"),
    ("confirmed", None, "evidence_required"),
])
def test_only_final_evidenced_outcomes_can_be_applied_by_hand(h: Harness, outcome, evidence, reason) -> None:
    """A manual settlement cannot restate unknown, invent a state or omit evidence."""
    in_doubt(h)
    ticket = open_ticket(h)
    with pytest.raises(ReconciliationRefused, match=reason):
        h.store.reconcile_unknown(ticket, ATTEMPT, outcome, evidence, operator=Operator(), now=NOW)
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"
    h.store.reconcile_unknown(ticket, ATTEMPT, "failed", "ev", operator=Operator(), now=NOW)


def test_a_settled_outcome_is_never_rewritten_by_a_second_ticket(h: Harness) -> None:
    """Terminal stays terminal: no new ticket can be opened and the stored outcome is unchanged."""
    in_doubt(h)
    h.store.reconcile_unknown(open_ticket(h), ATTEMPT, "failed", "ev", operator=Operator(), now=NOW)
    with pytest.raises(ReconciliationRefused, match="outcome_terminal"):
        open_ticket(h)
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "failed"


def test_the_ticket_log_is_append_only_and_survives_restart(tmp_path: Path) -> None:
    """Rows cannot be deleted or rewritten; an open ticket works after a reopen and then expires."""
    h = inert_harness(tmp_path)
    in_doubt(h)
    ticket = open_ticket(h)
    db = h.store._db
    for statement in (
        "DELETE FROM reconciliation_tickets",
        "UPDATE reconciliation_tickets SET attempt_id = 'x'",
        "UPDATE reconciliation_tickets SET expires_at = '9999-01-01T00:00:00.000000Z'",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="append-only|first consumption"):
            db.execute(statement)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        reopened.reconcile_unknown(ticket, ATTEMPT, "failed", "ev", operator=Operator(), now=NOW)
        with pytest.raises(sqlite3.DatabaseError, match="first consumption"):
            reopened._db.execute("UPDATE reconciliation_tickets SET consumed_at = 'x'")
    finally:
        reopened.close()


# --------------------------------------------------------------- startup report


def test_the_startup_report_lists_unknown_rows_and_changes_nothing(h: Harness) -> None:
    """In-doubt attempts are listed by opaque reference; the report is read-only."""
    before = quiet_snapshot(h.path)
    report = startup_reconciliation_report(h.store)
    assert report.in_doubt == () and report.unsent == 1
    in_doubt(h)
    before = quiet_snapshot(h.path)
    report = startup_reconciliation_report(h.store)
    assert report.in_doubt == (attempt_ref_for(ATTEMPT),) and report.unsent == 0
    assert report.as_public() == {"in_doubt": [attempt_ref_for(ATTEMPT)], "unsent": 0}
    assert quiet_snapshot(h.path) == before
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"


def test_settled_attempts_are_not_in_doubt(h: Harness) -> None:
    """A confirmed attempt is not listed."""
    approve(h)
    send(driver(h))
    report = startup_reconciliation_report(h.store)
    assert report.in_doubt == () and report.unsent == 0


def test_a_restart_reports_but_never_auto_settles(tmp_path: Path) -> None:
    """After a crash-equivalent reopen the unknown row is listed and still unknown, never retried."""
    h = inert_harness(tmp_path)
    approve(h)
    with pytest.raises(Exception):
        send(driver(h, simulation=Recorder(error=TimeoutError("slow"))))
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        report = startup_reconciliation_report(reopened)
        assert report.in_doubt == (attempt_ref_for(ATTEMPT),)
        sim = Recorder()
        h2 = Harness(reopened, h.path, h.verifier, h.gates, h.revocations)
        with pytest.raises(FinalBoundaryRefused, match="send_already_started"):
            send(driver(h2, simulation=sim))
        assert sim.calls == 0 and reopened.outbox_row(ATTEMPT)["outcome"] == "unknown"
    finally:
        reopened.close()


async def test_app_startup_exposes_only_counts_and_does_not_settle(h: Harness) -> None:
    """create_app lists in-doubt rows at startup; /health shows counts and nothing is changed."""
    in_doubt(h)
    before = quiet_snapshot(h.path)
    app = create_app(attempt_store=h.store)
    assert app.state.reconciliation_report.in_doubt == (attempt_ref_for(ATTEMPT),)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = (await client.get("/health")).json()
    assert body["reconciliation"] == {"in_doubt": 1, "unsent": 0}
    assert ATTEMPT not in str(body)
    assert quiet_snapshot(h.path) == before


async def test_app_without_a_store_has_no_reconciliation_section() -> None:
    """The default app reports no reconciliation state."""
    app = create_app()
    assert app.state.reconciliation_report is None
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert "reconciliation" not in (await client.get("/health")).json()


def test_a_failing_store_does_not_break_startup() -> None:
    """If the report cannot be read the app still starts and reports nothing."""
    class Broken:
        """Store whose reads fail."""

        def unknown_outbox_attempts(self):
            """Raise as a damaged store would."""
            raise sqlite3.DatabaseError("damaged")

        def unsent_outbox_count(self):
            """Raise as a damaged store would."""
            raise sqlite3.DatabaseError("damaged")

    assert create_app(attempt_store=Broken()).state.reconciliation_report is None


def test_driver_refuses_without_ports_even_with_an_approval(h: Harness) -> None:
    """An approval alone is not authority: effects deny and a missing verifier still refuse first."""
    approve(h)
    d = SealedInertDriver(h.store, effects_allowed=None, approval_verifier=None, revocations=None,
                          issuer_id=ISSUER, clock=lambda: NOW)
    with pytest.raises(FinalBoundaryRefused, match="effects_denied"):
        send(d)
    assert h.store.approval_state(ATTEMPT) == "granted"
    assert Approvals().seen == []
