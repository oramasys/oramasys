"""E1 C2 slice 2 (consumer): request validators, durable clock mark, abandon record, send gate."""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from orama.graph.circuit_breaker import CircuitBreaker
from orama.graph.dispatch_attempts import (
    AttemptAlreadyCommitted,
    AttemptStateError,
    AuthorizationRefused,
    ClockQuarantined,
    IssuerOutcomeRefused,
    OperatorRefused,
    SqliteAttemptStore,
)
from orama.graph.dispatch_consumer_wire import (
    WireError,
    validate_finalization_request_wire,
    validate_permit_request_wire,
)
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.effect_proposals import EffectScope, ReservationRefused
from orama.graph.finalization_window import Deadline
from orama.graph.issuer_availability import (
    ISSUER_UNAVAILABLE_STATUS,
    decide_issuer_call,
    next_retry_delay,
)
from tests.test_dispatch_attempts import (
    ATTEMPT,
    EXPECTED,
    GRANT,
    ISSUER,
    NOW,
    RESERVATION,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    Harness,
    db_path,
    ready,
    snapshot,
    vector_flow,
)

SCOPE = EffectScope("p-1", "g-1", "a" * 64, "b" * 64, "c" * 64, "dest-1")  # permit request/artifact digests
PERMIT_ID = "permit-vector-0001"


class Clock:
    def __init__(self, now: float = 0.0) -> None:
        """Start the fake clock at ``now`` seconds."""
        self.now = now

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.now


class FakeIssuerAuthenticator:
    """Test-only authenticated issuer boundary; production has no permissive default."""

    def verify(self, outcome: str, record: Mapping[str, str]) -> bool:
        """Accept fixture responses standing in for authenticated issuer transport."""
        return True


def harness(tmp_path: Path, *, governed: bool = True) -> Harness:
    """Open a store with the vector attempt, plus its proposal and reservation when governed."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(
        path, governed=governed, abandon_authenticator=FakeIssuerAuthenticator()
    )
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    if governed:
        store.propose("proposal-1", SCOPE, NOW)
        store.reserve(RESERVATION, "proposal-1", SCOPE, NOW + timedelta(hours=1), NOW)
    return Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())


def authorize(h: Harness, now=NOW, scope: EffectScope | None = SCOPE) -> None:
    """Run step 4.3 for the vector flow with an explicit scope."""
    flow = vector_flow()
    h.store.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, now, verifier=h.verifier, gates=h.gates,
        revocations=h.revocations, issuer_id=ISSUER, expected=EXPECTED, scope=scope,
    )


# ------------------------------------------------------------------ request validators


def permit_request() -> dict:
    """Return a valid 12-field permit request."""
    return {
        "grant_id": "grant-1", "grant_payload_digest": "a" * 64, "operation_id": "op-1",
        "request_digest": "b" * 64, "artifact_digest": "c" * 64, "reservation_id": "res-1",
        "ledger_store_id": "ledger-1", "configuration_policy_epoch": 3, "authority_epoch": 5,
        "consumer_acked_through": 0, "attempt_id": "attempt-1",
        "requested_at": "2026-10-19T04:00:00.000000Z",
    }


def finalization_request() -> dict:
    """Return a valid 8-field finalization request."""
    return {
        "permit_id": "permit-1", "permit_digest": "d" * 64, "attempt_id": "attempt-1",
        "reservation_id": "res-1", "ledger_store_id": "ledger-1", "consumer_acked_through": 0,
        "authority_epoch": 5, "requested_at": "2026-10-19T04:00:00.000000Z",
    }


def test_valid_requests_have_exactly_twelve_and_eight_fields() -> None:
    """Valid requests have exactly twelve and eight fields."""
    assert len(validate_permit_request_wire(permit_request())) == 12
    assert len(validate_finalization_request_wire(finalization_request())) == 8


@pytest.mark.parametrize("field", sorted(permit_request()))
def test_a_permit_request_missing_any_field_or_with_an_extra_is_refused(field: str) -> None:
    """A permit request missing any field or with an extra is refused."""
    missing = {k: v for k, v in permit_request().items() if k != field}
    with pytest.raises(WireError):
        validate_permit_request_wire(missing)
    with pytest.raises(WireError):
        validate_permit_request_wire({**permit_request(), "extra": "x"})


@pytest.mark.parametrize("field", sorted(finalization_request()))
def test_a_finalization_request_missing_any_field_is_refused(field: str) -> None:
    """A finalization request missing any field is refused."""
    with pytest.raises(WireError):
        validate_finalization_request_wire({k: v for k, v in finalization_request().items() if k != field})


@pytest.mark.parametrize(
    "changes",
    [
        {"request_digest": "B" * 64}, {"grant_payload_digest": "a" * 63}, {"authority_epoch": 0},
        {"configuration_policy_epoch": True}, {"consumer_acked_through": -1},
        {"requested_at": "2026-10-19 04:00:00"}, {"grant_id": " "}, {"attempt_id": 7},
        {"ledger_store_id": "x" * 2000},
    ],
)
def test_a_malformed_permit_request_value_is_refused(changes: dict) -> None:
    """A malformed permit request value is refused."""
    with pytest.raises(WireError):
        validate_permit_request_wire({**permit_request(), **changes})


def test_a_permit_wire_is_not_a_permit_request() -> None:
    """A permit wire is not a permit request."""
    with pytest.raises(WireError):
        validate_permit_request_wire(vector_flow().permit)
    with pytest.raises(WireError):
        validate_finalization_request_wire(vector_flow().fin)


# --------------------------------------------------------------- durable UTC high-water


def test_the_clock_mark_advances_and_tolerates_equal_time(tmp_path: Path) -> None:
    """The clock mark advances and tolerates equal time."""
    store = SqliteAttemptStore(db_path(tmp_path))
    store.observe_clock(NOW)
    store.observe_clock(NOW)
    store.observe_clock(NOW + timedelta(seconds=5))


def test_quarantine_committed_between_observation_and_authorization_blocks_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second connection's quarantine wins before any authorization writes commit."""
    h = harness(tmp_path)
    ready(h, vector_flow())
    peer = SqliteAttemptStore(h.path, governed=True)
    observe = h.store.observe_clock

    def quarantine_after_observation(now: datetime) -> None:
        """Force the interleaving between the two independent transactions."""
        observe(now)
        with pytest.raises(ClockQuarantined):
            peer.observe_clock(now - timedelta(seconds=1))

    before = snapshot(h.path)
    monkeypatch.setattr(h.store, "observe_clock", quarantine_after_observation)
    try:
        with pytest.raises(ClockQuarantined, match="clock_quarantined"):
            authorize(h)
        after = snapshot(h.path)
        for table in before.keys() - {"clock_high_water"}:
            assert after[table] == before[table]
        assert peer._db.execute("SELECT quarantined FROM clock_high_water").fetchone()[0] == 1
    finally:
        peer.close()
        h.store.close()


def test_clock_advance_between_observation_and_authorization_is_durably_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A newer peer mark cannot be bypassed by a previously captured authorization time."""
    h = harness(tmp_path)
    ready(h, vector_flow())
    peer = SqliteAttemptStore(h.path, governed=True)
    observe = h.store.observe_clock

    def advance_after_observation(now: datetime) -> None:
        """Advance through another SQLite connection after the preflight observation."""
        observe(now)
        peer.observe_clock(now + timedelta(seconds=10))

    before = snapshot(h.path)
    monkeypatch.setattr(h.store, "observe_clock", advance_after_observation)
    try:
        with pytest.raises(ClockQuarantined, match="clock_regressed"):
            authorize(h)
        after = snapshot(h.path)
        for table in before.keys() - {"clock_high_water"}:
            assert after[table] == before[table]
        assert peer._db.execute("SELECT quarantined FROM clock_high_water").fetchone()[0] == 1
    finally:
        peer.close()
        h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        with pytest.raises(ClockQuarantined, match="clock_quarantined"):
            reopened.observe_clock(NOW + timedelta(hours=1))
    finally:
        reopened.close()


def test_a_backward_step_quarantines_and_survives_a_restart(tmp_path: Path) -> None:
    """A backward step quarantines and survives a restart."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path)
    store.observe_clock(NOW)
    with pytest.raises(ClockQuarantined) as regressed:
        store.observe_clock(NOW - timedelta(microseconds=1))
    assert regressed.value.reason == "clock_regressed"
    store.close()
    reopened = SqliteAttemptStore(path)
    with pytest.raises(ClockQuarantined) as still:
        reopened.observe_clock(NOW + timedelta(hours=1))
    assert still.value.reason == "clock_quarantined"


class Operator:
    """Operator authority port: returns a fixed reference, or None to deny."""

    def __init__(self, reference: str | None = "operator-ref-1") -> None:
        """Choose the reference returned, or None to deny every call."""
        self.reference = reference
        self.calls: list[tuple[str, str]] = []

    def authorize(self, operation: str, *, subject: str) -> str | None:
        """Record the call and return the configured reference."""
        self.calls.append((operation, subject))
        return self.reference


def quarantined(tmp_path: Path, mark: timedelta = timedelta(hours=2)) -> Harness:
    """A governed store with a live reservation whose clock mark stepped backward."""
    h = harness(tmp_path)
    h.store.observe_clock(NOW + mark)
    with pytest.raises(ClockQuarantined):
        h.store.observe_clock(NOW)
    return h


def clear(h: Harness, *, operator: Operator | None = None, evidence: str = "ntp-attested-1",
          accepted: object = NOW) -> None:
    """Clear the quarantine through the operator port with evidence and an accepted time."""
    h.store.clear_clock_quarantine(
        operator=operator or Operator(), trusted_time_evidence=evidence, accepted_at=accepted,  # type: ignore[arg-type]
        now=NOW,
    )


def reconciliations(h: Harness) -> list[tuple]:
    """Return every logged reconciliation as a tuple of its recorded fields."""
    conn = sqlite3.connect(h.path)
    try:
        return conn.execute(
            "SELECT reconciled_by, trusted_time_evidence, previous_utc, accepted_utc, expired_reservations"
            " FROM clock_reconciliations ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


@pytest.mark.parametrize("reference", [None, "", "   "])
def test_an_unauthenticated_operator_cannot_clear_the_quarantine(tmp_path: Path, reference) -> None:
    """An unauthenticated operator cannot clear the quarantine."""
    h = quarantined(tmp_path)
    with pytest.raises(OperatorRefused):
        clear(h, operator=Operator(reference))
    assert reconciliations(h) == []
    with pytest.raises(ClockQuarantined) as still:
        h.store.observe_clock(NOW + timedelta(hours=3))
    assert still.value.reason == "clock_quarantined"


@pytest.mark.parametrize("evidence", ["", "  ", None])
def test_trusted_time_evidence_is_required(tmp_path: Path, evidence) -> None:
    """Trusted time evidence is required."""
    h = quarantined(tmp_path)
    with pytest.raises(ValueError):
        clear(h, evidence=evidence)
    assert reconciliations(h) == []


def test_there_must_be_a_quarantine_to_clear(tmp_path: Path) -> None:
    """There must be a quarantine to clear."""
    h = harness(tmp_path)
    h.store.observe_clock(NOW)
    with pytest.raises(AttemptStateError, match="no clock quarantine"):
        clear(h)
    assert reconciliations(h) == []


def test_the_reconciliation_records_both_timestamps_the_evidence_and_the_operator(tmp_path: Path) -> None:
    """The reconciliation records both timestamps the evidence and the operator."""
    h = quarantined(tmp_path)
    operator = Operator("operator-ref-9")
    clear(h, operator=operator, evidence="roughtime-receipt-77", accepted=NOW + timedelta(minutes=30))
    ((who, evidence, previous, accepted, expired),) = reconciliations(h)
    assert (who, evidence, expired) == ("operator-ref-9", "roughtime-receipt-77", 1)
    assert datetime.fromisoformat(previous) == NOW + timedelta(hours=2)
    assert datetime.fromisoformat(accepted) == NOW + timedelta(minutes=30)
    assert operator.calls == [("clear_clock_quarantine", "clock")]
    h.store.observe_clock(NOW + timedelta(minutes=31))  # dispatch may resume from the accepted time


def test_the_accepted_time_may_be_earlier_than_the_poisoned_mark(tmp_path: Path) -> None:
    """The accepted time may be earlier than the poisoned mark."""
    h = quarantined(tmp_path)
    clear(h, accepted=NOW - timedelta(minutes=5))
    with pytest.raises(ClockQuarantined):
        h.store.observe_clock(NOW - timedelta(minutes=6))


def test_reconciliation_never_revives_a_reservation_that_expired_at_the_old_mark(tmp_path: Path) -> None:
    """Reconciliation never revives a reservation that expired at the old mark."""
    h = quarantined(tmp_path)  # the mark reached NOW+2h; the reservation expired at NOW+1h
    clear(h, accepted=NOW)  # trusted time says it is only NOW, so it would look live again
    ready(h, vector_flow())
    with pytest.raises(ReservationRefused) as refusal:
        authorize(h, now=NOW)
    assert refusal.value.reason == "reservation_expired"


def test_a_reservation_still_live_at_the_old_mark_survives_and_a_used_one_stays_used(tmp_path: Path) -> None:
    """A reservation still live at the old mark survives and a used one stays used."""
    h = quarantined(tmp_path, mark=timedelta(minutes=10))  # reservation expires at NOW+1h
    clear(h, accepted=NOW)
    ((_, _, _, _, expired),) = reconciliations(h)
    assert expired == 0
    ready(h, vector_flow())
    authorize(h, now=NOW + timedelta(seconds=1))
    row = sqlite3.connect(h.path).execute("SELECT consumed_attempt_id FROM reservations").fetchone()
    assert row == (ATTEMPT,)


def test_the_reconciliation_log_is_append_only_across_incidents(tmp_path: Path) -> None:
    """The reconciliation log is append only across incidents."""
    h = quarantined(tmp_path)
    clear(h, evidence="first")
    h.store.observe_clock(NOW + timedelta(hours=1))
    with pytest.raises(ClockQuarantined):
        h.store.observe_clock(NOW)
    clear(h, evidence="second")
    assert [row[1] for row in reconciliations(h)] == ["first", "second"]


def test_a_governed_store_refuses_dispatch_while_the_clock_is_quarantined(tmp_path: Path) -> None:
    """A governed store refuses dispatch while the clock is quarantined."""
    h = harness(tmp_path)
    ready(h, vector_flow())
    h.store.observe_clock(NOW + timedelta(seconds=10))
    before = snapshot(h.path)
    with pytest.raises(ClockQuarantined):
        authorize(h, now=NOW)
    after = snapshot(h.path)
    for name in ("grant_use", "dispatch_intents", "outbox"):
        assert after[name] == before[name] == []


def test_a_governed_authorization_advances_the_mark_and_an_ungoverned_one_does_not(tmp_path: Path) -> None:
    """A governed authorization advances the mark and an ungoverned one does not."""
    (tmp_path / "g").mkdir()
    (tmp_path / "u").mkdir()
    g = harness(tmp_path / "g")
    ready(g, vector_flow())
    authorize(g)
    assert len(snapshot(g.path)["clock_high_water"]) == 1
    u = harness(tmp_path / "u", governed=False)
    ready(u, vector_flow())
    flow = vector_flow()
    u.store.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, NOW, verifier=u.verifier, gates=u.gates,
        revocations=u.revocations, issuer_id=ISSUER, expected=EXPECTED,
    )
    assert snapshot(u.path)["clock_high_water"] == []


# ------------------------------------------------------------------ consumer abandon


def fenced(tmp_path: Path) -> Harness:
    """A governed store whose attempt already carries its terminal fence."""
    h = harness(tmp_path)
    h.store.fence(ATTEMPT)
    return h


def issuer_record(h: Harness, attestation: dict, **changes: str) -> dict:
    """Build the issuer's abandon record for the attestation the store sent."""
    row = h.store._db.execute(
        "SELECT attestation_digest FROM abandon_attestations WHERE attempt_id = ?", (ATTEMPT,)
    ).fetchone()
    return {
        "permit_id": attestation["permit_id"], "attempt_id": ATTEMPT,
        "attestation_digest": row[0], "disposition_ref": "op-1",
        "recorded_at": "2026-10-19T04:00:01.000000Z", **changes,
    }


def test_an_attestation_needs_the_fence_first(tmp_path: Path) -> None:
    """An attestation needs the fence first."""
    h = harness(tmp_path)
    with pytest.raises(AttemptStateError, match="fence"):
        h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)


def test_a_committed_attempt_cannot_be_attested_and_cannot_be_fenced_after_commit(tmp_path: Path) -> None:
    """A committed attempt cannot be attested and cannot be fenced after commit."""
    h = harness(tmp_path)
    ready(h, vector_flow())
    authorize(h)
    with pytest.raises(AttemptAlreadyCommitted):
        h.store.fence(ATTEMPT)
    h.store._db.execute("UPDATE dispatch_attempts SET fenced = 1 WHERE attempt_id = ?", (ATTEMPT,))
    with pytest.raises(AttemptStateError, match="committed"):
        h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)


@pytest.mark.parametrize("cause, epoch", [("other", 1), ("loss", 0), ("loss", True), ("loss", "1")])
def test_a_bad_cause_or_epoch_is_refused(tmp_path: Path, cause: str, epoch: object) -> None:
    """A bad cause or epoch is refused."""
    h = fenced(tmp_path)
    with pytest.raises(AttemptStateError):
        h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, cause, epoch, NOW)  # type: ignore[arg-type]


def test_the_attestation_has_the_eight_issuer_fields_and_is_kept_idempotently(tmp_path: Path) -> None:
    """The attestation has the eight issuer fields and is kept idempotently."""
    h = fenced(tmp_path)
    first = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "cancellation", 2, NOW)
    assert set(first) == {
        "attempt_id", "permit_id", "cause", "consumer_fencing_epoch", "fence_evidence",
        "non_commit_evidence", "release_pending_record", "no_intent_exists",
    }
    assert first["no_intent_exists"] is True
    assert h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "cancellation", 2, NOW) == first
    with pytest.raises(AttemptStateError, match="different attestation"):
        h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 2, NOW)


def test_an_attestation_retry_keeps_its_original_fence_evidence_after_state_changes(tmp_path: Path) -> None:
    """An identical retry returns the durable first attestation, not one rebuilt from mutable state."""
    h = fenced(tmp_path)
    first = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    h.store.record_unavailable(ATTEMPT)
    assert h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW) == first


def test_the_authenticated_outcome_ends_the_attempt_and_authorizes_release(tmp_path: Path) -> None:
    """The authenticated outcome ends the attempt and authorizes release."""
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    record = issuer_record(h, attestation)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", record, NOW)
    outcome = h.store.abandon_outcome(ATTEMPT)
    assert outcome is not None
    assert (outcome["outcome"], outcome["release_authorized"], outcome["disposition_ref"]) == (
        "abandon.recorded", 1, "op-1",
    )
    record_state = h.store.get_attempt(ATTEMPT)
    assert record_state is not None and record_state.state == "abandoned"
    ready(h, vector_flow())
    with pytest.raises(AuthorizationRefused) as refusal:
        authorize(h)
    assert (refusal.value.rule, refusal.value.reason) == ("rule6", "attempt_not_live")


def test_an_identical_outcome_retry_is_idempotent_and_a_different_one_conflicts(tmp_path: Path) -> None:
    """An identical outcome retry is idempotent and a different one conflicts."""
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    record = issuer_record(h, attestation)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", record, NOW)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", record, NOW)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.already_abandoned", record, NOW)
    with pytest.raises(AttemptStateError, match="different abandon outcome"):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", {**record, "disposition_ref": "op-2"}, NOW)
    count = sqlite3.connect(h.path).execute("SELECT COUNT(*) FROM abandon_outcomes").fetchone()[0]
    assert count == 1
    assert h.store.abandon_outcome(ATTEMPT)["outcome"] == "abandon.recorded"


def test_an_outcome_retry_cannot_change_the_issuer_timestamp(tmp_path: Path) -> None:
    """A retry label may change, but the issuer's durable disposition may not."""
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    record = issuer_record(h, attestation)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", record, NOW)
    original = h.store.abandon_outcome(ATTEMPT)
    with pytest.raises(AttemptStateError, match="different abandon outcome"):
        h.store.record_abandon_outcome(
            ATTEMPT, "abandon.already_abandoned",
            {**record, "recorded_at": "2026-10-19T04:00:02.000000Z"}, NOW,
        )
    assert h.store.abandon_outcome(ATTEMPT) == original


def test_authentication_is_bound_to_the_exact_response_and_runs_again_on_retry(tmp_path: Path) -> None:
    """A verified response cannot authorize altered fields or bypass retry authentication."""
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    record = issuer_record(h, attestation)

    class BoundIssuer:
        """Model an adapter holding an independently authenticated issuer response."""

        calls = 0

        def verify(self, outcome: str, received: Mapping[str, str]) -> bool:
            """Bind the accepted status and complete immutable response to trusted evidence."""
            self.calls += 1
            return outcome == "abandon.recorded" and received == record

    adapter = BoundIssuer()
    h.store._abandon_authenticator = adapter
    with pytest.raises(IssuerOutcomeRefused):
        h.store.record_abandon_outcome(
            ATTEMPT, "abandon.recorded", {**record, "disposition_ref": "forged"}, NOW,
        )
    assert h.store.abandon_outcome(ATTEMPT) is None
    h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", record, NOW)
    with pytest.raises(IssuerOutcomeRefused):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.already_abandoned", record, NOW)
    assert adapter.calls == 3


@pytest.mark.parametrize("configured", [False, True])
def test_missing_or_rejecting_issuer_authentication_preserves_the_attempt(
    tmp_path: Path, configured: bool,
) -> None:
    """Copied attestation fields cannot create release authority without issuer authentication."""
    class RejectIssuer:
        """Reject every response as unauthenticated."""

        def verify(self, outcome: str, record: Mapping[str, str]) -> bool:
            """Refuse the unverified response."""
            return False

    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    record = issuer_record(h, attestation)
    h.store.close()
    store = SqliteAttemptStore(
        h.path, governed=True, abandon_authenticator=RejectIssuer() if configured else None,
    )
    with pytest.raises(IssuerOutcomeRefused):
        store.record_abandon_outcome(
            ATTEMPT, "abandon.recorded", record, NOW,
        )
    assert store.abandon_outcome(ATTEMPT) is None
    assert store.get_attempt(ATTEMPT).state != "abandoned"
    store.close()


@pytest.mark.parametrize(
    "changes",
    [{"attestation_digest": "0" * 64}, {"permit_id": "permit-other"}, {"attempt_id": "attempt-other"},
     {"disposition_ref": " "}, {"recorded_at": ""}],
)
def test_an_outcome_that_does_not_match_the_attestation_sent_is_refused(tmp_path: Path, changes: dict) -> None:
    """An outcome that does not match the attestation sent is refused."""
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    with pytest.raises((AttemptStateError, ValueError)):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", issuer_record(h, attestation, **changes), NOW)
    assert h.store.abandon_outcome(ATTEMPT) is None
    state = h.store.get_attempt(ATTEMPT)
    assert state is not None and state.state != "abandoned"


def test_an_outcome_needs_a_built_attestation_and_a_known_outcome_name(tmp_path: Path) -> None:
    """An outcome needs a built attestation and a known outcome name."""
    h = fenced(tmp_path)
    with pytest.raises(AttemptStateError, match="invalid fields"):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", {}, NOW)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    with pytest.raises(AttemptStateError, match="unknown abandon outcome"):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.maybe", issuer_record(h, attestation), NOW)


# ------------------------------------------------------------- sender precondition


def authorized(tmp_path: Path) -> Harness:
    """A governed store that has already committed step 4.3 for the vector attempt."""
    h = harness(tmp_path)
    ready(h, vector_flow())
    authorize(h)
    return h


def test_begin_send_succeeds_once_for_a_complete_authorized_attempt(tmp_path: Path) -> None:
    """Begin send succeeds once for a complete authorized attempt."""
    h = authorized(tmp_path)
    h.store.begin_send(ATTEMPT)
    with pytest.raises(OutcomeRefused) as second:
        h.store.begin_send(ATTEMPT)
    assert second.value.reason == "send_already_started"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE dispatch_attempts SET fenced = 1",
        "UPDATE dispatch_attempts SET state = 'abandoned'",
        "UPDATE outbox SET permit_id = ''",
        "UPDATE outbox SET authority_pair = ''",
    ],
)
def test_begin_send_refuses_a_fenced_abandoned_or_incomplete_attempt(tmp_path: Path, sql: str) -> None:
    """Begin send refuses a fenced abandoned or incomplete attempt."""
    h = authorized(tmp_path)
    h.store._db.execute(sql)
    with pytest.raises(OutcomeRefused) as refusal:
        h.store.begin_send(ATTEMPT)
    assert refusal.value.reason == "send_precondition_failed"
    row = h.store.outbox_row(ATTEMPT)
    assert row is not None and row["send_started"] == 0


# ----------------------------------------------------------- availability gate


def gate(remaining: float, *, failures: int = 0) -> tuple[CircuitBreaker, Deadline, Clock]:
    """Return a breaker, a deadline ``remaining`` seconds ahead and their shared clock."""
    clock = Clock(100.0)
    breaker = CircuitBreaker(clock)
    for _ in range(failures):
        breaker.record_failure()
    return breaker, Deadline(100.0 + remaining, clock), clock


def test_a_live_deadline_and_a_closed_breaker_allow_the_call() -> None:
    """A live deadline and a closed breaker allow the call."""
    breaker, deadline, _ = gate(60.0)
    assert decide_issuer_call(breaker, deadline, finalization=True).allowed is True


def test_an_expired_deadline_refuses_with_the_visible_status() -> None:
    """An expired deadline refuses with the visible status."""
    breaker, deadline, _ = gate(0.0)
    decision = decide_issuer_call(breaker, deadline, finalization=False)
    assert (decision.allowed, decision.status, decision.reason) == (
        False, ISSUER_UNAVAILABLE_STATUS, "deadline_expired",
    )
    assert ISSUER_UNAVAILABLE_STATUS == "dispatch.issuer_unavailable"


def test_a_short_window_blocks_finalization_but_not_admission() -> None:
    """A short window blocks finalization but not admission."""
    breaker, deadline, _ = gate(14.0)
    short = decide_issuer_call(breaker, deadline, finalization=True)
    assert (short.allowed, short.reason) == (False, "finalization_window_too_short")
    assert decide_issuer_call(breaker, deadline, finalization=False).allowed is True


def test_an_open_breaker_refuses_and_a_refusal_before_it_never_spends_the_probe() -> None:
    """An open breaker refuses and a refusal before it never spends the probe."""
    breaker, deadline, clock = gate(60.0, failures=5)
    assert breaker.state == "open"
    open_decision = decide_issuer_call(breaker, deadline, finalization=False)
    assert (open_decision.allowed, open_decision.reason) == (False, "circuit_open")
    clock.now += 15.0
    expired_first = Deadline(clock.now, clock)
    assert decide_issuer_call(breaker, expired_first, finalization=False).reason == "deadline_expired"
    assert breaker.state == "open"  # the probe was not consumed by an earlier refusal
    assert decide_issuer_call(breaker, deadline, finalization=False).allowed is True
    assert breaker.state == "half_open"


def test_retry_delays_are_bounded_exponential_and_never_overrun_the_budget() -> None:
    """Retry delays are bounded exponential and never overrun the budget."""
    assert [next_retry_delay(n, 100.0) for n in range(6)] == [0.5, 1.0, 2.0, 4.0, 4.0, 4.0]
    assert next_retry_delay(3, 3.9) is None
    assert next_retry_delay(3, 4.0) == 4.0
    assert next_retry_delay(0, 0.0) is None
    assert next_retry_delay(10_000, 100.0) == 4.0


@pytest.mark.parametrize(
    "kwargs",
    [{"failures": -1, "remaining": 1.0}, {"failures": True, "remaining": 1.0},
     {"failures": 0, "remaining": -1.0}, {"failures": 0, "remaining": float("nan")},
     {"failures": 0, "remaining": float("inf")}, {"failures": 0, "remaining": 1.0, "base": 0.0},
     {"failures": 0, "remaining": 1.0, "cap": -1.0}],
)
def test_bad_retry_arguments_raise(kwargs: dict) -> None:
    """Bad retry arguments raise."""
    with pytest.raises(ValueError):
        next_retry_delay(**kwargs)


# ------------------------------------------------- signed-policy clock skew (default zero)


def test_the_default_skew_is_zero_so_any_backward_step_quarantines(tmp_path: Path) -> None:
    """The default skew is zero so any backward step quarantines."""
    store = SqliteAttemptStore(db_path(tmp_path))
    store.observe_clock(NOW)
    with pytest.raises(ClockQuarantined):
        store.observe_clock(NOW - timedelta(microseconds=1))


def test_a_backward_step_within_the_skew_is_tolerated_and_never_lowers_the_mark(tmp_path: Path) -> None:
    """A backward step within the skew is tolerated and never lowers the mark."""
    skew = timedelta(seconds=2)
    store = SqliteAttemptStore(db_path(tmp_path), clock_skew_tolerance=skew)
    store.observe_clock(NOW)
    store.observe_clock(NOW - skew)  # exactly at the boundary: tolerated
    store.observe_clock(NOW - timedelta(seconds=1))
    # the mark stayed at NOW, so the boundary is still measured from NOW
    with pytest.raises(ClockQuarantined) as excinfo:
        store.observe_clock(NOW - skew - timedelta(microseconds=1))
    assert excinfo.value.reason == "clock_regressed"


def test_a_forward_step_still_advances_the_mark_under_a_skew(tmp_path: Path) -> None:
    """A forward step still advances the mark under a skew."""
    skew = timedelta(seconds=2)
    store = SqliteAttemptStore(db_path(tmp_path), clock_skew_tolerance=skew)
    store.observe_clock(NOW)
    store.observe_clock(NOW + timedelta(seconds=10))
    store.observe_clock(NOW + timedelta(seconds=8))  # within skew of the new mark
    with pytest.raises(ClockQuarantined):
        store.observe_clock(NOW + timedelta(seconds=7, microseconds=999_999))


@pytest.mark.parametrize("bad", [timedelta(seconds=-1), 2, 2.5, "2s", None, timedelta(days=1)])
def test_a_negative_or_non_timedelta_or_unbounded_skew_is_refused(tmp_path: Path, bad: object) -> None:
    """A negative or non timedelta or unbounded skew is refused."""
    with pytest.raises(ValueError, match="clock_skew_tolerance"):
        SqliteAttemptStore(db_path(tmp_path), clock_skew_tolerance=bad)  # type: ignore[arg-type]


def test_the_skew_does_not_relax_an_existing_quarantine(tmp_path: Path) -> None:
    """The skew does not relax an existing quarantine."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path)
    store.observe_clock(NOW)
    with pytest.raises(ClockQuarantined):
        store.observe_clock(NOW - timedelta(seconds=5))
    store.close()
    lenient = SqliteAttemptStore(path, clock_skew_tolerance=timedelta(minutes=4))
    with pytest.raises(ClockQuarantined) as excinfo:
        lenient.observe_clock(NOW)
    assert excinfo.value.reason == "clock_quarantined"


def test_a_reservation_expiring_exactly_at_the_old_mark_is_expired_by_reconciliation(tmp_path: Path) -> None:
    """A reservation expiring exactly at the old mark is expired by reconciliation."""
    h = harness(tmp_path)  # the reservation expires at NOW + 1 hour
    mark = timedelta(hours=1)
    h.store.observe_clock(NOW + mark)
    with pytest.raises(ClockQuarantined):
        h.store.observe_clock(NOW)
    clear(h, accepted=NOW)
    ((_, _, _, _, expired),) = reconciliations(h)
    assert expired == 1  # expiry is strict: at the mark itself it already counts as expired
