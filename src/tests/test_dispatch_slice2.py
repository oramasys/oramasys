"""E1 C2 slice 2 (consumer): request validators, durable clock mark, abandon record, send gate."""
from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from orama.graph.circuit_breaker import CircuitBreaker
from orama.graph.dispatch_attempts import (
    AttemptAlreadyCommitted,
    AttemptStateError,
    AuthorizationRefused,
    ClockQuarantined,
    SqliteAttemptStore,
)
from orama.graph.dispatch_consumer_wire import (
    WireError,
    validate_finalization_request_wire,
    validate_permit_request_wire,
)
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.effect_proposals import EffectScope
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
        self.now = now

    def __call__(self) -> float:
        return self.now


def harness(tmp_path: Path, *, governed: bool = True) -> Harness:
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path, governed=governed)
    store.create_attempt(ATTEMPT, GRANT, RESERVATION)
    if governed:
        store.propose("proposal-1", SCOPE, NOW)
        store.reserve(RESERVATION, "proposal-1", SCOPE, NOW + timedelta(hours=1), NOW)
    return Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())


def authorize(h: Harness, now=NOW, scope: EffectScope | None = SCOPE) -> None:
    flow = vector_flow()
    h.store.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, now, verifier=h.verifier, gates=h.gates,
        revocations=h.revocations, issuer_id=ISSUER, expected=EXPECTED, scope=scope,
    )


# ------------------------------------------------------------------ request validators


def permit_request() -> dict:
    return {
        "grant_id": "grant-1", "grant_payload_digest": "a" * 64, "operation_id": "op-1",
        "request_digest": "b" * 64, "artifact_digest": "c" * 64, "reservation_id": "res-1",
        "ledger_store_id": "ledger-1", "configuration_policy_epoch": 3, "authority_epoch": 5,
        "consumer_acked_through": 0, "attempt_id": "attempt-1",
        "requested_at": "2026-10-19T04:00:00.000000Z",
    }


def finalization_request() -> dict:
    return {
        "permit_id": "permit-1", "permit_digest": "d" * 64, "attempt_id": "attempt-1",
        "reservation_id": "res-1", "ledger_store_id": "ledger-1", "consumer_acked_through": 0,
        "authority_epoch": 5, "requested_at": "2026-10-19T04:00:00.000000Z",
    }


def test_valid_requests_have_exactly_twelve_and_eight_fields() -> None:
    assert len(validate_permit_request_wire(permit_request())) == 12
    assert len(validate_finalization_request_wire(finalization_request())) == 8


@pytest.mark.parametrize("field", sorted(permit_request()))
def test_a_permit_request_missing_any_field_or_with_an_extra_is_refused(field: str) -> None:
    missing = {k: v for k, v in permit_request().items() if k != field}
    with pytest.raises(WireError):
        validate_permit_request_wire(missing)
    with pytest.raises(WireError):
        validate_permit_request_wire({**permit_request(), "extra": "x"})


@pytest.mark.parametrize("field", sorted(finalization_request()))
def test_a_finalization_request_missing_any_field_is_refused(field: str) -> None:
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
    with pytest.raises(WireError):
        validate_permit_request_wire({**permit_request(), **changes})


def test_a_permit_wire_is_not_a_permit_request() -> None:
    with pytest.raises(WireError):
        validate_permit_request_wire(vector_flow().permit)
    with pytest.raises(WireError):
        validate_finalization_request_wire(vector_flow().fin)


# --------------------------------------------------------------- durable UTC high-water


def test_the_clock_mark_advances_and_tolerates_equal_time(tmp_path: Path) -> None:
    store = SqliteAttemptStore(db_path(tmp_path))
    store.observe_clock(NOW)
    store.observe_clock(NOW)
    store.observe_clock(NOW + timedelta(seconds=5))


def test_a_backward_step_quarantines_and_survives_a_restart(tmp_path: Path) -> None:
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


def test_the_quarantine_clears_only_with_a_named_reconciliation(tmp_path: Path) -> None:
    store = SqliteAttemptStore(db_path(tmp_path))
    store.observe_clock(NOW)
    with pytest.raises(ClockQuarantined):
        store.observe_clock(NOW - timedelta(seconds=1))
    for bad in ("", "  "):
        with pytest.raises(ValueError):
            store.clear_clock_quarantine(bad, NOW)
    store.clear_clock_quarantine("operator-ref-1", NOW - timedelta(seconds=1))
    store.observe_clock(NOW)


def test_a_governed_store_refuses_dispatch_while_the_clock_is_quarantined(tmp_path: Path) -> None:
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
    h = harness(tmp_path)
    h.store.fence(ATTEMPT)
    return h


def issuer_record(h: Harness, attestation: dict, **changes: str) -> dict:
    row = h.store._db.execute(
        "SELECT attestation_digest FROM abandon_attestations WHERE attempt_id = ?", (ATTEMPT,)
    ).fetchone()
    return {
        "permit_id": attestation["permit_id"], "attempt_id": ATTEMPT,
        "attestation_digest": row[0], "disposition_ref": "op-1",
        "recorded_at": "2026-10-19T04:00:01.000000Z", **changes,
    }


def test_an_attestation_needs_the_fence_first(tmp_path: Path) -> None:
    h = harness(tmp_path)
    with pytest.raises(AttemptStateError, match="fence"):
        h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)


def test_a_committed_attempt_cannot_be_attested_and_cannot_be_fenced_after_commit(tmp_path: Path) -> None:
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
    h = fenced(tmp_path)
    with pytest.raises(AttemptStateError):
        h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, cause, epoch, NOW)  # type: ignore[arg-type]


def test_the_attestation_has_the_eight_issuer_fields_and_is_kept_idempotently(tmp_path: Path) -> None:
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


def test_the_authenticated_outcome_ends_the_attempt_and_authorizes_release(tmp_path: Path) -> None:
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
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    record = issuer_record(h, attestation)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", record, NOW)
    h.store.record_abandon_outcome(ATTEMPT, "abandon.already_abandoned", record, NOW)
    with pytest.raises(AttemptStateError, match="different abandon outcome"):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", {**record, "disposition_ref": "op-2"}, NOW)
    count = sqlite3.connect(h.path).execute("SELECT COUNT(*) FROM abandon_outcomes").fetchone()[0]
    assert count == 1


@pytest.mark.parametrize(
    "changes",
    [{"attestation_digest": "0" * 64}, {"permit_id": "permit-other"}, {"attempt_id": "attempt-other"},
     {"disposition_ref": " "}, {"recorded_at": ""}],
)
def test_an_outcome_that_does_not_match_the_attestation_sent_is_refused(tmp_path: Path, changes: dict) -> None:
    h = fenced(tmp_path)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    with pytest.raises((AttemptStateError, ValueError)):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", issuer_record(h, attestation, **changes), NOW)
    assert h.store.abandon_outcome(ATTEMPT) is None
    state = h.store.get_attempt(ATTEMPT)
    assert state is not None and state.state != "abandoned"


def test_an_outcome_needs_a_built_attestation_and_a_known_outcome_name(tmp_path: Path) -> None:
    h = fenced(tmp_path)
    with pytest.raises(AttemptStateError, match="no attestation"):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.recorded", {}, NOW)
    attestation = h.store.build_abandon_attestation(ATTEMPT, PERMIT_ID, "loss", 1, NOW)
    with pytest.raises(AttemptStateError, match="unknown abandon outcome"):
        h.store.record_abandon_outcome(ATTEMPT, "abandon.maybe", issuer_record(h, attestation), NOW)


# ------------------------------------------------------------- sender precondition


def authorized(tmp_path: Path) -> Harness:
    h = harness(tmp_path)
    ready(h, vector_flow())
    authorize(h)
    return h


def test_begin_send_succeeds_once_for_a_complete_authorized_attempt(tmp_path: Path) -> None:
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
    h = authorized(tmp_path)
    h.store._db.execute(sql)
    with pytest.raises(OutcomeRefused) as refusal:
        h.store.begin_send(ATTEMPT)
    assert refusal.value.reason == "send_precondition_failed"
    row = h.store.outbox_row(ATTEMPT)
    assert row is not None and row["send_started"] == 0


# ----------------------------------------------------------- availability gate


def gate(remaining: float, *, failures: int = 0) -> tuple[CircuitBreaker, Deadline, Clock]:
    clock = Clock(100.0)
    breaker = CircuitBreaker(clock)
    for _ in range(failures):
        breaker.record_failure()
    return breaker, Deadline(100.0 + remaining, clock), clock


def test_a_live_deadline_and_a_closed_breaker_allow_the_call() -> None:
    breaker, deadline, _ = gate(60.0)
    assert decide_issuer_call(breaker, deadline, finalization=True).allowed is True


def test_an_expired_deadline_refuses_with_the_visible_status() -> None:
    breaker, deadline, _ = gate(0.0)
    decision = decide_issuer_call(breaker, deadline, finalization=False)
    assert (decision.allowed, decision.status, decision.reason) == (
        False, ISSUER_UNAVAILABLE_STATUS, "deadline_expired",
    )
    assert ISSUER_UNAVAILABLE_STATUS == "dispatch.issuer_unavailable"


def test_a_short_window_blocks_finalization_but_not_admission() -> None:
    breaker, deadline, _ = gate(14.0)
    short = decide_issuer_call(breaker, deadline, finalization=True)
    assert (short.allowed, short.reason) == (False, "finalization_window_too_short")
    assert decide_issuer_call(breaker, deadline, finalization=False).allowed is True


def test_an_open_breaker_refuses_and_a_refusal_before_it_never_spends_the_probe() -> None:
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
    with pytest.raises(ValueError):
        next_retry_delay(**kwargs)


# ------------------------------------------------- signed-policy clock skew (default zero)


def test_the_default_skew_is_zero_so_any_backward_step_quarantines(tmp_path: Path) -> None:
    store = SqliteAttemptStore(db_path(tmp_path))
    store.observe_clock(NOW)
    with pytest.raises(ClockQuarantined):
        store.observe_clock(NOW - timedelta(microseconds=1))


def test_a_backward_step_within_the_skew_is_tolerated_and_never_lowers_the_mark(tmp_path: Path) -> None:
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
    skew = timedelta(seconds=2)
    store = SqliteAttemptStore(db_path(tmp_path), clock_skew_tolerance=skew)
    store.observe_clock(NOW)
    store.observe_clock(NOW + timedelta(seconds=10))
    store.observe_clock(NOW + timedelta(seconds=8))  # within skew of the new mark
    with pytest.raises(ClockQuarantined):
        store.observe_clock(NOW + timedelta(seconds=7, microseconds=999_999))


@pytest.mark.parametrize("bad", [timedelta(seconds=-1), 2, 2.5, "2s", None, timedelta(days=1)])
def test_a_negative_or_non_timedelta_or_unbounded_skew_is_refused(tmp_path: Path, bad: object) -> None:
    with pytest.raises(ValueError, match="clock_skew_tolerance"):
        SqliteAttemptStore(db_path(tmp_path), clock_skew_tolerance=bad)  # type: ignore[arg-type]


def test_the_skew_does_not_relax_an_existing_quarantine(tmp_path: Path) -> None:
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
