"""Use the real governed transaction before driving an inert effect."""
import pytest
from dataclasses import replace
from orama.graph.dispatch_attempts import SqliteAttemptStore
from tests.test_dispatch_attempts import GRANT, RESERVATION, NOW, Harness, FakeVerifier, FakeGates, FakeRevocations, ready, vector_flow
from tests.test_effect_seam import SCOPE, LIVE_UNTIL, authorize

from orama.graph.inert_effect_driver import InertEffectDriver
from orama.graph.effect_outcomes import OutcomeRefused
from tests.test_effect_seam import governed, authorized, ATTEMPT


def test_real_effect_cannot_be_settled_by_simulation(tmp_path):
    """An inert driver cannot spend a real destination's authorization."""
    h = governed(tmp_path)
    try:
        authorized(h)
        before = h.store.outbox_row(ATTEMPT)
        with pytest.raises(OutcomeRefused, match="inert_scope_required"):
            InertEffectDriver(h.store).send(ATTEMPT)
        assert h.store.outbox_row(ATTEMPT) == before
    finally:
        h.store.close()


def inert_harness(tmp_path):
    """Create an authorized attempt explicitly scoped to the inert destination."""
    store = SqliteAttemptStore(tmp_path / "inert.sqlite", governed=True)
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    scope = replace(SCOPE, destination="inert://simulation")
    store.propose("inert-proposal", scope, NOW)
    store.reserve(RESERVATION, "inert-proposal", scope, LIVE_UNTIL, NOW)
    h = Harness(store, tmp_path / "inert.sqlite", FakeVerifier(), FakeGates(), FakeRevocations())
    ready(h, vector_flow())
    authorize(h, scope)
    return h


def test_inert_send_is_durable_and_single_use(tmp_path):
    """A simulated send requires authority and cannot be replayed after reopening."""
    h = inert_harness(tmp_path)
    try:
        driver = InertEffectDriver(h.store)
        assert driver.send(ATTEMPT) == "inert-simulation:v1"
        row = h.store.outbox_row(ATTEMPT)
        assert row["send_started"] == 1
        assert row["outcome"] == "confirmed"
        assert row["outcome_evidence"] == "inert-simulation:v1"
        with pytest.raises(OutcomeRefused):
            driver.send(ATTEMPT)
    finally:
        h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        with pytest.raises(OutcomeRefused):
            InertEffectDriver(reopened).send(ATTEMPT)
    finally:
        reopened.close()


def test_crash_after_send_marker_preserves_unknown_and_refuses_retry(tmp_path):
    """Restart cannot retry a send whose settlement never became durable."""
    h = inert_harness(tmp_path)
    h.store.begin_send(ATTEMPT, inert_only=True)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        assert reopened.outbox_row(ATTEMPT)["outcome"] == "unknown"
        with pytest.raises(OutcomeRefused):
            InertEffectDriver(reopened).send(ATTEMPT)
        assert reopened.outbox_row(ATTEMPT)["outcome"] == "unknown"
    finally:
        reopened.close()
