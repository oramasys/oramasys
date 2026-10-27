"""Use the real governed transaction before driving an inert effect."""
import pytest
from dataclasses import replace
from pathlib import Path
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
            InertEffectDriver(h.store, clock=lambda: NOW).send(ATTEMPT)
        assert h.store.outbox_row(ATTEMPT) == before
    finally:
        h.store.close()


def inert_harness(tmp_path: Path, *, authorize_attempt: bool = True) -> Harness:
    """Prepare an inert attempt, optionally pausing before its authorization commit."""
    store = SqliteAttemptStore(tmp_path / "inert.sqlite", governed=True)
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    scope = replace(SCOPE, destination="inert://simulation")
    store.propose("inert-proposal", scope, NOW)
    store.reserve(RESERVATION, "inert-proposal", scope, LIVE_UNTIL, NOW)
    h = Harness(store, tmp_path / "inert.sqlite", FakeVerifier(), FakeGates(), FakeRevocations())
    ready(h, vector_flow())
    if authorize_attempt:
        authorize(h, scope)
    return h


@pytest.mark.parametrize("cause", ["expired", "revoked", "missing"])
def test_final_send_boundary_refuses_stale_authority(tmp_path: Path, cause: str) -> None:
    """Expiry, acknowledged revocation and legacy missing context cannot start a send."""
    from datetime import timedelta
    from tests.test_dispatch_attempts import ISSUER
    h = inert_harness(tmp_path)
    try:
        now = NOW
        if cause == "expired":
            now += timedelta(days=1)
        elif cause == "revoked":
            h.store._db.execute(
                "INSERT INTO issuer_revocations VALUES (?, ?, 'grant', ?)",
                (ISSUER, 100, GRANT),
            )
        else:
            h.store._db.execute("DELETE FROM send_authority")
        before = h.store.outbox_row(ATTEMPT)
        with pytest.raises(OutcomeRefused):
            InertEffectDriver(h.store, clock=lambda: now).send(ATTEMPT)
        assert h.store.outbox_row(ATTEMPT) == before
    finally:
        h.store.close()


def test_send_authority_expires_at_the_earlier_parsed_instant(tmp_path: Path) -> None:
    """The stored send authority is the earlier of permit and finalization expiry, as instants."""
    from datetime import timedelta
    from orama.graph.dispatch_attempts import _earliest_expiry
    from orama.graph.dispatch_consumer_wire import WireError, parse_timestamp
    from tests.test_dispatch_attempts import EXPECTED, ISSUER, build_flow
    fin_expiry = "2026-10-19T04:01:00.000000Z"
    permit_expiry = "2026-10-19T04:01:31.000000Z"
    assert _earliest_expiry(permit_expiry, fin_expiry) == fin_expiry
    assert _earliest_expiry(fin_expiry, permit_expiry) == fin_expiry
    with pytest.raises(WireError):  # raw text would have stored an instant that does not exist
        _earliest_expiry(permit_expiry, "2026-02-30T00:00:00.000000Z")
    store = SqliteAttemptStore(tmp_path / "inert.sqlite", governed=True)
    try:
        store._create_attempt(ATTEMPT, GRANT, RESERVATION)
        scope = replace(SCOPE, destination="inert://simulation")
        store.propose("inert-proposal", scope, NOW)
        store.reserve(RESERVATION, "inert-proposal", scope, LIVE_UNTIL, NOW)
        h = Harness(store, tmp_path / "inert.sqlite", FakeVerifier(), FakeGates(), FakeRevocations())
        flow = build_flow(fin_changes={"expires_at": fin_expiry})
        ready(h, flow)
        store.authorize_dispatch(
            ATTEMPT, flow.permit, flow.fin, NOW, verifier=h.verifier, gates=h.gates,
            revocations=h.revocations, issuer_id=ISSUER, expected=EXPECTED, scope=scope,
        )
        assert flow.permit["expires_at"] == permit_expiry
        assert store._db.execute("SELECT expires_at FROM send_authority").fetchone() == (fin_expiry,)
        before = store.outbox_row(ATTEMPT)
        with pytest.raises(OutcomeRefused, match="send_authority_expired_or_missing"):
            InertEffectDriver(store, clock=lambda: parse_timestamp(fin_expiry)).send(ATTEMPT)
        assert store.outbox_row(ATTEMPT) == before
        last = parse_timestamp(fin_expiry) - timedelta(microseconds=1)
        assert InertEffectDriver(store, clock=lambda: last).send(ATTEMPT) == "inert-simulation:v1"
    finally:
        store.close()


def test_inert_send_is_durable_and_single_use(tmp_path):
    """A simulated send requires authority and cannot be replayed after reopening."""
    h = inert_harness(tmp_path)
    try:
        driver = InertEffectDriver(h.store, clock=lambda: NOW)
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
            InertEffectDriver(reopened, clock=lambda: NOW).send(ATTEMPT)
    finally:
        reopened.close()


def test_crash_after_send_marker_preserves_unknown_and_refuses_retry(tmp_path):
    """Restart cannot retry a send whose settlement never became durable."""
    h = inert_harness(tmp_path)
    h.store.begin_send(ATTEMPT, inert_only=True, now=NOW)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        assert reopened.outbox_row(ATTEMPT)["outcome"] == "unknown"
        with pytest.raises(OutcomeRefused):
            InertEffectDriver(reopened, clock=lambda: NOW).send(ATTEMPT)
        assert reopened.outbox_row(ATTEMPT)["outcome"] == "unknown"
    finally:
        reopened.close()
