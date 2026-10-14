"""A fit decision may neither rest on a stale measurement nor outlive the measurement it rests on.

Agate binds an observation to an aware ``observed_at`` timestamp but never compares it with a clock, and
the adapter's ``fit_validity`` used to count from *assessment* time. A week-old measurement presented as
"observed" therefore produced a decision that stayed valid for another full window. These tests pin the
consumer-side rule: evidence that is not fresh is not assessed, and a decision's expiry is capped by the
age of its measurement.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

# Measured fit (agate.fit / agate.evidence) does not exist at the production Agate pin: this is a
# candidate-only capability band, so the module skips there instead of erroring at collection.
pytest.importorskip("agate", reason="real Agate not installed")
pytest.importorskip("agate.evidence", reason="measured fit needs the candidate Agate (absent at the pin)")
from agate import HardwareObservation, load_policy, load_profile_store  # noqa: E402
from agate.evidence import FitEvidence  # noqa: E402
from agate.fit import assess_fit  # noqa: E402

from orama.graph.adapters import AgateAdapter  # noqa: E402

NOW = datetime(2026, 10, 14, 3, 0, tzinfo=UTC)
FIVE = timedelta(minutes=5)


def _model_and_profile() -> tuple[str, str]:
    """Pick a real (model, profile id) pair whose verdict allows placement."""
    policy = load_policy()
    for profile_id, profile in load_profile_store().profiles.items():
        for name, spec in policy.models.items():
            if spec.verdict_for_tier(profile.verdict_tier) in {"PREFER", "ALLOW"}:
                return name, profile_id
    pytest.skip("no real profile/model pair with an allowing verdict")


def _observation(profile_id: str) -> HardwareObservation:
    """Build the observation that identifies exactly this profile."""
    profile = load_profile_store().profiles[profile_id]
    match = profile.match
    return HardwareObservation(
        os=match.get("os", profile.os),
        cpu=match.get("cpu_contains", profile.cpu),
        ram_gb=match.get("ram_gb", profile.ram_gb),
        accelerator=match.get("accelerator_contains", profile.accelerator),
        accelerator_memory_gb=match.get("accelerator_memory_gb", profile.accelerator_memory_gb),
    )


def _assess(
    *,
    measured_at: datetime | None,
    unidentified: bool = False,
    **adapter_kwargs: object,
):
    """Run the real adapter over real Agate with evidence taken at ``measured_at`` (None = derived)."""
    model, profile_id = _model_and_profile()
    observation = HardwareObservation(None, None, None, None, None) if unidentified else _observation(profile_id)

    def evidence_provider(_context: object, obs: HardwareObservation) -> FitEvidence:
        """Attested evidence stamped with the scenario's collection time, or derived evidence."""
        if measured_at is None:
            return FitEvidence.derived(obs)
        stamp: datetime = measured_at
        return FitEvidence.observed(obs, collector="local-hardware-collector", clock=lambda: stamp)

    adapter = AgateAdapter(
        policy=load_policy(),
        assess_fit=assess_fit,
        observation_provider=lambda _context: observation,
        evidence_provider=evidence_provider,
        clock=lambda: NOW,
        **adapter_kwargs,
    )
    return adapter.assess(SimpleNamespace(run_id="run-1", model=model))


def test_a_measurement_older_than_the_window_is_refused_as_stale() -> None:
    """The reported gap: an hour-old 'observed' measurement used to be admitted as fresh."""
    decision = _assess(measured_at=NOW - timedelta(hours=1))

    assert decision.allowed is False
    assert decision.reason_code == "evidence_stale"
    assert decision.expires_at is None
    assert decision.overridable is False
    assert decision.evidence_class == "observed"


def test_a_fresh_measurement_is_allowed_and_its_expiry_is_capped_by_its_age() -> None:
    """Measured 2 minutes ago: the decision may live only for the 3 minutes of freshness left."""
    decision = _assess(measured_at=NOW - timedelta(minutes=2))

    assert decision.allowed is True
    assert decision.expires_at == NOW + timedelta(minutes=3)


def test_a_decision_never_outlives_its_measurement_even_with_a_long_validity() -> None:
    """A generous validity window must not stretch the life of an old measurement."""
    decision = _assess(
        measured_at=NOW - timedelta(minutes=1),
        fit_validity=timedelta(hours=1),
        max_observation_age=timedelta(minutes=10),
    )

    assert decision.allowed is True
    assert decision.expires_at == NOW + timedelta(minutes=9)


def test_the_age_limit_is_inclusive_and_one_second_over_is_stale() -> None:
    """Boundary: exactly the limit is fresh; one second more is stale."""
    at_limit = _assess(measured_at=NOW - FIVE)
    over = _assess(measured_at=NOW - FIVE - timedelta(seconds=1))

    assert at_limit.allowed is True and at_limit.expires_at == NOW
    assert over.allowed is False and over.reason_code == "evidence_stale"


def test_a_future_dated_measurement_is_refused() -> None:
    """A collector clock ahead of ours is not evidence of freshness."""
    decision = _assess(measured_at=NOW + timedelta(hours=1))

    assert decision.allowed is False
    assert decision.reason_code == "evidence_future_dated"


def test_small_clock_skew_is_tolerated() -> None:
    """Thirty seconds of collector skew must not refuse an otherwise fresh measurement."""
    decision = _assess(measured_at=NOW + timedelta(seconds=30))

    assert decision.allowed is True


def test_stale_evidence_is_not_assessed_so_age_takes_precedence_over_a_profile_miss() -> None:
    """Evidence that is not fresh is not evaluated at all, whatever it would have matched."""
    decision = _assess(measured_at=NOW - timedelta(hours=1), unidentified=True)

    assert decision.reason_code == "evidence_stale"


def test_derived_evidence_is_unchanged_by_the_age_rule() -> None:
    """Derived evidence carries no timestamp; admission, not this adapter, refuses it."""
    decision = _assess(measured_at=None)

    assert decision.allowed is True
    assert decision.evidence_class == "derived"
    assert decision.expires_at == NOW + FIVE
