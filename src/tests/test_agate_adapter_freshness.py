"""Regression coverage for the Agate adapter's measurement-freshness boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from orama.graph.adapters import AgateAdapter


def test_assess_refuses_an_allow_that_becomes_stale_during_fit_assessment() -> None:
    """An allowed decision must not be emitted after its evidence freshness expires."""
    measured_at = datetime(2026, 10, 14, 3, 0, tzinfo=UTC)
    current_time = measured_at + timedelta(minutes=5) - timedelta(milliseconds=1)

    def clock() -> datetime:
        return current_time

    def assess_after_deadline(*_args: object) -> SimpleNamespace:
        nonlocal current_time
        current_time += timedelta(milliseconds=2)
        return SimpleNamespace(feasible=True, reason_code="fit_allowed", evidence_class="observed")

    adapter = AgateAdapter(
        policy=object(),
        assess_fit=assess_after_deadline,
        observation_provider=lambda _context: object(),
        evidence_provider=lambda _context, _observation: SimpleNamespace(
            classification="observed", observed_at=measured_at
        ),
        clock=clock,
    )

    decision = adapter.assess(SimpleNamespace(run_id="run-1", model="model-1"))

    assert decision.allowed is False
    assert decision.reason_code == "evidence_stale"
    assert decision.expires_at is None
