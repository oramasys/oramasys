"""T1 runtime composition: public invocations cannot bypass admission."""
from __future__ import annotations

import pytest

from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.graph.admission import AdmissionRefused, AdmissionRequirements
from orama.graph.admission_runtime import AdmissionGraphRunner, UnconfiguredGraphRunner
from orama.graph.execution_guard import StepLedger
from tests.test_admission_decision import binding, context, providers


def _compiled_graph() -> object:
    """Build a minimal graph whose node can be observed through the real gate."""
    graph = MiniGraph()
    graph.add_node("work", lambda state: {"scratchpad": {"ran": True}})
    graph.add_edge(START, "work").add_edge("work", END)
    return graph.compile()


async def test_unconfigured_runner_refuses_before_invoking_graph() -> None:
    """Production's default runner never schedules work without admission wiring."""
    called = False

    class Graph:
        """Probe that makes an accidental scheduler call visible."""

        async def ainvoke(self, state: object, *, gate: object | None = None) -> object:
            """Record a call that must never occur for an unconfigured runner."""
            nonlocal called
            called = True
            return state

    with pytest.raises(AdmissionRefused, match="enforcement_unavailable"):
        await UnconfiguredGraphRunner().invoke(Graph(), PerpetuaState(session_id="run-1"))
    assert called is False


async def test_runner_refuses_context_with_a_different_run_id_before_dispatch(tmp_path) -> None:
    """A context cannot mint a run identity unrelated to the state being invoked."""
    owner_providers, clock = providers()
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        context_from_state=lambda _state: context(run_id="other-run"),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    with pytest.raises(AdmissionRefused, match="run_id_mismatch"):
        await runner.invoke(_compiled_graph(), PerpetuaState(session_id="run-1"))
    assert ledger.used("other-run") == 0
