"""T1: the application-side runner drives Core's real scheduler through the gate.

Needs the Core revision with the DispatchGate seam; collected only there (see conftest).
"""
from __future__ import annotations

from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.graph.admission import AdmissionRequirements
from orama.graph.admission_runtime import AdmissionGraphRunner
from orama.graph.execution_guard import StepLedger
from tests.test_admission_decision import binding, context, providers


def _compiled_graph() -> object:
    """Build a minimal graph whose node can be observed through the real gate."""
    graph = MiniGraph()
    graph.add_node("work", lambda state: {"scratchpad": {"ran": True}})
    graph.add_edge(START, "work").add_edge("work", END)
    return graph.compile()


async def test_configured_runner_builds_gate_and_uses_the_core_scheduler(tmp_path) -> None:
    """A trusted composition creates one gate and passes it to Core's scheduler."""
    owner_providers, clock = providers()
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        context_from_state=lambda _state: context(run_id="run-1"),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    result = await runner.invoke(_compiled_graph(), PerpetuaState(session_id="run-1"))

    assert result.scratchpad["ran"] is True
    assert ledger.used("run-1") == 1
