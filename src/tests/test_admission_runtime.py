"""T1 runtime composition: public invocations cannot bypass admission."""
from __future__ import annotations

from typing import Any

import pytest

from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.graph.admission import AdmissionProviders, AdmissionRefused, AdmissionRequirements
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


async def test_runner_refuses_unbound_invocation_before_dispatch(tmp_path) -> None:
    """An admission factory never trusts state to establish run authority."""
    owner_providers, clock = providers()
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        context_from_state=lambda _state: context(run_id="client-run"),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    with pytest.raises(AdmissionRefused, match="authenticated_context_required"):
        await runner.invoke(_compiled_graph(), PerpetuaState(session_id="run-1"))
    assert ledger.used("client-run") == 0


async def test_bound_runner_replaces_client_run_and_principal(tmp_path) -> None:
    """The server-bound capability, not request state, owns admission identity."""
    owner_providers, clock = providers()
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    seen_contexts: list[Any] = []

    class RecordingPhylax:
        """Record the effective context before delegating to the fake owner."""

        def admit(self, artifact: Any, effective_context: Any) -> Any:
            """Retain the context that admission actually receives."""
            seen_contexts.append(effective_context)
            assert owner_providers.phylax is not None
            return owner_providers.phylax.admit(artifact, effective_context)

        def is_current(self, decision: Any) -> bool:
            """Delegate freshness to the configured fake owner."""
            assert owner_providers.phylax is not None
            return owner_providers.phylax.is_current(decision)

    recorded_providers = AdmissionProviders(
        phylax=RecordingPhylax(),
        agate=owner_providers.agate,
        telos=owner_providers.telos,
    )

    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=recorded_providers,
        ledger=ledger,
        context_from_state=lambda _state: context(
            run_id="client-run", principal_id="client-principal"
        ),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    await runner.for_authenticated_principal("control-plane").invoke(
        _compiled_graph(), PerpetuaState(session_id="client-session")
    )
    assert len(seen_contexts) == 1
    effective = seen_contexts[0]
    assert effective.principal_id == "control-plane"
    assert effective.run_id not in {"client-run", "client-session"}
    assert ledger.used(effective.run_id) == 1
