"""T1 runtime composition: public invocations cannot bypass admission."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.graph.admission import (
    AdmissionProviders,
    AdmissionRefused,
    AdmissionRequirements,
)
from orama.graph.admission_runtime import AdmissionGraphRunner, UnconfiguredGraphRunner
from orama.graph.execution_guard import StepLedger
from orama.graph.run_control import RunControl, StopRequest
from tests.core_capabilities import CORE_GATE_AVAILABLE, invoke_or_expect_gate_refusal
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
        await UnconfiguredGraphRunner().invoke(
            Graph(), PerpetuaState(session_id="run-1")
        )
    assert called is False


async def test_runner_refuses_unbound_invocation_before_dispatch(
    tmp_path: Path,
) -> None:
    """An admission factory never trusts state to establish run authority."""
    owner_providers, clock = providers()
    store_path = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store_path)
    run_control = RunControl(store_path=store_path)
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        run_control=run_control,
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
    ledger.close()
    run_control.close()


async def test_bound_runner_replaces_client_run_and_principal(tmp_path: Path) -> None:
    """The server-bound capability, not request state, owns admission identity."""
    owner_providers, clock = providers()
    store_path = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store_path)
    run_control = RunControl(store_path=store_path)
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
        run_control=run_control,
        context_from_state=lambda _state: context(
            run_id="client-run", principal_id="client-principal"
        ),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    bound = runner.for_authenticated_principal("control-plane")
    outcome = await invoke_or_expect_gate_refusal(
        lambda: bound.invoke(
            _compiled_graph(), PerpetuaState(session_id="client-session")
        )
    )
    assert len(seen_contexts) == 1
    effective = seen_contexts[0]
    assert effective.principal_id == "control-plane"
    assert effective.run_id not in {"client-run", "client-session"}
    if outcome is None:  # Core without a gate: identity was bound, scheduling refused
        ledger.close()
        run_control.close()
        return
    assert ledger.used(effective.run_id) == 1
    receipt = run_control.terminal_receipt(effective.run_id)
    assert receipt is not None
    assert receipt.outcome == "completed"
    assert receipt.charge_summary[0] == ("steps", 1)
    assert receipt.evidence_digest is not None
    assert len(receipt.evidence_digest) == 64
    ledger.close()
    run_control.close()


async def test_bound_runner_rejects_split_run_control_and_ledger_stores(
    tmp_path: Path,
) -> None:
    """A run cannot split stop authority from its accounting ledger."""
    owner_providers, clock = providers()
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    run_control = RunControl(store_path=tmp_path / "control.sqlite3")
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        run_control=run_control,
        context_from_state=lambda _state: context(run_id="client-run"),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    with pytest.raises(AdmissionRefused, match="run_control_store_mismatch"):
        await runner.for_authenticated_principal("control-plane").invoke(
            _compiled_graph(), PerpetuaState(session_id="client-session")
        )
    assert ledger.limit("client-run") is None
    ledger.close()
    run_control.close()


async def test_stop_between_dispatch_and_start_is_recorded_truthfully(
    tmp_path: Path,
) -> None:
    """A stop winning the durable start fence prevents the callable and retains its hold."""
    owner_providers, clock = providers()
    store_path = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store_path)
    run_control = RunControl(store_path=store_path)
    run_ids: list[str] = []

    class StopAtStartGraph:
        """Inject a stop after admission but before the callable start marker."""

        async def ainvoke(self, state: object, *, gate: Any) -> object:
            from perpetua_core.graph.gate import DispatchRequest

            request = DispatchRequest("node", ("work",), 0)
            decision = await gate.before_dispatch(request)
            assert decision.verdict == "allow"
            run_ids.append(gate.run_id)
            run_control.request_stop(
                StopRequest(
                    run_id=gate.run_id,
                    principal="control-plane",
                    reason="operator.stop_at_start",
                )
            )
            await gate.before_start(request)
            raise AssertionError("the callable start boundary must have stopped")

    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        run_control=run_control,
        context_from_state=lambda _state: context(run_id="client-run"),
        max_steps=3,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )

    bound = runner.for_authenticated_principal("control-plane")
    if not CORE_GATE_AVAILABLE:
        await invoke_or_expect_gate_refusal(
            lambda: bound.invoke(
                StopAtStartGraph(), PerpetuaState(session_id="client-session")
            )
        )
        ledger.close()
        run_control.close()
        return
    with pytest.raises(AdmissionRefused, match="stop_requested"):
        await bound.invoke(
            StopAtStartGraph(), PerpetuaState(session_id="client-session")
        )

    assert len(run_ids) == 1
    receipt = run_control.terminal_receipt(run_ids[0])
    assert receipt is not None
    assert receipt.outcome == "unknown"
    assert receipt.reason == "operator.stop_at_start"
    assert len(receipt.unresolved_attempts) == 1
    assert ledger.hold_state(receipt.run_id, receipt.unresolved_attempts[0]) == "held"
    ledger.close()
    run_control.close()
