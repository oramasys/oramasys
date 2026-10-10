"""T1: AdmissionGate inside Core's one scheduler. Needs a Core revision with the
DispatchGate seam; collected only where that Core is installed (see conftest.py)."""
from __future__ import annotations

import pytest

from orama.graph.admission import admit_artifact
from orama.graph.execution_guard import AdmissionGate, StepLedger, StopSignal
from tests.admission_fakes import FakeAgate, FakeClock, FakePhylax, FakeTelos
from tests.test_admission_decision import binding, context


def make(tmp_path, *, max_steps=10, telos_ttl=60, agate_ttl=60):
    clock = FakeClock()
    phylax = FakePhylax(clock)
    from orama.graph.admission import AdmissionProviders

    providers = AdmissionProviders(phylax, FakeAgate(clock, ttl=agate_ttl), FakeTelos(clock, ttl=telos_ttl))
    decision = admit_artifact(binding(), context(), providers, clock=clock, max_steps=max_steps)
    assert decision.outcome == "allow"
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=decision.max_steps)
    stop = StopSignal()
    gate = AdmissionGate(
        decision=decision,
        binding=binding(),
        providers=providers,
        ledger=ledger,
        run_id="run-1",
        lease_epoch=epoch,
        stop=stop,
        clock=clock,
    )
    return gate, clock, phylax, ledger, stop


def linear(clock=None, advance=0, calls=None):
    from perpetua_core.graph.engine import END, MiniGraph

    graph = MiniGraph()

    def a(_):
        if calls is not None:
            calls.append("a")
        if clock is not None:
            clock.advance(advance)
        return {"scratchpad": {"a": 1}}

    graph.add_node("a", a)
    graph.add_node("b", lambda s: {"scratchpad": {**s.scratchpad, "b": 1}})
    graph.set_entry("a")
    graph.add_edge("a", "b")
    graph.add_edge("b", END)
    return graph


def fresh():
    from perpetua_core.state import PerpetuaState

    return PerpetuaState(session_id="t1")


async def test_allowed_run_completes_and_charges_each_node(tmp_path):
    gate, _, _, ledger, _ = make(tmp_path)
    state = await linear().compile().ainvoke(fresh(), gate=gate)
    assert state.status == "done"
    assert ledger.used("run-1") == 2


async def test_expiry_between_dispatch_and_commit_refuses_the_commit(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, clock, _, _, _ = make(tmp_path, telos_ttl=30)
    calls: list[str] = []
    with pytest.raises(GateRefused) as info:
        await linear(clock, advance=31, calls=calls).compile().ainvoke(fresh(), gate=gate)
    assert calls == ["a"]
    assert info.value.decision.reason == "authority.expired"
    assert info.value.request.boundary == "node"


async def test_revocation_after_admission_refuses_the_next_dispatch(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, _, phylax, _, _ = make(tmp_path)
    phylax.revoke()
    with pytest.raises(GateRefused) as info:
        await linear().compile().ainvoke(fresh(), gate=gate)
    assert info.value.decision.reason == "authority.owner_decision_stale"


async def test_fenced_lease_refuses_before_anything_runs(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, _, _, ledger, _ = make(tmp_path)
    ledger.open_lease("run-1", max_steps=10)  # a newer holder takes the lease
    calls: list[str] = []
    with pytest.raises(GateRefused) as info:
        await linear(calls=calls).compile().ainvoke(fresh(), gate=gate)
    assert calls == []
    assert info.value.decision.reason == "authority.lease_fenced"


async def test_stop_comes_after_authority_and_ends_the_run(tmp_path):
    gate, _, _, _, stop = make(tmp_path)
    stop.request("operator.stop")
    state = await linear().compile().ainvoke(fresh(), gate=gate)
    assert state.status == "stopped"
    assert state.metadata["stop_reason"] == "operator.stop"


async def test_authority_is_checked_before_stop(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, _, phylax, _, stop = make(tmp_path)
    stop.request("operator.stop")
    phylax.revoke()
    with pytest.raises(GateRefused):
        await linear().compile().ainvoke(fresh(), gate=gate)


async def test_unhealthy_delivery_refuses(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, *_ = make(tmp_path)
    gate.delivery = type("Down", (), {"healthy": lambda self: False})()
    with pytest.raises(GateRefused) as info:
        await linear().compile().ainvoke(fresh(), gate=gate)
    assert info.value.decision.reason == "delivery.unhealthy"


async def test_budget_exhaustion_refuses_without_charging(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, _, _, ledger, _ = make(tmp_path, max_steps=1)
    with pytest.raises(GateRefused) as info:
        await linear().compile().ainvoke(fresh(), gate=gate)
    assert info.value.decision.reason == "budget.steps_exhausted"
    assert ledger.used("run-1") == 1


async def test_fanout_batch_is_reserved_all_or_nothing(tmp_path):
    from perpetua_core.graph.engine import END, FanOut, MiniGraph
    from perpetua_core.graph.gate import GateRefused

    gate, _, _, ledger, _ = make(tmp_path, max_steps=3)
    calls: list[str] = []
    graph = MiniGraph()
    graph.add_node("plan", lambda s: {})
    for name in ("b1", "b2", "b3"):
        graph.add_node(name, lambda s, n=name: calls.append(n) or {"scratchpad": {n: 1}})
    graph.add_node("after", lambda s: {})
    graph.set_entry("plan")
    graph.add_edge("plan", FanOut(("b1", "b2", "b3"), "after"))
    graph.add_edge("after", END)
    with pytest.raises(GateRefused) as info:
        await graph.compile().ainvoke(fresh(), gate=gate)
    assert info.value.request.boundary == "fanout"
    assert calls == []  # 1 used by plan, 3 more do not fit: no branch starts
    assert ledger.used("run-1") == 1


async def test_expiry_before_reducer_refuses_the_fold(tmp_path):
    from perpetua_core.graph.engine import END, FanOut, MiniGraph
    from perpetua_core.graph.gate import GateRefused
    from perpetua_core.graph.reducers import Reducer

    gate, clock, _, _, _ = make(tmp_path, agate_ttl=30)
    folded: list[str] = []
    graph = MiniGraph()
    graph.add_node("plan", lambda s: {})

    def slow(_):
        clock.advance(31)
        return {"messages": [{"m": "x"}]}

    graph.add_node("b1", slow)
    graph.add_node("b2", lambda s: {"messages": [{"m": "y"}]})
    graph.add_node("after", lambda s: {})
    graph.set_entry("plan")
    graph.add_edge("plan", FanOut(("b1", "b2"), "after"))
    graph.add_edge("after", END)

    def fold(current, values):
        folded.append("fold")
        return list(current or []) + [v for value in values for v in value]

    graph.add_reducer("messages", Reducer("custom", fold))
    with pytest.raises(GateRefused) as info:
        await graph.compile().ainvoke(fresh(), gate=gate)
    assert info.value.request.boundary == "reducer"
    assert folded == []


async def test_changed_binding_refuses_even_with_a_valid_decision(tmp_path):
    from perpetua_core.graph.gate import GateRefused

    gate, *_ = make(tmp_path)
    gate.binding = binding(implementation_digest="sha256:" + "9" * 64)
    with pytest.raises(GateRefused) as info:
        await linear().compile().ainvoke(fresh(), gate=gate)
    assert info.value.decision.reason == "authority.binding_changed"


def test_gate_refuses_construction_from_a_non_allow_decision(tmp_path):
    from dataclasses import replace

    from orama.graph.admission import AdmissionRefused

    gate, *_ = make(tmp_path)
    with pytest.raises(AdmissionRefused):
        AdmissionGate(
            decision=replace(gate.decision, outcome="pending"),
            binding=gate.binding,
            providers=gate.providers,
            ledger=gate.ledger,
            run_id="run-1",
            lease_epoch=1,
            stop=StopSignal(),
            clock=gate.clock,
        )




def test_gate_refuses_a_lease_wider_than_the_admitted_bound(tmp_path):
    from orama.graph.admission import AdmissionRefused

    gate, *_ = make(tmp_path, max_steps=3)
    wider = StepLedger(tmp_path / "wider.sqlite3")
    epoch = wider.open_lease("run-1", max_steps=50)
    with pytest.raises(AdmissionRefused, match="ledger_bound_exceeds_admission"):
        AdmissionGate(decision=gate.decision, binding=gate.binding, providers=gate.providers,
                      ledger=wider, run_id="run-1", lease_epoch=epoch, stop=StopSignal(), clock=gate.clock)


def test_gate_refuses_a_run_with_no_lease(tmp_path):
    from orama.graph.admission import AdmissionRefused

    gate, *_ = make(tmp_path)
    with pytest.raises(AdmissionRefused, match="ledger_bound_exceeds_admission"):
        AdmissionGate(decision=gate.decision, binding=gate.binding, providers=gate.providers,
                      ledger=StepLedger(tmp_path / "empty.sqlite3"), run_id="run-1", lease_epoch=1,
                      stop=StopSignal(), clock=gate.clock)
