"""T2 accounting markers precede actual callable transfer in Core's scheduler."""
from __future__ import annotations

from pathlib import Path

import pytest

from orama.graph.accounting_types import ChargeUnits
from orama.graph.execution_guard import AdmissionRefused
from tests.core_gate.test_admission_gate_scheduler import fresh, linear, make



async def test_start_marker_is_durable_before_node_callable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Callable execution observes its already-persisted marker."""
    gate, _, _, ledger, _ = make(tmp_path)
    markers: list[str] = []
    original = ledger.mark_started

    def mark(run_id: str, attempt_id: str, epoch: int) -> object:
        result = original(run_id, attempt_id, epoch)
        markers.append(attempt_id)
        return result

    monkeypatch.setattr(ledger, "mark_started", mark)
    from perpetua_core.graph.engine import END, MiniGraph

    graph = MiniGraph()

    def node(_: object) -> dict[str, object]:
        assert markers == ["node::a::0"]
        return {"scratchpad": {"a": True}}

    graph.add_node("a", node)
    graph.set_entry("a")
    graph.add_edge("a", END)
    state = await graph.compile().ainvoke(fresh(), gate=gate)
    assert state.status == "done"
    assert ledger.hold_state("run-1", "node::a::0") == "settled"


async def test_failed_start_marker_never_calls_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A persistence failure fails closed before callable control transfer."""
    gate, _, _, ledger, _ = make(tmp_path)
    calls: list[str] = []

    def fail(*_: object) -> None:
        raise OSError("injected marker write failure")

    monkeypatch.setattr(ledger, "mark_started", fail)
    with pytest.raises(OSError, match="marker write"):
        await linear(calls=calls).compile().ainvoke(fresh(), gate=gate)
    assert calls == []


async def test_multi_unit_allowance_is_reserved_before_nodes(tmp_path: Path) -> None:
    """An explicit allowance enforces every configured dimension atomically."""
    gate, _, _, ledger, _ = make(tmp_path)
    gate.configure_accounting(
        limits=ChargeUnits(steps=10, elapsed_ms=10, cost_microunits=8,
                           effect_attempts=2, cost_basis="test-unit"),
        allowance=ChargeUnits(steps=1, elapsed_ms=5, cost_microunits=4,
                              effect_attempts=1, cost_basis="test-unit"),
    )
    state = await linear().compile().ainvoke(fresh(), gate=gate)
    assert state.status == "done"
    assert ledger.used("run-1") == 2
    assert ledger.usage("run-1") == ChargeUnits(
        steps=2, elapsed_ms=10, cost_microunits=8,
        effect_attempts=2, cost_basis="test-unit",
    )


def test_accounting_configuration_cannot_expand_admission(tmp_path: Path) -> None:
    """A runtime accounting limit cannot widen owner-approved steps."""
    gate, _, _, _, _ = make(tmp_path, max_steps=2)
    with pytest.raises(AdmissionRefused):
        gate.configure_accounting(
            limits=ChargeUnits(steps=3, cost_basis="test-unit"),
            allowance=ChargeUnits(steps=1, cost_basis="test-unit"),
        )


def test_compound_attempt_names_cannot_alias_one_another(tmp_path: Path) -> None:
    """Delimiter-bearing identifiers cannot collapse distinct callable requests."""
    gate, _, _, _, _ = make(tmp_path)
    first = gate._attempt_id("reducer", ("a::b", "c"), 2, None)
    second = gate._attempt_id("reducer", ("a", "b::c"), 2, None)
    assert first != second


async def test_idempotent_start_record_does_not_authorize_reexecution(tmp_path: Path) -> None:
    """Reusing a gate cannot replay a completed call for its old reservation."""
    from perpetua_core.graph.gate import GateRefused

    gate, _, _, ledger, _ = make(tmp_path)
    calls: list[str] = []
    compiled = linear(calls=calls).compile()
    await compiled.ainvoke(fresh(), gate=gate)
    with pytest.raises(GateRefused, match=r"ledger\.start_invalid"):
        await compiled.ainvoke(fresh(), gate=gate)
    assert calls == ["a"]
    assert ledger.used("run-1") == 2
