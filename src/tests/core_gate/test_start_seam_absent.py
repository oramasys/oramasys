"""Seam-less Core contract: collected only where the gate exists without the start seam."""
from __future__ import annotations

from pathlib import Path

import pytest

from orama.graph.accounting_types import ChargeUnits
from orama.graph.execution_guard import AdmissionRefused
from tests.core_gate.test_admission_gate_scheduler import fresh, linear, make


def test_accounting_configuration_is_refused_without_the_start_seam(tmp_path: Path) -> None:
    """Multi-unit accounting needs durable start markers, so it fails closed."""
    gate, _, _, _, _ = make(tmp_path)
    with pytest.raises(AdmissionRefused, match=r"gate\.core_start_seam_unavailable"):
        gate.configure_accounting(
            limits=ChargeUnits(steps=3, cost_basis="test-unit"),
            allowance=ChargeUnits(steps=1, cost_basis="test-unit"),
        )


async def test_legacy_run_completes_without_writing_start_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the seam the step-only path still settles and writes no marker."""
    gate, _, _, ledger, _ = make(tmp_path)
    markers: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        ledger, "mark_started", lambda *args: markers.append(args) or True
    )

    state = await linear().compile().ainvoke(fresh(), gate=gate)

    assert state.status == "done"
    assert markers == []
    assert ledger.hold_state("run-1", "node::a::0") == "settled"
