"""T1: step ledger and fail-closed gate construction (no Core seam needed).

Scheduler-level gate tests live in ``src/tests/core_gate/`` and run wherever the
installed Core has the T1 seam (required in the candidate CI job).

Original scope: AdmissionGate implements Core's DispatchGate inside the one scheduler.

Fixed order at every boundary: authority and lease, stop, delivery health, budget.
Expiry and revocation are re-checked at each boundary (node dispatch, reducer, commit,
fan-out batch), with injected clocks so nothing sleeps.
"""
from __future__ import annotations

import os

import pytest

from orama.graph.execution_guard import (
    CORE_GATE_AVAILABLE,
    LeaseFenced,
    StepLedger,
    StopSignal,
)
from tests.admission_fakes import FakeClock
from tests.test_admission_decision import binding


def test_required_core_gate_is_present_when_demanded():
    if os.environ.get("ORAMA_REQUIRE_CORE_GATE") == "1":
        assert CORE_GATE_AVAILABLE


# --- step ledger: single writer, fencing, atomic reservation ----------------


def test_ledger_reserves_atomically_and_never_over_commits(tmp_path):
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=3)
    assert ledger.reserve("run-1", epoch, 2)
    assert not ledger.reserve("run-1", epoch, 2)  # would exceed: nothing charged
    assert ledger.used("run-1") == 2
    assert ledger.reserve("run-1", epoch, 1)
    assert ledger.used("run-1") == 3


def test_reopening_a_lease_fences_the_old_holder(tmp_path):
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    old = ledger.open_lease("run-1", max_steps=5)
    new = ledger.open_lease("run-1", max_steps=5)
    assert new == old + 1
    with pytest.raises(LeaseFenced):
        ledger.reserve("run-1", old, 1)
    with pytest.raises(LeaseFenced):
        ledger.check("run-1", old)
    assert ledger.reserve("run-1", new, 1)


def test_ledger_is_durable_and_uses_wal_full_sync(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = StepLedger(path)
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve("run-1", epoch, 2)
    ledger.close()
    again = StepLedger(path)
    assert again.used("run-1") == 2
    assert again.pragmas() == ("wal", 2)


def test_ledger_rejects_bad_counts(tmp_path):
    ledger = StepLedger(tmp_path / "l.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            ledger.reserve("run-1", epoch, bad)  # type: ignore[arg-type]
    with pytest.raises(LeaseFenced):
        ledger.reserve("unknown-run", 1, 1)


def test_gate_construction_fails_closed_without_core_seam(monkeypatch, tmp_path):
    import orama.graph.execution_guard as guard
    from orama.graph.admission import AdmissionRefused

    monkeypatch.setattr(guard, "CORE_GATE_AVAILABLE", False)
    with pytest.raises(AdmissionRefused):
        guard.AdmissionGate(
            decision=None,  # type: ignore[arg-type]
            binding=binding(),
            providers=None,  # type: ignore[arg-type]
            ledger=StepLedger(tmp_path / "l.sqlite3"),
            run_id="run-1",
            lease_epoch=1,
            stop=StopSignal(),
            clock=FakeClock(),
        )


def test_ledger_reports_the_lease_limit(tmp_path):
    ledger = StepLedger(tmp_path / "l.sqlite3")
    assert ledger.limit("run-1") is None
    ledger.open_lease("run-1", max_steps=4)
    assert ledger.limit("run-1") == 4
