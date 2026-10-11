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
import sqlite3

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
    """Required core gate is present when demanded."""
    if os.environ.get("ORAMA_REQUIRE_CORE_GATE") == "1":
        assert CORE_GATE_AVAILABLE


# --- step ledger: single writer, fencing, atomic reservation ----------------


def test_ledger_reserves_atomically_and_never_over_commits(tmp_path):
    """Ledger reserves atomically and never over commits."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=3)
    assert ledger.reserve("run-1", epoch, 2)
    assert not ledger.reserve("run-1", epoch, 2)  # would exceed: nothing charged
    assert ledger.used("run-1") == 2
    assert ledger.reserve("run-1", epoch, 1)
    assert ledger.used("run-1") == 3


def test_reopening_a_lease_fences_the_old_holder(tmp_path):
    """Reopening a lease fences the old holder."""
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
    """Ledger is durable and uses wal full sync."""
    path = tmp_path / "ledger.sqlite3"
    ledger = StepLedger(path)
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve("run-1", epoch, 2)
    ledger.close()
    again = StepLedger(path)
    assert again.used("run-1") == 2
    assert again.pragmas() == ("wal", 2)


def test_ledger_rejects_bad_counts(tmp_path):
    """Ledger rejects bad counts."""
    ledger = StepLedger(tmp_path / "l.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            ledger.reserve("run-1", epoch, bad)  # type: ignore[arg-type]
    with pytest.raises(LeaseFenced):
        ledger.reserve("unknown-run", 1, 1)


def test_gate_construction_fails_closed_without_core_seam(monkeypatch, tmp_path):
    """Gate construction fails closed without core seam."""
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
    """Ledger reports the lease limit."""
    ledger = StepLedger(tmp_path / "l.sqlite3")
    assert ledger.limit("run-1") is None
    ledger.open_lease("run-1", max_steps=4)
    assert ledger.limit("run-1") == 4


@pytest.mark.asyncio
async def test_admission_gate_refuses_when_bounded_observer_unhealthy(tmp_path):
    """AdmissionGate fails closed when BoundedObserver marks delivery unhealthy."""
    from orama.graph.admission import (
        AdmissionContext,
        AdmissionProviders,
        admit_artifact,
    )
    from orama.graph.bounded_observer import BoundedObserver
    from orama.graph.execution_guard import AdmissionGate, StepLedger, StopSignal
    from perpetua_core.graph.engine import GraphEvent, GraphObservation
    from perpetua_core.graph.gate import DispatchRequest
    from perpetua_core.state import PerpetuaState
    from tests.test_admission_decision import binding, context, providers

    p, clock = providers()
    b = binding()
    ctx = context(run_id="run-1")
    decision = admit_artifact(b, ctx, p, clock=clock, max_steps=10)

    ledger = StepLedger(tmp_path / "l.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=10)

    observer = BoundedObserver(
        run_id="run-1", attempt_id="att-seam-guard", hold_id="hold-seam-guard", fence_epoch=1
    )

    def broken_sink(event):
        raise RuntimeError("critical sink failure")

    observer.register_sink("failing", broken_sink, critical=True)

    obs = GraphObservation(
        event=GraphEvent(kind="node.end", node="work", steps=1),
        state=PerpetuaState(session_id="run-1"),
        delta={"ok": False},
    )
    with pytest.raises(RuntimeError):
        await observer.on_observation(obs)

    assert not observer.healthy()

    gate = AdmissionGate(
        decision=decision,
        binding=b,
        providers=p,
        ledger=ledger,
        run_id="run-1",
        lease_epoch=epoch,
        stop=StopSignal(),
        clock=clock,
        delivery=observer,
    )

    req = DispatchRequest(boundary="node", nodes=("work",), steps=0, source=None)
    dec = await gate.before_dispatch(req)
    assert dec.verdict == "refuse"
    assert dec.reason == "delivery.unhealthy"


@pytest.mark.asyncio
async def test_critical_delivery_failure_during_an_inflight_batch_reservation(tmp_path):
    """Seam reconciliation (2026-10-11-rev3-t2-parallel-streams-plan.md, Part 3):
    Stream A's ledger and Stream B's observer must agree on exactly one
    unknown disposition for an attempt, with one recovery path, not two.

    Scenario: a fan-out batch is reserved (Stream A), then a critical
    delivery failure trips the observer's circuit (Stream B) while those
    holds are still outstanding -- before the batch ever reaches commit.
    Both streams' records of this must be the SAME type and must agree:
    the gate refuses all further dispatch (one recovery path: stop, not an
    automatic release), and the holds the ledger reserved stay exactly as
    reserved -- no silent release or relabeling triggered by the observer.
    """
    from orama.graph.admission import AdmissionProviders, admit_artifact
    from orama.graph.bounded_observer import BoundedObserver
    from orama.graph.execution_guard import AdmissionGate, StepLedger, StopSignal
    from orama.graph import execution_guard
    from perpetua_core.graph.gate import DispatchRequest
    from tests.test_admission_decision import binding, context, providers

    p, clock = providers()
    b = binding()
    ctx = context(run_id="run-seam-batch")
    decision = admit_artifact(b, ctx, p, clock=clock, max_steps=10)

    ledger = StepLedger(tmp_path / "l.sqlite3")
    epoch = ledger.open_lease("run-seam-batch", max_steps=10)

    observer = BoundedObserver(
        run_id="run-seam-batch",
        attempt_id="att-seam-batch",
        hold_id="hold-seam-batch",
        fence_epoch=1,
    )

    gate = AdmissionGate(
        decision=decision,
        binding=b,
        providers=p,
        ledger=ledger,
        run_id="run-seam-batch",
        lease_epoch=epoch,
        stop=StopSignal(),
        clock=clock,
        delivery=observer,
    )

    # 1. Reserve a fan-out batch through the real gate (Stream A's path).
    batch_id = "batch-seam-1"
    fanout_req = DispatchRequest(
        boundary="fanout", nodes=("branch-a", "branch-b"), steps=0, source=None, batch_id=batch_id
    )
    dec = await gate.before_dispatch(fanout_req)
    assert dec.verdict == "allow"

    def broken_sink(event):
        raise RuntimeError("critical sink failure mid-batch")

    observer.register_sink("failing", broken_sink, critical=True)

    # 2. Trip the circuit (Stream B's path) WHILE the batch is still
    # outstanding -- no commit has happened yet for either branch.
    from perpetua_core.graph.engine import GraphEvent, GraphObservation
    from perpetua_core.state import PerpetuaState

    obs = GraphObservation(
        event=GraphEvent(kind="node.end", node="branch-a", steps=1),
        state=PerpetuaState(session_id="run-seam-batch"),
        delta={"ok": False},
    )
    with pytest.raises(RuntimeError):
        await observer.on_observation(obs)

    # 3. The two streams' records of this failure must be the identical type.
    assert len(observer.unknown_dispositions) == 1
    disposition = observer.unknown_dispositions[0]
    assert isinstance(disposition, execution_guard.UnknownDisposition)
    assert disposition.cause == "critical_delivery_failure"

    # 4. One recovery path: the gate refuses all further dispatch (node,
    # another fanout) because delivery is unhealthy -- not because the
    # ledger silently released or relabeled the still-outstanding batch
    # holds. Confirm both halves of that claim directly.
    node_req = DispatchRequest(boundary="node", nodes=("branch-c",), steps=0, source=None)
    node_dec = await gate.before_dispatch(node_req)
    assert node_dec.verdict == "refuse"
    assert node_dec.reason == "delivery.unhealthy"

    another_fanout = DispatchRequest(
        boundary="fanout", nodes=("branch-d",), steps=0, source=None, batch_id="batch-seam-2"
    )
    fanout_dec = await gate.before_dispatch(another_fanout)
    assert fanout_dec.verdict == "refuse"
    assert fanout_dec.reason == "delivery.unhealthy"

    # The original batch's holds are still exactly as reserved: no silent
    # release happened as a side effect of the observer's circuit trip.
    with sqlite3.connect(tmp_path / "l.sqlite3") as db:
        rows = db.execute(
            "SELECT attempt_id, state FROM attempt_holds WHERE run_id = ?",
            ("run-seam-batch",),
        ).fetchall()
    attempt_ids = {row[0] for row in rows}
    assert attempt_ids == {f"{batch_id}:branch-a", f"{batch_id}:branch-b"}
    assert all(row[1] == "held" for row in rows)

