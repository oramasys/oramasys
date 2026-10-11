"""T1/T2: gate and delivery-observer seam tests that need the newer Core.

They import Core's DispatchGate types (and, for fan-out batches, ``batch_id``), which the
production, policy and core-r3 pins do not have, so they are collected only where Core
has the seam (see conftest) and never skipped.
"""
from __future__ import annotations

import sqlite3

import pytest


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
        """Fail the critical sink acknowledgment."""
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
        """Fail the critical sink acknowledgment mid-batch."""
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

