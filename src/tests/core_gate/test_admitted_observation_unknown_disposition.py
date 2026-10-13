"""T2: a critical delivery failure durably names a started, unsettled attempt.

Needs the Core revision with the start seam: without it no start marker is ever
written, so nothing can be both held and started (see conftest capability bands).
"""

from __future__ import annotations

import pytest
from pathlib import Path

from perpetua_core import PerpetuaState
from orama.graph.bounded_observer import BoundedObserver, OrderedEvent
from tests.core_gate.test_admitted_observation_delivery import (
    _router_graph,
    _runner,
    _unknown_rows,
)


async def test_critical_failure_names_the_started_unsettled_attempt_durably(
    tmp_path: Path,
) -> None:
    """A router attempt is held at the failing observation: one identity-valid record."""
    ran: list[str] = []
    observers: list[BoundedObserver] = []

    async def failing_sink(event: OrderedEvent) -> None:
        """Reject the observation delivered while the router attempt is still held."""
        if event.observation.event.kind == "edge.selected" and event.observation.event.node == "a":
            raise RuntimeError("persistence unavailable")

    def factory(run_id: str) -> BoundedObserver:
        """Give each run its own observer with one critical sink."""
        observer = BoundedObserver(run_id=run_id)
        observer.register_sink("audit", failing_sink, critical=True)
        observers.append(observer)
        return observer

    runner, ledger, run_control, store_path = _runner(tmp_path, factory)
    with pytest.raises((RuntimeError, BaseExceptionGroup)):
        await runner.for_authenticated_principal("control-plane").invoke(
            _router_graph(ran), PerpetuaState(session_id="run-1")
        )

    run_id = observers[0].run_id
    rows = _unknown_rows(store_path)
    assert ran == ["a"]
    assert len(rows) == 1
    attempt_id, hold_id, epoch, cause = rows[0]
    assert cause == "critical_delivery_failure"
    assert epoch >= 1 and hold_id and attempt_id
    assert ledger.hold_state(run_id, attempt_id) == "unknown"
    assert [d.attempt_id for d in observers[0].unknown_dispositions] == [attempt_id]
    ledger.close()
    run_control.close()
