"""Callable-settlement runtime behavior, collected only where Core has the start seam."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from perpetua_core import END, START, MiniGraph, PerpetuaState
from perpetua_core.graph.engine import ConditionalEdge
from tests.core_gate.support import runner_with_stores


async def test_successful_router_holds_settle_so_the_run_completes(tmp_path: Path) -> None:
    """Router callables finish their holds; completed work is never reported unknown."""
    runner, ledger, run_control = runner_with_stores(tmp_path)
    seen: list[str] = []
    graph = MiniGraph()

    def work(state: PerpetuaState) -> dict[str, Any]:
        """Record the trusted run id the node observed."""
        seen.append(state.metadata["run_id"])
        return {}

    graph.add_node("a", work)
    graph.add_edge(START, ConditionalEdge(lambda state: "a", ("a",)))
    graph.add_edge("a", ConditionalEdge(lambda state: END, (END,)))

    await runner.for_authenticated_principal("control-plane").invoke(
        graph.compile(), PerpetuaState(session_id="s")
    )

    receipt = run_control.terminal_receipt(seen[0])
    assert receipt is not None and receipt.outcome == "completed"
    ledger.close()
    run_control.close()


def _trailing_router_graph(on_trailing: Any) -> MiniGraph:
    """Build START -> node -> trailing router whose callable runs ``on_trailing``."""
    graph = MiniGraph()
    graph.add_node("a", lambda state: {})
    graph.add_edge(START, "a")

    def trailing(state: PerpetuaState) -> str:
        """Run the supplied hook, then resolve the route to END."""
        on_trailing(state)
        return END

    graph.add_edge("a", ConditionalEdge(trailing, (END,)))
    return graph


async def test_stop_persisted_before_trailing_settlement_is_a_stop_not_a_completion(
    tmp_path: Path,
) -> None:
    """A durable stop that wins over final settlement yields a cancelled receipt."""
    from orama.graph.admission import AdmissionRefused
    from orama.graph.run_control import StopRequest

    runner, ledger, run_control = runner_with_stores(tmp_path)
    run_ids: list[str] = []

    def request_stop(state: PerpetuaState) -> None:
        """Persist an owner-authorized stop from inside the trailing callable."""
        run_id = state.metadata["run_id"]
        run_ids.append(run_id)
        run_control.request_stop(
            StopRequest(run_id=run_id, principal="control-plane", reason="operator_request")
        )

    graph = _trailing_router_graph(request_stop)
    with pytest.raises(AdmissionRefused, match="stop_requested"):
        await runner.for_authenticated_principal("control-plane").invoke(
            graph.compile(), PerpetuaState(session_id="s")
        )

    receipt = run_control.terminal_receipt(run_ids[0])
    # The stop wins the transaction order, so the trailing hold cannot be
    # settled; unresolved holds conservatively force ``unknown`` while the
    # receipt still records the stop as the reason.
    assert receipt is not None
    assert receipt.reason == "operator_request"
    assert receipt.outcome == "unknown"
    ledger.close()
    run_control.close()


async def test_trailing_settlement_runs_off_the_loop_before_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Slow final settlement neither stalls the loop nor races the receipt."""
    runner, ledger, run_control = runner_with_stores(tmp_path)
    original = ledger.settle_commit
    settled: list[str] = []

    def slow_settle(run_id: str, attempt_id: str, digest: str) -> bool:
        """Settle after a blocking delay to prove the loop stays responsive."""
        time.sleep(0.3)
        settled.append(attempt_id)
        return original(run_id, attempt_id, digest)

    monkeypatch.setattr(ledger, "settle_commit", slow_settle)
    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    seen: list[str] = []
    graph = _trailing_router_graph(lambda state: seen.append(state.metadata["run_id"]))
    beat = asyncio.create_task(heartbeat())
    await runner.for_authenticated_principal("control-plane").invoke(
        graph.compile(), PerpetuaState(session_id="s")
    )
    beat.cancel()

    receipt = run_control.terminal_receipt(seen[0])
    assert receipt is not None and receipt.outcome == "completed"
    assert any(a.startswith("router::") for a in settled)
    assert ticks >= 10
    ledger.close()
    run_control.close()
