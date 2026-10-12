"""Runtime review hardening: callable settlement, run identity, fences, time log."""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from perpetua_core import END, START, MiniGraph, PerpetuaState
from perpetua_core.graph.engine import ConditionalEdge
from orama.graph.admission import AdmissionRequirements
from orama.graph.admission_runtime import AdmissionGraphRunner
from orama.graph.execution_guard import (
    LeaseFenced,
    StepLedger,
    core_start_seam_available,
)
from orama.graph.run_control import RunControl
from tests.test_admission_decision import binding, context, providers

requires_start_seam = pytest.mark.skipif(
    not core_start_seam_available(),
    reason="installed perpetua-core lacks the T2 _before_start seam",
)


def _runner(tmp_path: Path) -> tuple[AdmissionGraphRunner, StepLedger, RunControl]:
    """Build an admission runner, ledger and run control sharing one SQLite store."""
    owner_providers, clock = providers()
    store = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store)
    run_control = RunControl(store_path=store)
    runner = AdmissionGraphRunner(
        binding=binding(),
        providers=owner_providers,
        ledger=ledger,
        run_control=run_control,
        context_from_state=lambda _state: context(run_id="client-run"),
        max_steps=6,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
    )
    return runner, ledger, run_control


async def test_trusted_run_identity_reaches_the_graph_state(tmp_path: Path) -> None:
    """Nodes see the server-minted run id, never the client's metadata run id."""
    runner, ledger, run_control = _runner(tmp_path)
    seen: list[str] = []
    graph = MiniGraph()
    graph.add_node("work", lambda state: seen.append(state.metadata["run_id"]) or {})
    graph.add_edge(START, "work").add_edge("work", END)

    await runner.for_authenticated_principal("control-plane").invoke(
        graph.compile(),
        PerpetuaState(session_id="client-session", metadata={"run_id": "client-meta"}),
    )

    assert seen and seen[0] not in {"client-meta", "client-session"}
    assert run_control.terminal_receipt(seen[0]) is not None
    ledger.close()
    run_control.close()


@requires_start_seam
async def test_successful_router_holds_settle_so_the_run_completes(tmp_path: Path) -> None:
    """Router callables finish their holds; completed work is never reported unknown."""
    runner, ledger, run_control = _runner(tmp_path)
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


def test_legacy_reserve_is_fenced_after_the_run_is_terminal(tmp_path: Path) -> None:
    """A closed run cannot gain charges through the legacy step reserve."""
    store = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store)
    run_control = RunControl(store_path=store)
    run_control.register_run(run_id="r1", owner_principal="p")
    epoch = ledger.open_lease("r1", max_steps=5)
    run_control.record_runtime_terminal(
        run_id="r1", epoch=epoch, outcome="completed", reason="run.completed"
    )
    used = ledger.used("r1")

    with pytest.raises(LeaseFenced):
        ledger.reserve("r1", epoch, 1)
    assert ledger.used("r1") == used
    ledger.close()
    run_control.close()


def test_time_observation_appends_one_anchor_event_not_one_per_boundary(tmp_path: Path) -> None:
    """The high-water row carries rollback state; the event log is not grown per call."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("r1", max_steps=5)
    start = datetime(2026, 10, 12, tzinfo=UTC)
    for tick in range(5):
        ledger.observe_time("r1", epoch, start + timedelta(seconds=tick))

    count = ledger._db.execute(
        "SELECT COUNT(*) FROM accounting_events WHERE run_id = ? AND event_type = 'time_observed'",
        ("r1",),
    ).fetchone()[0]
    assert count == 1
    with pytest.raises(ValueError, match="rollback"):
        ledger.observe_time("r1", epoch, start)
    ledger.close()


def test_api_module_imports_when_core_has_no_gate_seam() -> None:
    """A pre-T1 Core pin still loads the API so it can refuse work safely."""
    import subprocess
    import sys
    import textwrap

    code = textwrap.dedent(
        """
        import importlib.abc, sys
        import perpetua_core.state, perpetua_core.graph.engine
        sys.modules.pop("perpetua_core.graph.gate", None)

        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):
                if name == "perpetua_core.graph.gate":
                    raise ImportError("simulated pre-T1 Core pin")

        sys.meta_path.insert(0, Block())
        import orama.api.server
        from orama.graph.execution_guard import CORE_GATE_AVAILABLE
        assert CORE_GATE_AVAILABLE is False
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


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


@requires_start_seam
async def test_stop_persisted_before_trailing_settlement_is_a_stop_not_a_completion(
    tmp_path: Path,
) -> None:
    """A durable stop that wins over final settlement yields a cancelled receipt."""
    from orama.graph.admission import AdmissionRefused
    from orama.graph.run_control import StopRequest

    runner, ledger, run_control = _runner(tmp_path)
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


@requires_start_seam
async def test_trailing_settlement_runs_off_the_loop_before_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Slow final settlement neither stalls the loop nor races the receipt."""
    runner, ledger, run_control = _runner(tmp_path)
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
