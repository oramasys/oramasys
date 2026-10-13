"""T2: the admitted-run path drains Core's observations through its delivery authority.

The transport is Core's existing ``run_with_plugins`` (no new Core seam). What this
module pins is the composition: observations reach the delivery, a critical failure
stops the next dispatch, and a durable unknown disposition is written only for an
attempt the ledger itself shows as started and unsettled.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.graph.admission import AdmissionRequirements
from orama.graph.admission_runtime import AdmissionGraphRunner, AdmissionRefused
from orama.graph.bounded_observer import BoundedObserver, OrderedEvent
from orama.graph.execution_guard import StepLedger
from orama.graph.run_control import RunControl
from tests.test_admission_decision import binding, context, providers

import pytest


def _runner(tmp_path: Path, factory) -> tuple[AdmissionGraphRunner, StepLedger, RunControl, Path]:
    """Build the production runner over one shared store with a per-run delivery."""
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
        max_steps=8,
        requirements=AdmissionRequirements.for_effects(
            model_dispatch=True, endpoint_purposes=("model_egress",)
        ),
        clock=clock,
        run_delivery_factory=factory,
    )
    return runner, ledger, run_control, store_path


def _unknown_rows(store_path: Path) -> list[tuple[str, str, int, str]]:
    """Read the durable unknown dispositions straight from the shared store."""
    with sqlite3.connect(store_path) as db:
        return db.execute(
            "SELECT attempt_id, hold_id, epoch, cause FROM unknown_dispositions ORDER BY attempt_id"
        ).fetchall()


def _node_graph(ran: list[str]) -> object:
    """Two node-boundary attempts, so a failure on the first must stop the second."""
    graph = MiniGraph()
    graph.add_node("a", lambda state: ran.append("a") or {"scratchpad": {"a": True}})
    graph.add_node("b", lambda state: ran.append("b") or {"scratchpad": {"b": True}})
    graph.add_edge(START, "a").add_edge("a", "b").add_edge("b", END)
    return graph.compile()


def _router_graph(ran: list[str]) -> object:
    """A router boundary: its attempt stays held until the next boundary settles it."""
    graph = MiniGraph()
    graph.add_node("a", lambda state: ran.append("a") or {"scratchpad": {"a": True}})
    graph.add_node("b", lambda state: ran.append("b") or {"scratchpad": {"b": True}})
    graph.add_edge(START, "a").add_edge("a", lambda state: "b").add_edge("b", END)
    return graph.compile()


class _Recording:
    """A healthy delivery that records the event kinds Core's real run emits."""

    def __init__(self) -> None:
        """Start with no recorded observations."""
        self.kinds: list[str] = []

    def healthy(self) -> bool:
        """Stay healthy while observations are accepted."""
        return True

    async def on_observation(self, observation: object) -> None:
        """Record the neutral event kind."""
        self.kinds.append(str(observation.event.kind))  # type: ignore[attr-defined]


async def test_admitted_runner_drains_core_observations_through_its_delivery(
    tmp_path: Path,
) -> None:
    """Observations reach the delivery authority on the production path."""
    seen_run_ids: list[str] = []
    delivery = _Recording()

    def factory(run_id: str) -> _Recording:
        """Receive the server-minted run identity, never a client-supplied one."""
        seen_run_ids.append(run_id)
        return delivery

    ran: list[str] = []
    runner, ledger, run_control, _ = _runner(tmp_path, factory)

    await runner.for_authenticated_principal("control-plane").invoke(
        _node_graph(ran), PerpetuaState(session_id="run-1")
    )

    assert ran == ["a", "b"]
    assert delivery.kinds[0] == "edge.selected" and delivery.kinds[-1] == "done"
    assert delivery.kinds.count("node.end") == 2
    assert len(seen_run_ids) == 1 and seen_run_ids[0] not in ("", "client-run")
    ledger.close()
    run_control.close()


async def test_critical_failure_stops_the_next_dispatch_and_records_a_delivery_terminal(
    tmp_path: Path,
) -> None:
    """A rejected persistence boundary prevents the second node and says why."""
    ran: list[str] = []
    observers: list[BoundedObserver] = []

    async def failing_sink(event: OrderedEvent) -> None:
        """Reject the first node-end observation."""
        if event.observation.event.kind == "node.end":
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
            _node_graph(ran), PerpetuaState(session_id="run-1")
        )

    run_id = observers[0].run_id
    receipt = run_control.terminal_receipt(run_id)
    assert ran == ["a"]  # the second dispatch never started
    assert receipt is not None and receipt.reason == "delivery.critical_failure"
    # The failed observation belongs to an attempt that already settled, so there is
    # nothing unsettled to name and no identity may be invented for it.
    assert _unknown_rows(store_path) == []
    ledger.close()
    run_control.close()


async def test_an_observing_delivery_on_a_graph_without_observation_is_refused(
    tmp_path: Path,
) -> None:
    """Fail closed: an observing delivery must never be silently skipped."""

    class GateOnly:
        """A graph exposing only the gate-capable surface, no observation stream."""

        async def ainvoke(self, state: object, *, gate: object) -> object:
            """Would run without delivery if the runner allowed it."""
            raise AssertionError("must not run unobserved")

    runner, ledger, run_control, _ = _runner(tmp_path, lambda run_id: _Recording())

    with pytest.raises(AdmissionRefused, match="observation"):
        await runner.for_authenticated_principal("control-plane").invoke(
            GateOnly(), PerpetuaState(session_id="run-1")
        )
    ledger.close()
    run_control.close()


def _rows(store_path: Path, table: str) -> int:
    """Count rows in one shared-store table."""
    with sqlite3.connect(store_path) as db:
        return int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


async def test_a_binding_failure_still_records_a_terminal_for_the_run(tmp_path: Path) -> None:
    """Binding happens inside the guarded lifecycle, so a refusal cannot strand a run."""
    seen: list[str] = []

    def factory(run_id: str) -> BoundedObserver:
        """Return an observer that is already bound, as a shared instance would be."""
        seen.append(run_id)
        observer = BoundedObserver(run_id=run_id)
        observer.bind_authority(identity_source=lambda: [], on_unknown=lambda d: None)
        return observer

    runner, ledger, run_control, _ = _runner(tmp_path, factory)
    with pytest.raises(RuntimeError, match="already bound"):
        await runner.for_authenticated_principal("control-plane").invoke(
            _node_graph([]), PerpetuaState(session_id="run-1")
        )

    receipt = run_control.terminal_receipt(seen[0])
    assert receipt is not None and receipt.outcome == "unknown"
    ledger.close()
    run_control.close()


async def test_a_core_without_the_plugin_runner_is_refused_before_any_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An undrainable Core is an admission refusal: no owner, no lease, no terminal."""
    monkeypatch.setitem(sys.modules, "perpetua_core.graph.plugins.observer", None)
    runner, ledger, run_control, store_path = _runner(tmp_path, lambda run_id: _Recording())

    with pytest.raises(AdmissionRefused, match="delivery_core_unsupported"):
        await runner.for_authenticated_principal("control-plane").invoke(
            _node_graph([]), PerpetuaState(session_id="run-1")
        )

    assert _rows(store_path, "run_owners") == 0
    assert _rows(store_path, "terminal_receipts") == 0
    ledger.close()
    run_control.close()


class _Quiescing(_Recording):
    """A delivery that records when it was shut down relative to the terminal receipt."""

    def __init__(self, run_control: RunControl, *, fail_shutdown: bool = False) -> None:
        """Remember the run control used to observe terminal-receipt ordering."""
        super().__init__()
        self.run_control = run_control
        self.run_id = ""
        self.fail_shutdown = fail_shutdown
        self.shutdowns: list[bool] = []

    async def shutdown(self) -> None:
        """Record whether a terminal receipt already existed when shutdown ran."""
        self.shutdowns.append(self.run_control.terminal_receipt(self.run_id) is not None)
        if self.fail_shutdown:
            raise OSError("sink close failed")


async def test_an_observing_delivery_is_shut_down_after_a_clean_run(tmp_path: Path) -> None:
    """Workers and callbacks are released once per run, before the terminal is recorded."""
    holder: dict[str, _Quiescing] = {}
    runner, ledger, run_control, _ = _runner(tmp_path, lambda run_id: holder["d"])
    holder["d"] = _Quiescing(run_control)
    runner.run_delivery_factory = lambda run_id: _bind_run(holder["d"], run_id)

    await runner.for_authenticated_principal("control-plane").invoke(
        _node_graph([]), PerpetuaState(session_id="run-1")
    )

    assert holder["d"].shutdowns == [False]
    ledger.close()
    run_control.close()


def _bind_run(delivery: _Quiescing, run_id: str) -> _Quiescing:
    """Tell the test double which run it serves."""
    delivery.run_id = run_id
    return delivery


async def test_shutdown_precedes_the_terminal_on_failure_and_never_masks_it(
    tmp_path: Path,
) -> None:
    """A failing close is suppressed so the original failure stays primary."""
    holder: dict[str, _Quiescing] = {}

    async def failing_sink(event: OrderedEvent) -> None:
        """Reject the first node-end observation."""
        if event.observation.event.kind == "node.end":
            raise RuntimeError("persistence unavailable")

    class Failing(BoundedObserver):
        """A real bounded observer that also reports shutdown ordering and then fails."""

        def __init__(self, run_control: RunControl, run_id: str) -> None:
            """Own one critical sink that rejects the first node-end observation."""
            super().__init__(run_id=run_id)
            self.run_control = run_control
            self.shutdowns: list[bool] = []
            self.register_sink("audit", failing_sink, critical=True)

        async def shutdown(self, grace_period: float | None = None) -> None:
            """Record whether a terminal already existed, then fail like a sink close can."""
            self.shutdowns.append(self.run_control.terminal_receipt(self.run_id) is not None)
            raise OSError("sink close failed")

    runner, ledger, run_control, _ = _runner(tmp_path, lambda run_id: holder["d"])
    runner.run_delivery_factory = lambda run_id: holder.setdefault("d", Failing(run_control, run_id))

    with pytest.raises((RuntimeError, BaseExceptionGroup)):
        await runner.for_authenticated_principal("control-plane").invoke(
            _node_graph([]), PerpetuaState(session_id="run-1")
        )

    receipt = run_control.terminal_receipt(holder["d"].run_id)
    assert holder["d"].shutdowns == [False]  # shut down before the terminal existed
    assert receipt is not None and receipt.reason == "delivery.critical_failure"
    ledger.close()
    run_control.close()


async def test_a_clean_run_whose_delivery_cannot_shut_down_is_not_reported_complete(
    tmp_path: Path,
) -> None:
    """Un-quiesced delivery is uncertain state, so it must not look like a clean finish."""
    holder: dict[str, _Quiescing] = {}
    runner, ledger, run_control, _ = _runner(tmp_path, lambda run_id: holder["d"])
    holder["d"] = _Quiescing(run_control, fail_shutdown=True)
    runner.run_delivery_factory = lambda run_id: _bind_run(holder["d"], run_id)

    with pytest.raises(OSError, match="sink close failed"):
        await runner.for_authenticated_principal("control-plane").invoke(
            _node_graph([]), PerpetuaState(session_id="run-1")
        )

    receipt = run_control.terminal_receipt(holder["d"].run_id)
    assert receipt is not None and receipt.outcome == "unknown"
    ledger.close()
    run_control.close()
