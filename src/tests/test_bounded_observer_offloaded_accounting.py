"""An off-loop callback keeps its event and byte charge until its thread returns.

A thread cannot be interrupted. Cancelling the worker that awaits it only stops the
await: the callback keeps running and keeps holding the event. Releasing the byte
charge (and draining the queue slot) at the moment of cancellation therefore reports
memory as free and a sink as drained while work is still in flight, which is the
over-admission this observer exists to prevent.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest
from perpetua_core import PerpetuaState
from perpetua_core.graph.engine import GraphEvent, GraphObservation

from orama.graph.bounded_observer import BoundedObserver, BoundedObserverConfig, OrderedEvent

POLL_STEP = 0.01
POLL_LIMIT = 2.0


class _GatedThreadSink:
    """A sink that declares itself thread-safe and blocks until its gate opens."""

    runs_off_loop = True

    def __init__(self) -> None:
        """Create the gate and the signal that the call has started."""
        self.started = threading.Event()
        self.gate = threading.Event()
        self.finished = threading.Event()

    def __call__(self, _event: OrderedEvent) -> None:
        """Hold the event inside a worker thread until the test opens the gate."""
        self.started.set()
        self.gate.wait(timeout=5.0)
        self.finished.set()


def _observation() -> GraphObservation:
    """One minimal observation with a non-zero payload size."""
    state = PerpetuaState(session_id="s", scratchpad={"k": "v" * 64})
    return GraphObservation(GraphEvent("node.end", node="a", steps=1), state, delta={"k": "v"})


async def _until(predicate: Any, what: str) -> None:
    """Poll a condition on the loop with a hard ceiling, failing with a description."""
    deadline = time.monotonic() + POLL_LIMIT
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for: {what}")
        await asyncio.sleep(POLL_STEP)


async def _started(sink: _GatedThreadSink) -> None:
    """Wait until the thread is inside the callback."""
    await _until(sink.started.is_set, "off-loop callback to start")


@pytest.mark.asyncio
async def test_worker_cancellation_does_not_release_the_charge_while_the_thread_runs() -> None:
    """Cancelling the worker leaves the byte charge held until the thread returns."""
    observer = BoundedObserver(run_id="run-1")
    sink = _GatedThreadSink()
    observer.register_sink("audit", sink)
    await observer.on_observation(_observation())
    await _started(sink)
    charged = observer.inflight_bytes
    assert charged > 0

    worker = observer._sinks["audit"].worker_task  # noqa: SLF001 - the cancellation under test
    assert worker is not None
    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)

    assert not sink.finished.is_set()
    assert observer.inflight_bytes == charged  # the thread still holds the event

    sink.gate.set()
    await _until(lambda: observer.inflight_bytes == 0, "charge released after the thread returned")


@pytest.mark.asyncio
async def test_the_queue_slot_is_not_drained_until_the_thread_returns() -> None:
    """``queue.join()`` must not report a sink drained while its callback still runs."""
    observer = BoundedObserver(run_id="run-1")
    sink = _GatedThreadSink()
    observer.register_sink("audit", sink)
    await observer.on_observation(_observation())
    await _started(sink)
    reg = observer._sinks["audit"]  # noqa: SLF001
    assert reg.worker_task is not None and reg.queue is not None

    reg.worker_task.cancel()
    await asyncio.gather(reg.worker_task, return_exceptions=True)
    drained = asyncio.ensure_future(reg.queue.join())
    await asyncio.sleep(0.05)
    assert not drained.done()

    sink.gate.set()
    await asyncio.wait_for(drained, timeout=POLL_LIMIT)


@pytest.mark.asyncio
async def test_shutdown_waits_for_the_thread_inside_its_deadline() -> None:
    """A callback that finishes within the grace period leaves the observer healthy."""
    observer = BoundedObserver(run_id="run-1")
    sink = _GatedThreadSink()
    observer.register_sink("audit", sink)
    await observer.on_observation(_observation())
    await _started(sink)
    threading.Timer(0.1, sink.gate.set).start()

    await observer.shutdown(grace_period=2.0)

    assert sink.finished.is_set()
    assert observer.inflight_bytes == 0
    assert observer.healthy()


@pytest.mark.asyncio
async def test_shutdown_records_a_stop_timeout_when_the_thread_outlives_the_deadline() -> None:
    """A thread still running at the deadline is reported, never presented as drained."""
    observer = BoundedObserver(
        run_id="run-1", config=BoundedObserverConfig(stop_grace_period=0.1)
    )
    sink = _GatedThreadSink()
    observer.register_sink("audit", sink)
    await observer.on_observation(_observation())
    await _started(sink)

    started = time.monotonic()
    await observer.shutdown(grace_period=0.2)
    elapsed = time.monotonic() - started

    assert not sink.finished.is_set()
    assert not observer.healthy()
    assert observer.inflight_bytes > 0  # still honestly accounted
    assert elapsed < 1.0  # the deadline is a bound, not a wait-forever

    sink.gate.set()
    await _until(lambda: observer.inflight_bytes == 0, "charge released after the thread returned")
