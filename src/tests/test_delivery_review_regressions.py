"""Delivery review regressions: acknowledgement and task ownership."""
from __future__ import annotations

import asyncio

import pytest

from orama.graph.bounded_observer import BoundedObserver, BoundedObserverConfig
from orama.graph.sink_isolation import ProcessIsolatedSink
from tests.test_delivery_hardening import dummy_target, make_obs


async def test_enqueue_only_process_sink_cannot_acknowledge_critical_delivery() -> None:
    """Enqueue acceptance is not proof of the worker's persistence boundary."""
    sink = ProcessIsolatedSink(dummy_target)
    observer = BoundedObserver(run_id="critical-process")
    try:
        with pytest.raises(ValueError, match="acknowledg"):
            observer.register_sink("critical", sink, critical=True)
        assert not sink._started
        assert sink._queue is None
        assert sink._error_queue is None
        assert not observer._sinks
    finally:
        sink.close()
        await observer.shutdown()


async def test_timed_out_callback_remains_owned_until_it_actually_finishes() -> None:
    """Cancellation requested does not mean a cancellation-suppressing task stopped."""
    observer = BoundedObserver(
        run_id="timeout-owned",
        config=BoundedObserverConfig(critical_ack_timeout=0.01),
    )
    release = asyncio.Event()
    running: list[asyncio.Task[object]] = []

    async def sink(_: object) -> None:
        task = asyncio.current_task()
        assert task is not None
        running.append(task)
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue

    observer.register_sink("critical", sink, critical=True)
    try:
        with pytest.raises(TimeoutError):
            await observer.on_observation(make_obs("timeout-owned"))
        assert len(running) == 1
        assert running[0] in observer._pending_callbacks
        await observer.shutdown(grace_period=0.01)
        assert running[0] in observer._pending_callbacks
        assert not running[0].done()
        assert not observer.healthy()
    finally:
        release.set()
        await asyncio.gather(*running)
        await asyncio.sleep(0)
        await observer.shutdown(grace_period=0.01)
    assert not observer._pending_callbacks


async def test_replacing_sink_retains_old_worker_until_completion() -> None:
    """A replaced registration cannot discard ownership of its live callback."""
    observer = BoundedObserver(run_id="replaced-owned")
    started = asyncio.Event()
    release = asyncio.Event()

    async def sink(_: object) -> None:
        started.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue

    observer.register_sink("sink", sink)
    await observer.on_observation(make_obs("replaced-owned"))
    await asyncio.wait_for(started.wait(), timeout=1)
    old = observer._sinks["sink"].worker_task
    assert old is not None
    try:
        observer.register_sink("sink", lambda _: None)
        assert old in observer._pending_callbacks
        assert not old.done()
    finally:
        release.set()
        await asyncio.wait_for(old, timeout=1)
        await observer.shutdown(grace_period=0.01)
    assert old not in observer._pending_callbacks


def test_closing_an_unstarted_sink_allocates_no_ipc_and_refuses_restart() -> None:
    """Rejected or closed registrations do not allocate multiprocessing resources."""
    sink = ProcessIsolatedSink(dummy_target)
    sink.close()
    sink.close()
    assert sink._queue is None
    assert sink._error_queue is None
    with pytest.raises(RuntimeError, match="closed"):
        sink.start()
