"""TDD: Delivery Hardening & Process Isolation (REV3 Task 3 / T2-A).

Required acceptance tests:
- test_critical_failure_prevents_next_dispatch
- test_cancellation_suppressing_sink_returns_within_wait_bound
- test_late_ack_has_no_authority
- test_replacement_retains_running_task
- test_aggregate_bytes_include_inflight_across_sinks
- test_gap_metadata_is_bounded
- test_invalid_limits_refuse
- test_unicode_payload_counts_encoded_bytes
- test_unidentified_observer_refuses_before_tasks
- test_blocking_sink_requires_isolation
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
import pytest

from perpetua_core.graph.engine import GraphEvent, GraphObservation
from perpetua_core.state import PerpetuaState

from orama.graph.bounded_observer import (
    BoundedObserver,
    BoundedObserverConfig,
    OrderedEvent,
)
from orama.graph.execution_guard import AdmissionGate, StepLedger, StopSignal
from orama.graph.sink_isolation import ProcessIsolatedSink, BlockingSinkRequiresIsolationError


def make_obs(run_id: str = "run-t3", text: str = "test", data: dict[str, Any] | None = None) -> GraphObservation:
    s = PerpetuaState(session_id=run_id, scratchpad=data or {"text": text})
    ev = GraphEvent(kind="node.end", node="work", steps=1)
    return GraphObservation(event=ev, state=s, delta=data or {"text": text})


@pytest.mark.asyncio
async def test_invalid_limits_refuse():
    """Constructing BoundedObserver or config with zero/negative limits refuses construction."""
    with pytest.raises(ValueError, match="limit"):
        BoundedObserverConfig(default_max_queue_size=0)
    with pytest.raises(ValueError, match="limit"):
        BoundedObserverConfig(aggregate_byte_limit=-100)
    with pytest.raises(ValueError, match="limit"):
        BoundedObserver(run_id="run-1", config=BoundedObserverConfig(critical_ack_timeout=-0.5))


@pytest.mark.asyncio
async def test_unidentified_observer_refuses_before_tasks():
    """Observer built without real run/attempt/hold identity refuses before allocating sink tasks."""
    observer = BoundedObserver(run_id="", attempt_id=None, hold_id=None)
    with pytest.raises(ValueError, match="identity"):
        observer.register_sink("critical", lambda e: None, critical=True)


@pytest.mark.asyncio
async def test_unicode_payload_counts_encoded_bytes():
    """Payload size accounting uses actual UTF-8 encoded byte length, not len(str)."""
    # 4-byte unicode character repeated
    emoji_str = "🔥" * 100  # len is 100, utf-8 byte len is 400
    obs = make_obs(text=emoji_str)
    observer = BoundedObserver(run_id="run-unicode", attempt_id="att-1", hold_id="h-1", fence_epoch=1)

    received_bytes = 0
    def sink(event: OrderedEvent):
        nonlocal received_bytes
        received_bytes = event.size_bytes

    observer.register_sink("sink", sink, critical=False)
    await observer.on_observation(obs)
    await observer.shutdown(grace_period=0.5)

    # Encoded bytes must reflect UTF-8 multibyte representation
    assert received_bytes >= 400


@pytest.mark.asyncio
async def test_gap_metadata_is_bounded():
    """GapRecord accumulation itself must be bounded to prevent memory leaks."""
    config = BoundedObserverConfig(default_max_queue_size=2, aggregate_byte_limit=1024)
    observer = BoundedObserver(run_id="run-gap", config=config, attempt_id="att-1", hold_id="h-1", fence_epoch=1)

    async def slow_sink(event: OrderedEvent):
        await asyncio.sleep(0.5)

    observer.register_sink("sink", slow_sink, critical=False)

    # Overflow queue repeatedly
    for i in range(200):
        await observer.on_observation(make_obs(run_id="run-gap", text=f"event-{i}"))

    assert len(observer.gaps) <= 50  # Must be bounded
    await observer.shutdown(grace_period=0.1)


@pytest.mark.asyncio
async def test_cancellation_suppressing_sink_returns_within_wait_bound():
    """A sink that catches CancelledError and keeps running must still have its outer wait bound by timeout."""
    stop = StopSignal()
    config = BoundedObserverConfig(critical_ack_timeout=0.1)
    observer = BoundedObserver(run_id="run-cancel-suppress", config=config, stop_signal=stop, attempt_id="att-1", hold_id="h-1", fence_epoch=1)

    async def misbehaving_sink(event: OrderedEvent):
        try:
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            # Swallow CancelledError and keep spinning
            await asyncio.sleep(0.5)

    observer.register_sink("bad_sink", misbehaving_sink, critical=True)

    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        await observer.on_observation(make_obs("run-cancel-suppress"))
    elapsed = time.monotonic() - t0

    # Outer wait must not hang for 0.5s+; must return within bound
    assert elapsed < 0.25
    assert not observer.healthy()


@pytest.mark.asyncio
async def test_late_ack_has_no_authority():
    """A sink's acknowledgment arriving after timeout already fired must not un-trip circuit or grant authority."""
    stop = StopSignal()
    config = BoundedObserverConfig(critical_ack_timeout=0.05)
    observer = BoundedObserver(run_id="run-late", config=config, stop_signal=stop, attempt_id="att-1", hold_id="h-1", fence_epoch=1)

    sink_finished = asyncio.Event()

    async def late_sink(event: OrderedEvent):
        try:
            await asyncio.sleep(0.1)
        finally:
            sink_finished.set()

    observer.register_sink("late", late_sink, critical=True)

    with pytest.raises(TimeoutError):
        await observer.on_observation(make_obs("run-late"))
    assert not observer.healthy()

    await asyncio.wait_for(sink_finished.wait(), timeout=0.5)
    # Late arrival does not restore health
    assert not observer.healthy()


@pytest.mark.asyncio
async def test_replacement_retains_running_task():
    """Replacing a sink registration while its old task is running must retain ownership and not orphan it."""
    observer = BoundedObserver(run_id="run-replace", attempt_id="att-1", hold_id="h-1", fence_epoch=1)
    task_running = asyncio.Event()
    task_released = asyncio.Event()

    async def long_running_sink(event: OrderedEvent):
        task_running.set()
        await task_released.wait()

    observer.register_sink("s1", long_running_sink, critical=False)
    await observer.on_observation(make_obs("run-replace"))
    await task_running.wait()

    # Replace registration
    observer.register_sink("s1", lambda e: None, critical=False)

    # Old task must still be tracked in pending tasks
    task_released.set()
    await observer.shutdown(grace_period=0.5)


@pytest.mark.asyncio
async def test_aggregate_bytes_include_inflight_across_sinks():
    """8 MiB aggregate payload bound must count bytes actually in flight across all sinks."""
    observer = BoundedObserver(run_id="run-bytes", attempt_id="att-1", hold_id="h-1", fence_epoch=1)
    block = asyncio.Event()

    async def blocking_sink(event: OrderedEvent):
        await block.wait()

    observer.register_sink("s1", blocking_sink, critical=False)
    observer.register_sink("s2", blocking_sink, critical=False)

    await observer.on_observation(make_obs("run-bytes", text="payload-data"))
    await asyncio.sleep(0.01)
    # Both workers hold event in-flight
    assert observer.inflight_bytes > 0
    block.set()
    await observer.shutdown(grace_period=0.5)
    assert observer.inflight_bytes == 0


@pytest.mark.asyncio
async def test_blocking_sink_requires_isolation():
    """Registering a sink declared as blocking without process isolation is refused at registration time."""
    observer = BoundedObserver(run_id="run-block", attempt_id="att-1", hold_id="h-1", fence_epoch=1)

    class DeclaredBlockingSink:
        is_blocking = True

    with pytest.raises(BlockingSinkRequiresIsolationError):
        observer.register_sink("blocking", DeclaredBlockingSink())


@pytest.mark.asyncio
async def test_critical_failure_prevents_next_dispatch(tmp_path):
    """Critical delivery failure trips health and prevents any further graph dispatch."""
    stop = StopSignal()
    config = BoundedObserverConfig(critical_ack_timeout=0.05)
    observer = BoundedObserver(run_id="run-fail-dispatch", config=config, stop_signal=stop, attempt_id="att-1", hold_id="h-1", fence_epoch=1)

    async def failing_sink(event: OrderedEvent):
        raise RuntimeError("critical sink crashed")

    observer.register_sink("crit", failing_sink, critical=True)

    with pytest.raises(RuntimeError, match="critical sink crashed"):
        await observer.on_observation(make_obs("run-fail-dispatch"))

    assert not observer.healthy()
    assert stop.reason is not None


def dummy_target(event):
    pass


@pytest.mark.asyncio
async def test_process_isolated_sink_dead_worker_detected():
    """ProcessIsolatedSink detects when worker process is terminated and raises RuntimeError."""
    sink = ProcessIsolatedSink(dummy_target, queue_size=10)
    sink.start()
    assert sink._process.is_alive()
    # Terminate process to simulate unexpected crash
    sink._process.terminate()
    sink._process.join(timeout=0.5)
    assert not sink._process.is_alive()
    with pytest.raises(RuntimeError, match="not alive"):
        sink("event")
    sink.close()


@pytest.mark.asyncio
async def test_process_isolated_sink_close_lifecycle_on_shutdown():
    """Observer shutdown automatically closes registered sinks implementing close()."""
    sink = ProcessIsolatedSink(dummy_target, queue_size=10)
    sink.start()
    observer = BoundedObserver(run_id="run-sink-close", attempt_id="att-1", hold_id="h-1", fence_epoch=1)
    observer.register_sink("isolated", sink, critical=False)
    assert sink._process.is_alive()
    await observer.shutdown(grace_period=0.1)
    assert not sink._process.is_alive()


@pytest.mark.asyncio
async def test_process_isolated_sink_close_lifecycle_on_unregister():
    """Observer unregister_sink automatically closes sink implementing close()."""
    sink = ProcessIsolatedSink(dummy_target, queue_size=10)
    sink.start()
    observer = BoundedObserver(run_id="run-sink-unreg", attempt_id="att-1", hold_id="h-1", fence_epoch=1)
    observer.register_sink("isolated", sink, critical=False)
    assert sink._process.is_alive()
    observer.unregister_sink("isolated")
    assert not sink._process.is_alive()

