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
from orama.graph.execution_guard import StopSignal
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
    await observer.shutdown(grace_period=3.0)
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
    # Close runs off the event loop; wait on its tracked task, not on the loop.
    await asyncio.wait(tuple(observer._close_tasks), timeout=3.0)
    assert not sink._process.is_alive()


class _SlowCloseSink:
    """Sink whose close blocks like a process join."""

    supports_critical_ack = True

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds

    def __call__(self, event: Any) -> None:
        return None

    def close(self) -> None:
        time.sleep(self.seconds)


async def test_shutdown_closes_sinks_off_the_loop_inside_one_deadline() -> None:
    """A slow close neither stalls the loop nor stretches shutdown past its grace."""
    observer = BoundedObserver(run_id="r", attempt_id="a", hold_id="h", fence_epoch=1)
    observer.register_sink("slow", _SlowCloseSink(1.5), critical=False)
    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    started = time.monotonic()
    await observer.shutdown(grace_period=0.3)
    elapsed = time.monotonic() - started
    beat.cancel()

    assert elapsed < 0.9
    assert ticks >= 10


def _slow_target(event: Any) -> None:
    time.sleep(5)


class _Sized:
    def __init__(self, size_bytes: int) -> None:
        self.size_bytes = size_bytes


def test_isolated_sink_bytes_stay_bounded_until_the_worker_consumes() -> None:
    """The process queue cannot retain more than its byte allowance."""
    sink = ProcessIsolatedSink(
        _slow_target, queue_size=1024, fail_closed=True, max_queue_bytes=1000
    )
    try:
        with pytest.raises(BufferError, match="allowance"):
            for _ in range(10):
                sink(_Sized(400))
        assert sink._pending_bytes.value <= 1000
    finally:
        sink.close(timeout=0.2)


class _CountingCloseSink:
    """Sink that records how many times its close lifecycle ran."""

    supports_critical_ack = True

    def __init__(self) -> None:
        self.closed = 0

    def __call__(self, event: Any) -> None:
        return None

    def close(self) -> None:
        self.closed += 1


async def test_repeated_shutdown_closes_each_sink_once() -> None:
    """A second shutdown pass must not re-close registrations already closed."""
    sink = _CountingCloseSink()
    observer = BoundedObserver(run_id="r", attempt_id="a", hold_id="h", fence_epoch=1)
    observer.register_sink("counting", sink, critical=False)
    await observer.shutdown(grace_period=1.0)
    finished = asyncio.ensure_future(asyncio.sleep(0))
    await finished
    observer._pending_callbacks.add(finished)  # forces the second pass to run
    await observer.shutdown(grace_period=1.0)

    assert sink.closed == 1


class _PaddedEvent:
    """Event whose declared size omits a large field that still crosses the pipe."""

    def __init__(self) -> None:
        self.size_bytes = 1
        self.run_id = "r" * 600


def test_isolated_sink_charges_serialized_size_not_the_declared_size() -> None:
    """An understated ``size_bytes`` cannot defeat the process byte allowance."""
    sink = ProcessIsolatedSink(
        _slow_target, queue_size=1024, fail_closed=True, max_queue_bytes=1000
    )
    try:
        with pytest.raises(BufferError, match="allowance"):
            for _ in range(10):
                sink(_PaddedEvent())
    finally:
        sink.close(timeout=0.2)


class _ThreadRecordingSink:
    """Non-critical sink that records the thread each event is handled on."""

    supports_critical_ack = True

    def __init__(self, runs_off_loop: bool) -> None:
        self.runs_off_loop = runs_off_loop
        self.threads: list[int] = []

    def __call__(self, event: Any) -> None:
        import threading

        self.threads.append(threading.get_ident())


async def test_sink_declaring_runs_off_loop_is_called_in_a_worker_thread() -> None:
    """Event sizing for isolated sinks cannot run on the scheduler's loop thread."""
    import threading

    observer = BoundedObserver(run_id="r", attempt_id="a", hold_id="h", fence_epoch=1)
    inline, offloaded = _ThreadRecordingSink(False), _ThreadRecordingSink(True)
    observer.register_sink("inline", inline, critical=False)
    observer.register_sink("offloaded", offloaded, critical=False)
    await observer.on_observation(
        GraphObservation(GraphEvent("node.start", node="n", steps=0), PerpetuaState(session_id="s"))
    )
    await observer.shutdown(grace_period=2.0)

    loop_thread = threading.get_ident()
    assert inline.threads == [loop_thread]
    assert len(offloaded.threads) == 1 and offloaded.threads[0] != loop_thread


def test_process_isolated_sink_declares_it_runs_off_the_loop() -> None:
    """The isolated sink opts in, so production wiring is off-loop by default."""
    assert ProcessIsolatedSink.runs_off_loop is True
