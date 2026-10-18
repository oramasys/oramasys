"""REV3 Batch 4 / Stream B: Bounded Observer, delivery health, and cooperative stop tests.

Named acceptance tests per CONTRACT-DURABLE-HITL-EFFECTS.md and 2026-10-11-rev3-t2-parallel-streams-plan.md:
- Task B1: Bounded non-blocking delivery, mutation isolation, ordering, gap records.
- Task B2: Critical-sink acknowledgment, failure mapping to unknown disposition, circuit closure.
- Task B3: Cooperative stop, bounded grace periods, honest termination reporting, authority fencing.
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
    UnknownDisposition,
)
from orama.graph import execution_guard
from orama.graph.execution_guard import StopSignal


def make_obs(run_id: str, kind: str = "node.end", node: str = "work", data: dict[str, Any] | None = None) -> GraphObservation:
    """Test helper: make obs."""
    s = PerpetuaState(session_id=run_id, scratchpad=data or {"count": 1})
    ev = GraphEvent(kind=kind, node=node, steps=1)
    return GraphObservation(event=ev, state=s, delta=data or {"count": 1})


# ==============================================================================
# Task B1: Bounded non-blocking delivery
# ==============================================================================

@pytest.mark.asyncio
async def test_slow_telemetry_does_not_delay_node_dispatch():
    """Slow non-critical sinks must never block on_observation dispatch."""
    observer = BoundedObserver(run_id="run-b1")
    slow_done = asyncio.Event()

    async def slow_sink(event: OrderedEvent) -> None:
        """Test helper: slow sink."""
        await asyncio.sleep(0.5)
        slow_done.set()

    observer.register_sink("telemetry", slow_sink, critical=False)

    obs = make_obs("run-b1")
    t0 = time.monotonic()
    await observer.on_observation(obs)
    elapsed = time.monotonic() - t0

    # Dispatch to bounded observer must be near-instantaneous (well below 0.1s)
    assert elapsed < 0.1
    assert not slow_done.is_set()

    # Wait for the background worker to finish
    await observer.shutdown(grace_period=1.0)
    assert slow_done.is_set()


@pytest.mark.asyncio
async def test_ordered_event_identity_preserved_end_to_end():
    """Events must maintain ordered sequence identities (run_id, sequence)."""
    observer = BoundedObserver(run_id="run-b1-order")
    received: list[tuple[str, int]] = []

    def sink(event: OrderedEvent) -> None:
        """Test helper: sink."""
        received.append((event.run_id, event.sequence))

    observer.register_sink("order_sink", sink, critical=False)

    for i in range(5):
        await observer.on_observation(make_obs("run-b1-order", node=f"node_{i}"))

    await observer.shutdown(grace_period=1.0)

    assert len(received) == 5
    assert received == [
        ("run-b1-order", 0),
        ("run-b1-order", 1),
        ("run-b1-order", 2),
        ("run-b1-order", 3),
        ("run-b1-order", 4),
    ]


@pytest.mark.asyncio
async def test_mutation_isolation_between_sinks():
    """One sink mutating its observed payload must not corrupt other sinks or original."""
    observer = BoundedObserver(run_id="run-b1-iso")
    seen_by_sink2: list[dict[str, Any]] = []

    def mutating_sink(event: OrderedEvent) -> None:
        """Test helper: mutating sink."""
        event.observation.state.scratchpad["count"] = 99999
        event.observation.delta["corrupted"] = True

    def pristine_sink(event: OrderedEvent) -> None:
        """Test helper: pristine sink."""
        seen_by_sink2.append({
            "scratchpad": dict(event.observation.state.scratchpad),
            "delta": dict(event.observation.delta),
        })

    observer.register_sink("sink1", mutating_sink, critical=False)
    observer.register_sink("sink2", pristine_sink, critical=False)

    original_obs = make_obs("run-b1-iso", data={"count": 1})
    await observer.on_observation(original_obs)
    await observer.shutdown(grace_period=1.0)

    # Pristine sink must have seen original unmutated values
    assert len(seen_by_sink2) == 1
    assert seen_by_sink2[0]["scratchpad"] == {"count": 1}
    assert "corrupted" not in seen_by_sink2[0]["delta"]
    assert original_obs.state.scratchpad["count"] == 1


@pytest.mark.asyncio
async def test_overflow_drops_newest_telemetry_with_gap_record_never_critical():
    """Queue overflow must drop non-critical events and emit a GapRecord, never drop critical."""
    config = BoundedObserverConfig(default_max_queue_size=3)
    observer = BoundedObserver(run_id="run-b1-overflow", config=config)

    received_non_critical: list[int] = []
    received_critical: list[int] = []

    # Slow consumer to trigger queue saturation
    queue_unblock = asyncio.Event()

    async def slow_sink(event: OrderedEvent) -> None:
        """Test helper: slow sink."""
        await queue_unblock.wait()
        received_non_critical.append(event.sequence)

    async def critical_sink(event: OrderedEvent) -> None:
        """Test helper: critical sink."""
        received_critical.append(event.sequence)

    observer.register_sink("slow_telemetry", slow_sink, critical=False, max_queue_size=3)
    observer.register_sink("audit_critical", critical_sink, critical=True)

    # Push 6 events while slow_telemetry is blocked (capacity 3)
    for i in range(6):
        await observer.on_observation(make_obs("run-b1-overflow", node=f"n{i}"))

    assert len(observer.gaps) > 0
    total_dropped = sum(g.dropped_count for g in observer.gaps)
    assert total_dropped > 0

    # Unblock and drain
    queue_unblock.set()
    await observer.shutdown(grace_period=1.0)

    # All 6 critical events must have been delivered without drop
    assert received_critical == [0, 1, 2, 3, 4, 5]
    # Non-critical should have processed only what fit
    assert len(received_non_critical) < 6


# ==============================================================================
# Task B2: Critical-sink acknowledgment and failure mapping
# ==============================================================================

@pytest.mark.asyncio
async def test_critical_callback_exceptions_surface_and_map_to_unknown():
    """Exceptions from critical sinks must surface and mark delivery unhealthy with UnknownDisposition."""
    stop_signal = StopSignal()
    observer = BoundedObserver(
        run_id="run-b2-err",
        attempt_id="att-1",
        hold_id="hold-1",
        fence_epoch=2,
        stop_signal=stop_signal,
    )

    def failing_critical_sink(event: OrderedEvent) -> None:
        """Test helper: failing critical sink."""
        raise RuntimeError("database connection lost")

    observer.register_sink("db_sink", failing_critical_sink, critical=True)

    obs = make_obs("run-b2-err")
    with pytest.raises(RuntimeError, match="database connection lost"):
        await observer.on_observation(obs)

    # Delivery must be unhealthy
    assert not observer.healthy()
    # Stop must have been requested
    assert stop_signal.reason == "delivery.critical_failure"

    # UnknownDisposition must be recorded matching Gate 2 schema
    disps = observer.unknown_dispositions
    assert len(disps) == 1
    assert disps[0] == UnknownDisposition(
        attempt_id="att-1",
        hold_id="hold-1",
        fence_epoch=2,
        cause="critical_delivery_failure",
        stop_state="requested",
        settlement_state="unsettled",
    )


@pytest.mark.asyncio
async def test_critical_sink_timeout_maps_to_unknown_and_unhealthy():
    """Critical sink exceeding 500ms timeout must fail, request stop, and record UnknownDisposition."""
    config = BoundedObserverConfig(critical_ack_timeout=0.05)  # Fast 50ms for test
    stop_signal = StopSignal()
    observer = BoundedObserver(
        run_id="run-b2-timeout",
        attempt_id="att-2",
        hold_id="hold-2",
        fence_epoch=3,
        config=config,
        stop_signal=stop_signal,
    )

    async def hanging_critical_sink(event: OrderedEvent) -> None:
        """Test helper: hanging critical sink."""
        await asyncio.sleep(1.0)

    observer.register_sink("hang_sink", hanging_critical_sink, critical=True)

    with pytest.raises(TimeoutError, match="critical sink acknowledgment timeout"):
        await observer.on_observation(make_obs("run-b2-timeout"))

    assert not observer.healthy()
    assert stop_signal.reason == "delivery.critical_timeout"
    assert len(observer.unknown_dispositions) == 1
    assert observer.unknown_dispositions[0].cause == "critical_delivery_failure"


@pytest.mark.asyncio
async def test_late_acknowledgment_never_reopens_dispatch_authority():
    """Late acknowledgment after circuit has closed must never restore healthy() to True."""
    config = BoundedObserverConfig(critical_ack_timeout=0.05)
    observer = BoundedObserver(
        run_id="run-b2-late",
        attempt_id="att-late",
        hold_id="hold-late",
        fence_epoch=1,
        config=config,
    )

    ack_completed = asyncio.Event()

    async def delayed_critical_sink(event: OrderedEvent) -> None:
        """Test helper: delayed critical sink."""
        async def late_worker() -> None:
            """Test helper: late worker."""
            await asyncio.sleep(0.1)
            ack_completed.set()
        asyncio.create_task(late_worker())
        await asyncio.sleep(0.5)

    observer.register_sink("delayed_sink", delayed_critical_sink, critical=True)

    with pytest.raises(TimeoutError):
        await observer.on_observation(make_obs("run-b2-late"))

    assert not observer.healthy()

    # Wait for the late acknowledgment to complete
    await asyncio.wait_for(ack_completed.wait(), timeout=1.0)

    # Late ack must NOT reopen dispatch authority
    assert not observer.healthy()


@pytest.mark.asyncio
async def test_oversize_critical_payload_is_refused():
    """Oversize payload exceeding limit must be refused with ValueError, never truncated."""
    config = BoundedObserverConfig(max_critical_payload_bytes=100)
    observer = BoundedObserver(run_id="run-b2-oversize", config=config)

    observer.register_sink("crit", lambda e: None, critical=True)

    huge_payload = {"blob": "x" * 500}
    obs = make_obs("run-b2-oversize", data=huge_payload)

    with pytest.raises(ValueError, match="oversize critical payload"):
        await observer.on_observation(obs)


@pytest.mark.asyncio
async def test_repeated_shutdown_and_lifecycle_idempotent():
    """Repeated shutdown, register, and unregister calls must be idempotent."""
    observer = BoundedObserver(run_id="run-b2-idempotent")

    def dummy(event: OrderedEvent) -> None:
        """Test helper: dummy."""
        pass

    observer.register_sink("sink_a", dummy)
    observer.register_sink("sink_a", dummy)  # Re-register is safe
    observer.unregister_sink("sink_a")
    observer.unregister_sink("sink_a")  # Unregister non-existent is safe

    await observer.shutdown()
    await observer.shutdown()  # Repeated shutdown is safe


@pytest.mark.asyncio
async def test_async_context_manager_cleanup_on_exception():
    """Async context manager must ensure cleanup on every exit path including exceptions."""
    observer = BoundedObserver(run_id="run-b2-ctx")

    with pytest.raises(ZeroDivisionError):
        async with observer:
            observer.register_sink("dummy", lambda e: None)
            _ = 1 / 0

    assert observer.is_shutdown


# ==============================================================================
# Task B3: Cooperative stop, honestly bounded
# ==============================================================================

@pytest.mark.asyncio
async def test_stop_grace_period_honored():
    """Shutdown honors grace period allowing pending work to drain."""
    observer = BoundedObserver(run_id="run-b3-grace")
    worker_finished = False

    async def worker(event: OrderedEvent) -> None:
        """Test helper: worker."""
        nonlocal worker_finished
        await asyncio.sleep(0.05)
        worker_finished = True

    observer.register_sink("worker", worker, critical=False)
    await observer.on_observation(make_obs("run-b3-grace"))

    await observer.shutdown(grace_period=0.2)
    assert worker_finished


@pytest.mark.asyncio
async def test_timeout_reported_honestly_as_stop_timeout():
    """When grace period expires, observer records stop_timeout disposition and does not claim clean stop."""
    observer = BoundedObserver(
        run_id="run-b3-timeout",
        attempt_id="att-3",
        hold_id="hold-3",
        fence_epoch=4,
    )

    async def stalled_worker(event: OrderedEvent) -> None:
        """Test helper: stalled worker."""
        await asyncio.sleep(1.0)

    observer.register_sink("stalled", stalled_worker, critical=False)
    await observer.on_observation(make_obs("run-b3-timeout"))

    # Shutdown with very short grace period
    await observer.shutdown(grace_period=0.05)

    assert not observer.healthy()
    # Must have recorded an honest stop_timeout disposition
    disps = observer.unknown_dispositions
    assert any(d.cause == "stop_timeout" for d in disps)


@pytest.mark.asyncio
async def test_circuit_is_fenced_against_late_authority_after_stop():
    """After shutdown/stop, any subsequent on_observation must be rejected."""
    observer = BoundedObserver(run_id="run-b3-fenced")
    await observer.shutdown()

    with pytest.raises(RuntimeError, match="observer is shut down"):
        await observer.on_observation(make_obs("run-b3-fenced"))


def test_unknown_disposition_is_the_same_type_the_ledger_uses() -> None:
    """Seam reconciliation: Stream A and Stream B must share ONE UnknownDisposition
    type, not two structurally-identical-but-unrelated classes.

    Both streams independently implemented Gate 2's schema correctly and
    identically by field shape -- but as two separate dataclasses in two
    modules, bounded_observer.UnknownDisposition was never actually the
    same type as execution_guard.UnknownDisposition, which also carries a
    schema_version field and real __post_init__ validation that the
    duplicate lacked entirely. A ledger or any other consumer written
    against execution_guard.UnknownDisposition would silently accept an
    unvalidated object from the observer that only duck-types the same
    shape.
    """
    assert UnknownDisposition is execution_guard.UnknownDisposition


@pytest.mark.asyncio
async def test_circuit_trip_produces_a_validated_disposition_not_a_bypass() -> None:
    """The disposition BoundedObserver records on a critical failure must pass
    through the real __post_init__ validation Stream A defined -- not a
    parallel class with no validation at all."""
    observer = BoundedObserver(
        run_id="run-seam-1", attempt_id="att-seam-1", hold_id="hold-seam-1", fence_epoch=1
    )

    def broken_sink(event):
        """Test helper: broken sink."""
        raise RuntimeError("critical sink failure")

    observer.register_sink("failing", broken_sink, critical=True)
    with pytest.raises(RuntimeError):
        await observer.on_observation(make_obs("run-seam-1"))

    assert len(observer.unknown_dispositions) == 1
    disposition = observer.unknown_dispositions[0]
    assert isinstance(disposition, execution_guard.UnknownDisposition)
    assert disposition.schema_version == 1
    assert disposition.cause == "critical_delivery_failure"

    # Confirm the validation is real, not accidentally satisfied: constructing
    # the same type directly with a bad cause must raise, proving this isn't
    # an unchecked dataclass that happens to pass today's one call site.
    with pytest.raises(ValueError):
        execution_guard.UnknownDisposition(
            attempt_id=disposition.attempt_id,
            hold_id=disposition.hold_id,
            fence_epoch=disposition.fence_epoch,
            cause="not_a_real_cause",  # type: ignore[arg-type]
            stop_state=disposition.stop_state,
            settlement_state=disposition.settlement_state,
        )


# ==============================================================================
# Review fixes: aggregate byte bound, worker accounting, unidentified observer
# ==============================================================================

@pytest.mark.asyncio
async def test_aggregate_byte_limit_drops_newest_with_gap_record():
    """Queued non-critical payload bytes never exceed the aggregate limit; overflow leaves a gap."""
    observer = BoundedObserver(run_id="run-bytes", config=BoundedObserverConfig(aggregate_byte_limit=1))
    observer.register_sink("telemetry", lambda event: None, critical=False)
    await observer.on_observation(make_obs("run-bytes"))
    assert len(observer.gaps) == 1
    assert observer.gaps[0].dropped_count == 1
    assert observer.healthy()


@pytest.mark.asyncio
async def test_failing_noncritical_callback_does_not_stall_shutdown():
    """A raising telemetry callback still acknowledges its queue item, so shutdown drains cleanly."""
    observer = BoundedObserver(run_id="run-taskdone")

    def boom(event: OrderedEvent) -> None:
        """Raise from a non-critical sink."""
        raise RuntimeError("telemetry down")

    observer.register_sink("telemetry", boom, critical=False)
    await observer.on_observation(make_obs("run-taskdone"))
    await observer.shutdown(grace_period=0.5)
    assert observer.unknown_dispositions == []


@pytest.mark.asyncio
async def test_unidentified_observer_still_requests_stop_and_surfaces_sink_error():
    """Default (invalid) identity must not mask the sink error or lose the stop request."""
    stop = StopSignal()
    observer = BoundedObserver(run_id="run-noid", stop_signal=stop)

    def boom(event: OrderedEvent) -> None:
        """Fail the critical sink."""
        raise RuntimeError("critical sink failure")

    observer.register_sink("critical", boom, critical=True)
    with pytest.raises(RuntimeError, match="critical sink failure"):
        await observer.on_observation(make_obs("run-noid"))
    assert stop.reason == "delivery.critical_failure"
    assert not observer.healthy()


@pytest.mark.asyncio
async def test_bytes_stay_counted_while_callback_runs_then_release():
    """A dequeued event still holds memory until its callback finishes."""
    observer = BoundedObserver(run_id="run-inflight")
    gate = asyncio.Event()

    async def slow(event: OrderedEvent) -> None:
        """Block until released."""
        await gate.wait()

    observer.register_sink("slow", slow, critical=False)
    await observer.on_observation(make_obs("run-inflight"))
    await asyncio.sleep(0.01)  # worker dequeues and blocks inside the callback
    assert observer._queued_bytes > 0
    gate.set()
    await observer.shutdown(grace_period=0.5)
    assert observer._queued_bytes == 0


@pytest.mark.asyncio
async def test_replacing_a_sink_releases_its_abandoned_queue_bytes():
    """Replacing a sink with queued events must not leak its byte allowance."""
    observer = BoundedObserver(run_id="run-replace")
    block = asyncio.Event()

    async def stuck(event: OrderedEvent) -> None:
        """Block so later events stay queued."""
        await block.wait()

    observer.register_sink("s", stuck, critical=False)
    for _ in range(3):
        await observer.on_observation(make_obs("run-replace"))
    await asyncio.sleep(0.01)
    observer.register_sink("s", lambda event: None, critical=False)
    await asyncio.sleep(0.01)
    assert observer._queued_bytes == 0
    await observer.shutdown(grace_period=0.5)
