"""Bounded, non-blocking observation and delivery coordinator (REV3 Batch 4 / Stream B).

Fulfills CONTRACT-DURABLE-HITL-EFFECTS.md and 2026-10-11-rev3-t2-parallel-streams-plan.md:
- Bounded FIFO queues for non-critical sinks (default 1024 events, 8 MiB aggregate detached payload).
- Explicit persistence boundary acknowledgment for critical sinks (default wait 500 ms).
- Circuit breaker tripping on critical timeout/exception, mapping to UnknownDisposition.
- Cooperative stop bounded honestly by grace period (default 1000 ms).
- Idempotent lifecycle and subscription management.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import time
from copy import deepcopy
from dataclasses import dataclass
from collections.abc import Callable, Iterable
from typing import Any, Awaitable, Literal, Protocol

from perpetua_core.graph.engine import GraphObservation
from orama.graph.execution_guard import DeliveryHealth, StopSignal, UnknownDisposition
from orama.graph.sink_isolation import BlockingSinkRequiresIsolationError

# Re-exported for existing importers of this module (seam reconciliation,
# 2026-10-11): UnknownDisposition is execution_guard's real, versioned,
# validated type -- Gate 2 requires ONE shared type across Stream A and
# Stream B, not two structurally-identical-but-unrelated dataclasses. Do not
# redefine it here; a local duplicate would skip execution_guard's
# __post_init__ validation and schema_version field entirely.
__all__ = ["UnknownDisposition"]


@dataclass(frozen=True, slots=True)
class GapRecord:
    """External gap record capturing dropped telemetry due to non-critical queue overflow."""

    sink_id: str
    dropped_count: int
    from_sequence: int
    to_sequence: int
    timestamp: float


@dataclass(frozen=True, slots=True)
class OrderedEvent:
    """Ordered event envelope preserving sequence and run identity."""

    run_id: str
    sequence: int
    observation: GraphObservation
    size_bytes: int


@dataclass(frozen=True, slots=True)
class BoundedObserverConfig:
    """Configuration boundaries for delivery and observation handling."""

    default_max_queue_size: int = 1024
    aggregate_byte_limit: int = 8 * 1024 * 1024  # 8 MiB per REV3 §4
    critical_ack_timeout: float = 0.5            # 500 ms per REV3 §4
    stop_grace_period: float = 1.0               # 1000 ms per REV3 §4
    max_critical_payload_bytes: int = 8 * 1024 * 1024  # 8 MiB

    def __post_init__(self) -> None:
        """Validate non-negative and positive limits."""
        if self.default_max_queue_size <= 0:
            raise ValueError(f"default_max_queue_size limit must be positive, got {self.default_max_queue_size}")
        if self.aggregate_byte_limit <= 0:
            raise ValueError(f"aggregate_byte_limit limit must be positive, got {self.aggregate_byte_limit}")
        if self.critical_ack_timeout <= 0:
            raise ValueError(f"critical_ack_timeout limit must be positive, got {self.critical_ack_timeout}")
        if self.stop_grace_period <= 0:
            raise ValueError(f"stop_grace_period limit must be positive, got {self.stop_grace_period}")
        if self.max_critical_payload_bytes <= 0:
            raise ValueError(f"max_critical_payload_bytes limit must be positive, got {self.max_critical_payload_bytes}")


class SinkCallback(Protocol):
    """Callback protocol for an observation sink."""

    def __call__(self, event: OrderedEvent) -> Any | Awaitable[Any]:
        """Process one ordered observation event."""


@dataclass
class _SinkRegistration:
    """Test helper _SinkRegistration."""
    sink_id: str
    callback: Any
    critical: bool
    max_queue_size: int
    queue: asyncio.Queue[OrderedEvent] | None = None
    worker_task: asyncio.Task[None] | None = None
    retired: bool = False


def _estimate_payload_bytes(observation: GraphObservation) -> int:
    """Estimate detached payload size in UTF-8 encoded bytes."""
    total = 128
    if observation.delta:
        try:
            total += len(json.dumps(observation.delta, default=str, ensure_ascii=False).encode("utf-8"))
        except Exception:
            total += 512
    if observation.state:
        try:
            total += len(json.dumps(observation.state.model_dump(), default=str, ensure_ascii=False).encode("utf-8"))
        except Exception:
            total += 1024
    return total


def _detach_observation(observation: GraphObservation) -> GraphObservation:
    """Create a completely deep-isolated copy of GraphObservation."""
    fields: dict[str, Any] = {
        "event": observation.event,
        "state": observation.state.model_copy(deep=True),
        "delta": deepcopy(observation.delta),
    }
    # Older Core pins (policy-r3) have no provenance field; copy it only where it exists.
    if hasattr(observation, "provenance"):
        fields["provenance"] = deepcopy(observation.provenance)
    return GraphObservation(**fields)


class BoundedObserver(DeliveryHealth):
    """Bounded, non-blocking delivery observer implementing DeliveryHealth."""

    def __init__(
        self,
        run_id: str,
        attempt_id: str = "",
        hold_id: str = "",
        fence_epoch: int = 0,
        config: BoundedObserverConfig | None = None,
        stop_signal: StopSignal | None = None,
    ) -> None:
        """Initialize bounded observer with configuration and identity."""
        self.run_id = run_id
        self.attempt_id = attempt_id
        self.hold_id = hold_id
        self.fence_epoch = fence_epoch
        self.config = config or BoundedObserverConfig()
        self.stop_signal = stop_signal

        self._is_healthy = True
        self._circuit_closed = False
        self._is_shutdown = False
        self._sequence = 0

        self._sinks: dict[str, _SinkRegistration] = {}
        self._gaps: list[GapRecord] = []
        self._unknown_dispositions: list[UnknownDisposition] = []
        self._unpersisted_dispositions: list[UnknownDisposition] = []
        self._identity_source: Callable[[], Iterable[Any]] | None = None
        self._on_unknown: Callable[[UnknownDisposition], None] | None = None
        self._pending_callbacks: set[asyncio.Task[Any]] = set()
        self._close_tasks: set[asyncio.Task[Any]] = set()  # off-loop sink closes
        self._queued_bytes = 0  # aggregate detached payload bytes held in non-critical queues
        self._inflight_bytes = 0  # bytes currently executing inside active callback tasks

    # DeliveryHealth protocol ----------------------------------------------------

    def healthy(self) -> bool:
        """Report whether delivery is healthy and circuit remains un-tripped."""
        return self._is_healthy and not self._circuit_closed

    @property
    def inflight_bytes(self) -> int:
        """Aggregate bytes held in-flight across active callbacks."""
        return self._inflight_bytes

    @property
    def is_shutdown(self) -> bool:
        """Report whether observer has completed shutdown."""
        return self._is_shutdown

    @property
    def gaps(self) -> list[GapRecord]:
        """Return list of recorded gap records from telemetry drops."""
        return list(self._gaps)

    @property
    def unknown_dispositions(self) -> list[UnknownDisposition]:
        """Return list of unknown dispositions recorded during failures."""
        return list(self._unknown_dispositions)

    @property
    def unpersisted_dispositions(self) -> list[UnknownDisposition]:
        """Return dispositions whose durable write failed, so none is silently lost."""
        return list(self._unpersisted_dispositions)

    def bind_authority(
        self,
        *,
        identity_source: Callable[[], Iterable[Any]],
        on_unknown: Callable[[UnknownDisposition], None],
        stop_signal: StopSignal | None = None,
    ) -> None:
        """Bind the authoritative identity and durable write for this run, once.

        Why: the constructor's ``attempt_id``/``hold_id``/``fence_epoch`` describe a
        single attempt, but an observer is per run and a run has many. A failure can
        also arrive before any attempt exists, or after the last one settled. With
        blank defaults ``UnknownDisposition`` rejects the record and the failure path
        used to swallow that, so no disposition existed at all; nothing ever wrote
        the in-memory list to the ledger either.

        How: ``identity_source`` is read at the moment the circuit trips and yields
        the attempts the ledger shows as started and unsettled (``attempt_id``,
        ``hold_id`` and ``fence_epoch`` each). ``on_unknown`` is the durable write
        (the ledger's validated ``mark_unknown``). Once bound it is the only source:
        an empty answer means nothing is unsettled and nothing is invented, so the
        run-level terminal is the conservative record. Binding twice raises, because
        a second source would let identity change mid-run. ``stop_signal`` is adopted
        only if the observer was not given one, so a recorded disposition truthfully
        reports that a stop was requested.
        """
        if self._identity_source is not None:
            raise RuntimeError("observer authority is already bound")
        self._identity_source = identity_source
        self._on_unknown = on_unknown
        if stop_signal is not None and self.stop_signal is None:
            self.stop_signal = stop_signal

    def _unsettled_identities(self) -> list[tuple[str, str, int]]:
        """Resolve the identities a trip must name, never raising into the failure path.

        Unbound observers keep the constructor identity (the pre-existing contract).
        Once bound, the source is read here and only here. An unreadable source
        yields no identities: the circuit is already tripped and the stop already
        requested, and the original sink failure must reach the caller unmasked.
        """
        if self._identity_source is None:
            return [(self.attempt_id, self.hold_id, self.fence_epoch)]
        try:
            holds = tuple(self._identity_source())
        except Exception:  # noqa: BLE001 - an unreadable authority must not mask the sink failure
            return []
        return [(h.attempt_id, h.hold_id, h.fence_epoch) for h in holds]

    # Sink registration ----------------------------------------------------------

    def register_sink(
        self,
        sink_id: str,
        callback: Any,
        critical: bool = False,
        max_queue_size: int | None = None,
    ) -> None:
        """Register or update an observation sink. Idempotent."""
        if not self.run_id or not isinstance(self.run_id, str):
            raise ValueError("observer must have valid run_id identity before registering sinks")
        if getattr(callback, "is_blocking", False):
            raise BlockingSinkRequiresIsolationError(f"sink {sink_id} is blocking and requires process isolation")
        if critical and getattr(callback, "supports_critical_ack", True) is False:
            raise ValueError("critical sinks require persistence-boundary acknowledgment, not enqueue acceptance")

        if sink_id in self._sinks:
            self.unregister_sink(sink_id)

        queue_limit = max_queue_size or self.config.default_max_queue_size
        reg = _SinkRegistration(
            sink_id=sink_id,
            callback=callback,
            critical=critical,
            max_queue_size=queue_limit,
        )

        if not critical:
            reg.queue = asyncio.Queue(maxsize=queue_limit)
            reg.worker_task = asyncio.create_task(self._run_queue_worker(reg))
            self._track_callback(reg.worker_task)

        self._sinks[sink_id] = reg

    def unregister_sink(self, sink_id: str) -> None:
        """Unregister a sink and cancel its background worker. Idempotent."""
        reg = self._sinks.pop(sink_id, None)
        if reg is not None:
            reg.retired = True
        if reg and reg.worker_task and not reg.worker_task.done():
            reg.worker_task.cancel()
        if reg:
            self._close_off_loop(reg.callback)
        if reg and reg.queue is not None:
            # Release the allowance of events abandoned in the replaced queue.
            while True:
                try:
                    event = reg.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._queued_bytes = max(0, self._queued_bytes - event.size_bytes)
                reg.queue.task_done()

    def _close_off_loop(self, callback: Any) -> asyncio.Task[Any] | None:
        """Close a sink without blocking the event loop; failures are swallowed.

        ``ProcessIsolatedSink.close`` joins its worker process, which blocks for
        up to a fraction of a second per sink, so it runs in a thread and is
        tracked so shutdown can wait for it inside its single deadline.
        """
        close = getattr(callback, "close", None)
        if not callable(close):
            return None

        async def _close_quietly() -> None:
            """Run the sink's blocking close in a thread and swallow its failure."""
            try:
                await asyncio.to_thread(close)
            except Exception:  # noqa: BLE001 - a failing close must not break shutdown
                pass

        try:
            task = asyncio.get_running_loop().create_task(_close_quietly())
        except RuntimeError:  # no running loop: nothing to protect, close inline
            try:
                close()
            except Exception:  # noqa: BLE001
                pass
            return None
        self._close_tasks.add(task)
        task.add_done_callback(self._close_tasks.discard)
        return task

    # Core observation dispatch -------------------------------------------------

    def _track_callback(self, task: asyncio.Task[Any]) -> None:
        """Own a callback until it finishes, including suppressed cancellation."""
        self._pending_callbacks.add(task)
        task.add_done_callback(self._callback_finished)

    def _callback_finished(self, task: asyncio.Task[Any]) -> None:
        """Release completed ownership and retrieve late exceptions."""
        self._pending_callbacks.discard(task)
        if not task.cancelled():
            task.exception()

    async def on_observation(self, observation: GraphObservation) -> None:
        """Dispatch observation to critical and non-critical sinks.

        Non-critical sinks enqueue without blocking. Critical sinks await explicit
        boundary acknowledgment with a strict timeout.
        """
        if self._is_shutdown:
            raise RuntimeError("observer is shut down; late authority is fenced")

        size_bytes = _estimate_payload_bytes(observation)

        # Check critical payload limit before processing
        has_critical = any(r.critical for r in self._sinks.values())
        if has_critical and size_bytes > self.config.max_critical_payload_bytes:
            raise ValueError(
                f"oversize critical payload: {size_bytes} bytes exceeds "
                f"limit of {self.config.max_critical_payload_bytes}"
            )

        seq = self._sequence
        self._sequence += 1

        # 1. Dispatch non-critical sinks (non-blocking)
        for reg in list(self._sinks.values()):
            if not reg.critical and reg.queue is not None:
                event = OrderedEvent(
                    run_id=self.run_id,
                    sequence=seq,
                    observation=_detach_observation(observation),
                    size_bytes=size_bytes,
                )
                try:
                    if self._queued_bytes + size_bytes > self.config.aggregate_byte_limit:
                        raise asyncio.QueueFull
                    reg.queue.put_nowait(event)
                    self._queued_bytes += size_bytes
                except asyncio.QueueFull:
                    # Drop newest and record bounded gap
                    if len(self._gaps) >= 50:
                        self._gaps.pop(0)
                    self._gaps.append(
                        GapRecord(
                            sink_id=reg.sink_id,
                            dropped_count=1,
                            from_sequence=seq,
                            to_sequence=seq,
                            timestamp=time.time(),
                        )
                    )

        # 2. Await critical sinks with persistence boundary timeout
        critical_sinks = [r for r in self._sinks.values() if r.critical]
        for reg in critical_sinks:
            event = OrderedEvent(
                run_id=self.run_id,
                sequence=seq,
                observation=_detach_observation(observation),
                size_bytes=size_bytes,
            )
            await self._dispatch_critical_sink(reg, event)

    async def _dispatch_critical_sink(self, reg: _SinkRegistration, event: OrderedEvent) -> None:
        """Await critical sink callback within the configured acknowledgment timeout."""
        try:
            res = reg.callback(event)
            if inspect.isawaitable(res):
                task = asyncio.create_task(res)
                self._track_callback(task)
                try:
                    _, pending = await asyncio.wait([task], timeout=self.config.critical_ack_timeout)
                    if task in pending:
                        task.cancel()
                        raise asyncio.TimeoutError
                    task.result()
                except asyncio.CancelledError:
                    task.cancel()
                    self._trip_circuit("critical_delivery_failure", "delivery.critical_cancelled")
                    raise
        except asyncio.TimeoutError:
            self._trip_circuit("critical_delivery_failure", "delivery.critical_timeout")
            raise TimeoutError(
                f"critical sink acknowledgment timeout for sink '{reg.sink_id}'"
            ) from None
        except Exception:
            self._trip_circuit("critical_delivery_failure", "delivery.critical_failure")
            raise

    def _trip_circuit(self, cause: Literal["critical_delivery_failure", "stop_timeout"], stop_reason: str) -> None:
        """Trip circuit breaker, request stop, and record UnknownDisposition.

        Order matters. The circuit trips and the stop is requested first, so an
        unreadable authority or an invalid identity can never delay or swallow the
        stop. The stop notifier is a side channel: if it raises, records are still
        written and the sink's own failure still reaches the caller, and the recorded
        ``stop_state`` follows what the signal actually holds (a durable stop may have
        committed before the notifier failed). Each unsettled identity then becomes
        one validated disposition, appended in memory and handed to the durable
        write. A refused write (fenced lease, conflicting record) is kept in
        ``unpersisted_dispositions`` instead of being raised. Recovery re-derives the
        same attempts from the ledger if a write was lost.
        """
        self._is_healthy = False
        self._circuit_closed = True
        # Request the stop first: an invalid observer identity must never swallow it
        # or replace the original sink failure with a ValueError.
        stop_requested = False
        if self.stop_signal:
            try:
                self.stop_signal.request(stop_reason)
                stop_requested = True
            except Exception:  # noqa: BLE001 - a failing notifier must not skip records
                try:
                    stop_requested = getattr(self.stop_signal, "reason", None) is not None
                except Exception:  # noqa: BLE001
                    stop_requested = False
        for attempt_id, hold_id, fence_epoch in self._unsettled_identities():
            try:
                disposition = UnknownDisposition(
                    attempt_id=attempt_id,
                    hold_id=hold_id,
                    fence_epoch=fence_epoch,
                    cause=cause,
                    stop_state="requested" if stop_requested else "none",
                    settlement_state="unsettled",
                )
            except ValueError:
                continue  # unidentified: circuit stays tripped, nothing to settle against
            self._unknown_dispositions.append(disposition)
            if self._on_unknown is None:
                continue
            try:
                self._on_unknown(disposition)
            except Exception:  # noqa: BLE001 - keep the record; never mask the sink failure
                self._unpersisted_dispositions.append(disposition)

    async def _run_queue_worker(self, reg: _SinkRegistration) -> None:
        """Background worker consuming from a non-critical sink queue."""
        assert reg.queue is not None
        while not reg.retired:
            try:
                event = await reg.queue.get()
            except asyncio.CancelledError:
                break
            # The event's bytes stay counted while its callback runs (it is still held
            # in memory) and are released in ``finally`` on completion or cancellation.
            cancelled = False
            self._inflight_bytes += event.size_bytes
            try:
                if getattr(reg.callback, "runs_off_loop", False):
                    # Sizing and enqueueing a large event is CPU work; a sink that
                    # declares itself thread-safe is called in a worker thread so
                    # it cannot stall the scheduler's event loop.
                    res = await asyncio.to_thread(reg.callback, event)
                else:
                    res = reg.callback(event)
                if inspect.isawaitable(res):
                    await res
            except asyncio.CancelledError:
                cancelled = True
            except Exception:  # noqa: BLE001 - non-critical sinks never trip the circuit
                pass
            finally:
                self._inflight_bytes = max(0, self._inflight_bytes - event.size_bytes)
                self._queued_bytes = max(0, self._queued_bytes - event.size_bytes)
                reg.queue.task_done()
            if cancelled:
                break

    # Cooperative stop & shutdown ------------------------------------------------

    async def shutdown(self, grace_period: float | None = None) -> None:
        """Perform cooperative stop, waiting up to grace_period for drains. Idempotent."""
        if self._is_shutdown and not self._pending_callbacks:
            return

        self._is_shutdown = True
        grace = grace_period if grace_period is not None else self.config.stop_grace_period
        # One deadline bounds the whole shutdown: drain, callback cancellation
        # and sink close share it instead of each spending a fresh grace.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + grace

        def remaining() -> float:
            """Return the seconds left before the shared shutdown deadline."""
            return max(0.0, deadline - loop.time())

        # Wait for non-critical queues to drain
        drain_coros = []
        for reg in self._sinks.values():
            if reg.queue:
                drain_coros.append(reg.queue.join())

        if drain_coros:
            try:
                await asyncio.wait_for(asyncio.gather(*drain_coros), timeout=remaining())
            except asyncio.TimeoutError:
                # Grace period expired: honesty constraint dictates recording stop_timeout
                self._trip_circuit("stop_timeout", "stop.grace_period_expired")

        # Cancel remaining workers
        for reg in list(self._sinks.values()):
            reg.retired = True
            if reg.worker_task and not reg.worker_task.done():
                reg.worker_task.cancel()

        # Cancel any other pending callbacks
        for task in list(self._pending_callbacks):
            if not task.done():
                task.cancel()
        if self._pending_callbacks:
            _, pending = await asyncio.wait(tuple(self._pending_callbacks), timeout=remaining())
            if pending:
                self._trip_circuit("stop_timeout", "stop.grace_period_expired")

        # Close sinks with an explicit close() lifecycle off the event loop.
        closing = list(self._sinks.values())
        self._sinks.clear()  # a repeated shutdown must not close a sink twice
        for reg in closing:
            self._close_off_loop(reg.callback)
        if self._close_tasks:
            _, unfinished = await asyncio.wait(tuple(self._close_tasks), timeout=remaining())
            if unfinished:
                self._trip_circuit("stop_timeout", "stop.grace_period_expired")

    async def __aenter__(self) -> BoundedObserver:
        """Enter async context."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context ensuring honest shutdown."""
        await self.shutdown()
