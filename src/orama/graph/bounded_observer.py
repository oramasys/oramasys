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
        self._pending_callbacks: set[asyncio.Task[Any]] = set()
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
            self._pending_callbacks.add(reg.worker_task)

        self._sinks[sink_id] = reg

    def unregister_sink(self, sink_id: str) -> None:
        """Unregister a sink and cancel its background worker. Idempotent."""
        reg = self._sinks.pop(sink_id, None)
        if reg and reg.worker_task and not reg.worker_task.done():
            reg.worker_task.cancel()
            self._pending_callbacks.discard(reg.worker_task)
        if reg and hasattr(reg.callback, "close") and callable(reg.callback.close):
            try:
                reg.callback.close()
            except Exception:
                pass
        if reg and reg.queue is not None:
            # Release the allowance of events abandoned in the replaced queue.
            while True:
                try:
                    event = reg.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._queued_bytes = max(0, self._queued_bytes - event.size_bytes)
                reg.queue.task_done()

    # Core observation dispatch -------------------------------------------------

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
                self._pending_callbacks.add(task)
                try:
                    done, pending = await asyncio.wait([task], timeout=self.config.critical_ack_timeout)
                    if task in pending:
                        task.cancel()
                        raise asyncio.TimeoutError
                    # If done, retrieve exception or result
                    task.result()
                finally:
                    self._pending_callbacks.discard(task)
        except asyncio.TimeoutError:
            self._trip_circuit("critical_delivery_failure", "delivery.critical_timeout")
            raise TimeoutError(
                f"critical sink acknowledgment timeout for sink '{reg.sink_id}'"
            ) from None
        except Exception:
            self._trip_circuit("critical_delivery_failure", "delivery.critical_failure")
            raise

    def _trip_circuit(self, cause: Literal["critical_delivery_failure", "stop_timeout"], stop_reason: str) -> None:
        """Trip circuit breaker, request stop, and record UnknownDisposition."""
        self._is_healthy = False
        self._circuit_closed = True
        # Request the stop first: an invalid observer identity must never swallow it
        # or replace the original sink failure with a ValueError.
        if self.stop_signal:
            self.stop_signal.request(stop_reason)
        try:
            disposition = UnknownDisposition(
                attempt_id=self.attempt_id,
                hold_id=self.hold_id,
                fence_epoch=self.fence_epoch,
                cause=cause,
                stop_state="requested" if self.stop_signal else "none",
                settlement_state="unsettled",
            )
        except ValueError:
            return  # unidentified observer: circuit stays tripped, nothing to settle against
        self._unknown_dispositions.append(disposition)

    async def _run_queue_worker(self, reg: _SinkRegistration) -> None:
        """Background worker consuming from a non-critical sink queue."""
        assert reg.queue is not None
        while True:
            try:
                event = await reg.queue.get()
            except asyncio.CancelledError:
                break
            # The event's bytes stay counted while its callback runs (it is still held
            # in memory) and are released in ``finally`` on completion or cancellation.
            cancelled = False
            self._inflight_bytes += event.size_bytes
            try:
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
        if self._is_shutdown:
            return

        self._is_shutdown = True
        grace = grace_period if grace_period is not None else self.config.stop_grace_period

        # Wait for non-critical queues to drain
        drain_coros = []
        for reg in self._sinks.values():
            if reg.queue:
                drain_coros.append(reg.queue.join())

        if drain_coros:
            try:
                await asyncio.wait_for(asyncio.gather(*drain_coros), timeout=grace)
            except asyncio.TimeoutError:
                # Grace period expired: honesty constraint dictates recording stop_timeout
                self._trip_circuit("stop_timeout", "stop.grace_period_expired")

        # Cancel remaining workers
        for reg in list(self._sinks.values()):
            if reg.worker_task and not reg.worker_task.done():
                reg.worker_task.cancel()
                self._pending_callbacks.discard(reg.worker_task)

        # Cancel any other pending callbacks
        for task in list(self._pending_callbacks):
            if not task.done():
                task.cancel()
        self._pending_callbacks.clear()

        # Close any sinks with an explicit close() lifecycle
        for reg in self._sinks.values():
            if hasattr(reg.callback, "close") and callable(reg.callback.close):
                try:
                    reg.callback.close()
                except Exception:
                    pass

    async def __aenter__(self) -> BoundedObserver:
        """Enter async context."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context ensuring honest shutdown."""
        await self.shutdown()
