"""Sink Isolation: Declared process isolation contracts for blocking delivery sinks.

Enforces that observation sinks which can block the event loop or perform synchronous
I/O must run in isolated processes with bounded IPC queues.
"""
from __future__ import annotations

import multiprocessing as mp
import pickle
from typing import Any, Callable

DEFAULT_MAX_QUEUE_BYTES = 8 * 1024 * 1024  # matches BoundedObserver's aggregate bound


class BlockingSinkRequiresIsolationError(ValueError):
    """Raised when a blocking sink is registered without opting into process isolation."""


def _event_size(event: Any) -> int:
    """Return the charged size of one event: never less than its pickle.

    A producer's ``size_bytes`` can omit fields that still cross the process
    boundary (for example a large run identity), so it is only a lower bound.
    """
    wire = len(pickle.dumps(event, protocol=pickle.HIGHEST_PROTOCOL))
    size = getattr(event, "size_bytes", None)
    if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
        return max(size, wire)
    return wire


def _worker_loop(
    target: Callable[[Any], None],
    queue: mp.Queue,
    error_queue: mp.Queue,
    pending_bytes: Any,
) -> None:
    """Worker process main loop consuming serialized events."""
    while True:
        try:
            item = queue.get()
            if item is None:
                break
            size, event = item
            with pending_bytes.get_lock():
                pending_bytes.value = max(0, pending_bytes.value - size)
            try:
                target(event)
            except Exception as e:
                try:
                    error_queue.put_nowait(f"{type(e).__name__}: {e}")
                except Exception:
                    pass
        except (KeyboardInterrupt, SystemExit):
            break
        except Exception:
            break


class ProcessIsolatedSink:
    """Wrapper that runs a blocking observation sink in an isolated worker process.

    Protects the scheduler and async event loop from hangs, blocking system calls,
    or uncaught signals in synchronous third-party telemetry sinks.
    """

    # This wrapper acknowledges enqueue only, not worker execution or persistence.
    supports_critical_ack = False
    # Pickling for the byte allowance is O(event size); the observer therefore
    # calls this sink in a worker thread. Its state is a lock-guarded shared
    # counter and a multiprocessing queue, both safe across threads.
    runs_off_loop = True

    def __init__(
        self,
        target: Callable[[Any], None],
        queue_size: int = 1024,
        fail_closed: bool = False,
        max_queue_bytes: int = DEFAULT_MAX_QUEUE_BYTES,
    ) -> None:
        """Configure the isolated worker, its queue bounds and its shared byte allowance."""
        if isinstance(max_queue_bytes, bool) or not isinstance(max_queue_bytes, int) or max_queue_bytes <= 0:
            raise ValueError("max_queue_bytes must be a positive integer")
        self.target = target
        self.max_queue_bytes = max_queue_bytes
        self.queue_size = queue_size
        self.fail_closed = fail_closed
        self.is_blocking = False  # Wrapped into isolated non-blocking boundary
        self._ctx = mp.get_context("spawn")
        self._pending_bytes = self._ctx.Value("q", 0)
        self._queue: mp.Queue | None = None
        self._error_queue: mp.Queue | None = None
        self._process = None
        self._started = False
        self._closed = False

    def start(self) -> None:
        """Start the background worker process."""
        if self._closed:
            raise RuntimeError("ProcessIsolatedSink is closed")
        if not self._started:
            self._queue = self._ctx.Queue(maxsize=self.queue_size)
            self._error_queue = self._ctx.Queue(maxsize=16)
            self._process = self._ctx.Process(
                target=_worker_loop,
                args=(self.target, self._queue, self._error_queue, self._pending_bytes),
                daemon=True,
            )
            self._process.start()
            self._started = True

    def __call__(self, event: Any) -> None:
        """Forward event across isolated boundary into bounded IPC queue."""
        if not self._started:
            self.start()
        if self._closed:
            raise RuntimeError("ProcessIsolatedSink is closed")
        assert self._process is not None and self._queue is not None and self._error_queue is not None
        if not self._process.is_alive():
            raise RuntimeError("ProcessIsolatedSink worker process is not alive")

        try:
            err_msg = self._error_queue.get_nowait()
            raise RuntimeError(f"ProcessIsolatedSink worker error: {err_msg}")
        except mp.queues.Empty:
            pass

        # The observer releases its own byte charge as soon as this call
        # returns, so the sink keeps the events it still owns bounded here
        # until the worker consumes them.
        size = _event_size(event)
        with self._pending_bytes.get_lock():
            if self._pending_bytes.value + size > self.max_queue_bytes:
                over_allowance = True
            else:
                over_allowance = False
                self._pending_bytes.value += size
        if over_allowance:
            if self.fail_closed:
                raise BufferError("ProcessIsolatedSink byte allowance exhausted")
            return
        try:
            self._queue.put_nowait((size, event))
        except Exception:
            with self._pending_bytes.get_lock():
                self._pending_bytes.value = max(0, self._pending_bytes.value - size)
            if self.fail_closed:
                raise

    def close(self, timeout: float = 0.5) -> None:
        """Shut down the background worker process."""
        self._closed = True
        if self._started and self._process is not None and self._process.is_alive():
            try:
                self._queue.put_nowait(None)
            except Exception:
                pass
            self._process.join(timeout=timeout)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(timeout=0.1)
        for queue in (self._queue, self._error_queue):
            if queue is not None:
                try:
                    queue.close()
                except Exception:
                    pass
