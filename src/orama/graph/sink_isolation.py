"""Sink Isolation: Declared process isolation contracts for blocking delivery sinks.

Enforces that observation sinks which can block the event loop or perform synchronous
I/O must run in isolated processes with bounded IPC queues.
"""
from __future__ import annotations

import multiprocessing as mp
import threading
from typing import Any, Callable


class BlockingSinkRequiresIsolationError(ValueError):
    """Raised when a blocking sink is registered without opting into process isolation."""


def _worker_loop(target: Callable[[Any], None], queue: mp.Queue) -> None:
    """Worker process main loop consuming serialized events."""
    while True:
        try:
            item = queue.get()
            if item is None:
                break
            target(item)
        except (KeyboardInterrupt, SystemExit):
            break
        except Exception:
            pass


class ProcessIsolatedSink:
    """Wrapper that runs a blocking observation sink in an isolated worker process.
    
    Protects the scheduler and async event loop from hangs, blocking system calls,
    or uncaught signals in synchronous third-party telemetry sinks.
    """

    def __init__(self, target: Callable[[Any], None], queue_size: int = 1024) -> None:
        self.target = target
        self.queue_size = queue_size
        self.is_blocking = False  # Wrapped into isolated non-blocking boundary
        self._ctx = mp.get_context("spawn")
        self._queue: mp.Queue = self._ctx.Queue(maxsize=queue_size)
        self._process = self._ctx.Process(target=_worker_loop, args=(target, self._queue), daemon=True)
        self._started = False

    def start(self) -> None:
        """Start the background worker process."""
        if not self._started:
            self._process.start()
            self._started = True

    def __call__(self, event: Any) -> None:
        """Forward event across isolated boundary into bounded IPC queue."""
        if not self._started:
            self.start()
        try:
            self._queue.put_nowait(event)
        except Exception:
            pass  # Drops when IPC queue full; non-blocking boundary preserved

    def close(self, timeout: float = 0.5) -> None:
        """Shut down the background worker process."""
        if self._started and self._process.is_alive():
            try:
                self._queue.put_nowait(None)
            except Exception:
                pass
            self._process.join(timeout=timeout)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(timeout=0.1)
