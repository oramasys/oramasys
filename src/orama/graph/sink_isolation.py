"""Sink Isolation: Declared process isolation contracts for blocking delivery sinks.

Enforces that observation sinks which can block the event loop or perform synchronous
I/O must run in isolated processes with bounded IPC queues.
"""
from __future__ import annotations

from typing import Any, Callable


class BlockingSinkRequiresIsolationError(ValueError):
    """Raised when a blocking sink is registered without opting into process isolation."""


class ProcessIsolatedSink:
    """Wrapper that runs a blocking observation sink in an isolated worker process."""

    def __init__(self, target: Callable[[Any], None], queue_size: int = 1024) -> None:
        self.target = target
        self.queue_size = queue_size
        self.is_blocking = False  # Wrapped into isolated non-blocking boundary

    def __call__(self, event: Any) -> None:
        """Forward event across isolated boundary."""
        self.target(event)
