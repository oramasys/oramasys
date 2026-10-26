"""One local inert driver; never performs network, filesystem or shell effects.

The caller must first complete the existing governed authorization transaction.
This driver uses its durable one-send marker and records evidence of a simulation,
not evidence that an external effect occurred. A crash leaves UNKNOWN and must not
be retried automatically.

This is a store-level primitive only. It is not a send path for composed grants and
it is never reachable from ``POST /effects/inert``: that route accepts only the
``FinalBoundarySender`` (verify-and-bind composer plus the sealed final boundary).
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from orama.graph.dispatch_attempts import SqliteAttemptStore


class InertEffectDriver:
    """Exercise the real outbox lifecycle without an external side effect."""

    def __init__(self, store: SqliteAttemptStore, *, clock: Callable[[], datetime] | None = None) -> None:
        """Use the caller-owned store; never manufacture authorization."""
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    def send(self, attempt_id: str) -> str:
        """Consume one authorized send and durably settle the inert simulation."""
        self._store.begin_send(attempt_id, inert_only=True, now=self._clock())
        evidence = "inert-simulation:v1"
        self._store.record_outcome(attempt_id, "confirmed", evidence)
        return evidence
