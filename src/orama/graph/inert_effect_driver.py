"""One local inert driver; never performs network, filesystem or shell effects.

The caller must first complete the existing governed authorization transaction.
This driver uses its durable one-send marker and records evidence of a simulation,
not evidence that an external effect occurred. A crash leaves UNKNOWN and must not
be retried automatically.
"""
from __future__ import annotations

from orama.graph.dispatch_attempts import SqliteAttemptStore


class InertEffectDriver:
    """Exercise the real outbox lifecycle without an external side effect."""

    def __init__(self, store: SqliteAttemptStore) -> None:
        """Use the caller-owned store; never manufacture authorization."""
        self._store = store

    def send(self, attempt_id: str) -> str:
        """Consume one authorized send and durably settle the inert simulation."""
        self._store.begin_send(attempt_id, inert_only=True)
        evidence = "inert-simulation:v1"
        self._store.record_outcome(attempt_id, "confirmed", evidence)
        return evidence
