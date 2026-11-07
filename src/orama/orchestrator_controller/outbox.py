"""Redacted outbox payloads and the post-commit publisher (doc 68 sections 4.1 and 6).

The store writes an outbox row in the same transaction as the state change it announces.
Payloads are built only from ``PAYLOAD_ALLOWLIST`` and then scanned for topology fragments
(IC-21, IC-22); a payload that fails the scan aborts the whole transition. Each row carries
its payload digest and the allowlist digest so alteration is detectable (IC-23, partial).

``OutboxPublisher`` delivers pending rows in sequence order to an ``EventSink`` and marks a
row published only after the sink returns. Delivery is at least once: a crash between send
and mark redelivers the same ``event_id``, which consumers deduplicate. Publishing never
touches claim state, and no controller entry point accepts an event as input, so a
duplicated, reordered or forged event cannot create, renew, complete or release a claim
(IC-5).
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from orama.orchestrator_controller.envelope import canonical_json, contains_topology, sha256_hex

if TYPE_CHECKING:
    from orama.orchestrator_controller.store import ControllerStore

PAYLOAD_ALLOWLIST: tuple[str, ...] = (
    "event_id",
    "kind",
    "task_id",
    "task_version",
    "state",
    "lease_id",
    "disposition",
    "failure_class",
    "occurred_at",
    "lineage",
)
ALLOWLIST_DIGEST: str = sha256_hex(canonical_json(sorted(PAYLOAD_ALLOWLIST)))
MAX_PUBLISH_LIMIT = 10_000


class EgressRefused(ValueError):
    """A payload contained something that must not leave the controller store."""


class OutboxIntegrityError(RuntimeError):
    """A stored outbox row no longer matches its recorded digests; it is not delivered."""


def assert_egress_safe(value: object) -> None:
    """Raise ``EgressRefused`` when any key or string in ``value`` looks like topology."""
    if isinstance(value, str):
        if contains_topology(value):
            raise EgressRefused("payload carries a topology fragment")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            assert_egress_safe(key)
            assert_egress_safe(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            assert_egress_safe(item)
    elif value is not None and not isinstance(value, (bool, int)):
        raise EgressRefused("payload carries an unsupported value type")


def build_redacted_payload(fields: Mapping[str, object]) -> tuple[str, str]:
    """Return ``(payload_json, payload_digest)`` holding only allowlisted, non-null, safe fields."""
    payload = {key: fields[key] for key in PAYLOAD_ALLOWLIST if fields.get(key) is not None}
    assert_egress_safe(payload)
    text = canonical_json(payload)
    return text, sha256_hex(text)


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    """One committed, redacted event as handed to a sink."""

    event_id: str
    sequence: int
    kind: str
    payload: Mapping[str, Any]
    payload_digest: str
    allowlist_digest: str

    @classmethod
    def from_row(cls, event_id: str, sequence: int, kind: str, text: str, digest: str,
                 allowlist_digest: str) -> OutboxEvent:
        """Rebuild an event from its row, refusing any row whose digests do not match."""
        if sha256_hex(text) != digest or allowlist_digest != ALLOWLIST_DIGEST:
            raise OutboxIntegrityError(f"outbox row {sequence} failed its integrity check")
        payload = json.loads(text)
        if payload.get("event_id") != event_id or payload.get("kind") != kind:
            raise OutboxIntegrityError(f"outbox row {sequence} failed its integrity check")
        return cls(event_id, sequence, kind, payload, digest, allowlist_digest)


class EventSink(Protocol):
    """Where redacted events go (for example a GossipBus adapter composed outside this package)."""

    def publish(self, event: OutboxEvent) -> None:
        """Deliver ``event``; raising leaves it pending for a later attempt."""
        ...


@dataclass(frozen=True, slots=True)
class PublishReport:
    """How many events one pass delivered and which event, if any, the sink refused."""

    delivered: int
    failed_event_id: str | None = None


class OutboxPublisher:
    """Explicitly invoked, bounded, in-order publisher of pending outbox rows."""

    def __init__(self, store: ControllerStore, sink: EventSink) -> None:
        """Bind the publisher to one store and one sink; nothing runs until called."""
        self._store = store
        self._sink = sink

    def publish_pending(self, *, limit: int = 100) -> PublishReport:
        """Deliver up to ``limit`` pending events in sequence order.

        A sink failure stops the pass and leaves that event and every later one pending. A
        row that fails its integrity check raises ``OutboxIntegrityError`` before any
        event in that batch is sent or its delivery attempt recorded.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PUBLISH_LIMIT:
            raise ValueError(f"limit must be an integer from 1 to {MAX_PUBLISH_LIMIT}")
        delivered = 0
        for event in self._store.pending_outbox(limit):
            self._store.record_delivery_attempt(event.event_id)
            try:
                self._sink.publish(event)
            except Exception:  # noqa: BLE001 - any sink failure keeps the row pending
                return PublishReport(delivered, event.event_id)
            self._store.mark_published(event.event_id)
            delivered += 1
        return PublishReport(delivered)
