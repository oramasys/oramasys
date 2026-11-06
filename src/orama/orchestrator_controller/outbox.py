"""Redacted outbox payloads for post-commit egress (doc 68 section 4.1, IC-21).

The store writes an outbox row in the same transaction as the state change it announces.
Payloads are built only from ``PAYLOAD_ALLOWLIST``; anything else a caller passes is
dropped. Proof material, lease tokens, principals' credentials and source lines are never
in the allowlist.
"""
from __future__ import annotations

from collections.abc import Mapping

from orama.orchestrator_controller.envelope import canonical_json, sha256_hex

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


def build_redacted_payload(fields: Mapping[str, object]) -> tuple[str, str]:
    """Return ``(payload_json, payload_digest)`` holding only allowlisted, non-null fields."""
    payload = {key: fields[key] for key in PAYLOAD_ALLOWLIST if fields.get(key) is not None}
    text = canonical_json(payload)
    return text, sha256_hex(text)
