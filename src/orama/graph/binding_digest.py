"""E1 "C2" permit-replay: the binding digest persisted alongside an issued permit.

Per the design doc's Retry identity section: the issuer persists a canonical
digest of the object made of exactly nine immutable request fields. This
digest is the retry-identity key — it binds a retry to the same request.
``requested_at`` and ``consumer_acked_through`` are explicitly EXCLUDED from
the binding digest and must never appear in this module.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class BindingDigestFields:
    """The nine immutable request fields that make up the binding digest."""

    grant_id: str
    grant_payload_digest: str
    operation_id: str
    request_digest: str
    artifact_digest: str
    reservation_id: str
    ledger_store_id: str
    configuration_policy_epoch: int
    authority_epoch: int

    def __post_init__(self) -> None:
        """Fail closed on invalid field invariants."""
        if not self.grant_id.strip():
            raise ValueError("grant_id is required")
        if not self.grant_payload_digest.strip():
            raise ValueError("grant_payload_digest is required")
        if not self.operation_id.strip():
            raise ValueError("operation_id is required")
        if not self.request_digest.strip():
            raise ValueError("request_digest is required")
        if not self.artifact_digest.strip():
            raise ValueError("artifact_digest is required")
        if not self.reservation_id.strip():
            raise ValueError("reservation_id is required")
        if not self.ledger_store_id.strip():
            raise ValueError("ledger_store_id is required")
        if (
            isinstance(self.configuration_policy_epoch, bool)
            or not isinstance(self.configuration_policy_epoch, int)
            or self.configuration_policy_epoch < 1
        ):
            raise ValueError("configuration_policy_epoch must be a positive integer")
        if (
            isinstance(self.authority_epoch, bool)
            or not isinstance(self.authority_epoch, int)
            or self.authority_epoch < 1
        ):
            raise ValueError("authority_epoch must be a positive integer")


def compute_binding_digest(fields: BindingDigestFields) -> str:
    """Return the canonical SHA-256 hex digest of the nine binding fields.

    Uses this repo's established manifest-encoding convention
    (``src/orama/compat/manifest.py::canonical_digest``): UTF-8, sorted
    keys, no extra whitespace, NaN/Infinity refused rather than silently
    hashed. Byte-identical canonical encoding matters here because the
    digest is a retry-identity key compared across requests/processes.
    """
    value = asdict(fields)
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
