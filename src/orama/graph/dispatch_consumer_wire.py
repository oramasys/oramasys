"""E1 "C2" consumer-side wire: strict validators, canonical bytes and digests.

Pure: no I/O, no clock, no database and NO cryptography. Signature checks go
through the injected ``SignatureVerifier`` port only. Field sets, types and
limits follow the frozen permit contract and the vendored vectors
(``src/tests/vectors/dispatch-permit-v1.json``).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, Protocol

SCHEMA_VERSION: Final = 1
MAX_SAFE_INTEGER: Final = (2**53) - 1
MAX_TEXT_BYTES: Final = 1_024
MAX_WIRE_BYTES: Final = 65_536
SIGNATURE_BYTES: Final = 64
GENESIS_EVENT_DIGEST: Final = "0" * 64
EVENT_KINDS: Final = frozenset({"revocation", "cascade", "finalization"})
SUBJECT_KINDS: Final = frozenset({"grant", "approval", "issuer"})
_IDENTIFIER_RE: Final = re.compile(r"[\x21-\x7e]{1,1024}")

_PERMIT_REQUEST_FIELDS: Final = (
    "grant_id", "grant_payload_digest", "operation_id", "request_digest", "artifact_digest",
    "reservation_id", "ledger_store_id", "configuration_policy_epoch", "authority_epoch",
    "consumer_acked_through", "attempt_id", "requested_at",
)
PERMIT_BODY_FIELDS: Final = frozenset(
    {
        "schema_version", *_PERMIT_REQUEST_FIELDS, "permit_id", "revocation_version",
        "issuer_authority_version", "issued_at", "expires_at", "issuer_key_id",
    }
)
PERMIT_WIRE_FIELDS: Final = PERMIT_BODY_FIELDS | {"payload_digest", "issuer_signature"}

_FINALIZATION_REQUEST_FIELDS: Final = (
    "permit_id", "permit_digest", "attempt_id", "reservation_id", "ledger_store_id",
    "consumer_acked_through", "authority_epoch", "requested_at",
)
FINALIZATION_BODY_FIELDS: Final = frozenset(
    {
        "schema_version", *_FINALIZATION_REQUEST_FIELDS, "finalization_id",
        "revocation_version", "revocation_event_digest", "issued_at", "expires_at",
    }
)
FINALIZATION_WIRE_FIELDS: Final = FINALIZATION_BODY_FIELDS | {"issuer_signature"}

EVENT_WIRE_FIELDS: Final = frozenset(
    {
        "version", "kind", "body", "previous_event_digest", "event_digest",
        "issuer_key_id", "signature",
    }
)

_DIGEST_FIELDS: Final = frozenset(
    {
        "grant_payload_digest", "request_digest", "artifact_digest", "permit_digest",
        "revocation_event_digest", "payload_digest", "previous_event_digest", "event_digest",
    }
)
_POSITIVE_INTEGER_FIELDS: Final = frozenset(
    {"configuration_policy_epoch", "authority_epoch", "issuer_authority_version", "version"}
)
_NONNEGATIVE_INTEGER_FIELDS: Final = frozenset(
    {"consumer_acked_through", "revocation_version", "schema_version"}
)
_TIMESTAMP_FIELDS: Final = frozenset({"requested_at", "issued_at", "expires_at"})
_SIGNATURE_FIELDS: Final = frozenset({"issuer_signature", "signature"})
_DIGEST_RE: Final = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_RE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


class WireError(ValueError):
    """A wire object is malformed: wrong fields, wrong types or oversize."""


class SignatureVerifier(Protocol):
    """Injected verifier port; Oramasys itself holds no signature primitive."""

    def verify_permit(self, key_id: str, body: Mapping[str, Any], signature: str) -> bool:
        """Return True only if the permit body signature verifies under ``key_id``."""
        ...

    def verify_finalization(self, key_id: str, body: Mapping[str, Any], signature: str) -> bool:
        """Return True only if the finalization body signature verifies under ``key_id``."""
        ...

    def verify_event(self, key_id: str, digest: str, signature: str) -> bool:
        """Return True only if the event digest signature verifies under ``key_id``."""
        ...


def canonical_bytes(obj: Mapping[str, Any]) -> bytes:
    """Serialize ``obj`` as the one valid canonical JSON form, UTF-8 encoded."""
    if not isinstance(obj, Mapping):
        raise WireError("canonical form requires an object")
    try:
        return json.dumps(
            dict(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise WireError("object is not JSON serializable") from error


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def parse_timestamp(value: object) -> datetime:
    """Decode strict six-digit UTC wire text, refusing every other form."""
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise WireError("timestamp must be six-digit UTC text")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise WireError("timestamp is not a real instant") from error


def _b64url_decode(value: object) -> bytes:
    """Decode strict canonical unpadded base64url text."""
    if not isinstance(value, str):
        raise WireError("signature must be base64url text")
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))
    except (UnicodeEncodeError, ValueError) as error:
        raise WireError("signature is not base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise WireError("signature is not canonical unpadded base64url")
    return decoded


def _is_int(value: object) -> bool:
    """Return True for a real integer (never a bool)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _check_value(name: str, value: object) -> None:
    """Validate one field against its frozen type and limit."""
    if name in _POSITIVE_INTEGER_FIELDS or name in _NONNEGATIVE_INTEGER_FIELDS:
        low = 1 if name in _POSITIVE_INTEGER_FIELDS else 0
        if not _is_int(value) or not low <= value <= MAX_SAFE_INTEGER:  # type: ignore[operator]
            raise WireError(f"{name} must be a safe integer of at least {low}")
    elif name in _DIGEST_FIELDS:
        if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
            raise WireError(f"{name} must be 64 lowercase hexadecimal characters")
    elif name in _TIMESTAMP_FIELDS:
        parse_timestamp(value)
    elif name in _SIGNATURE_FIELDS:
        if len(_b64url_decode(value)) != SIGNATURE_BYTES:
            raise WireError(f"{name} must decode to {SIGNATURE_BYTES} bytes")
    elif name != "body" and name != "kind":
        if not isinstance(value, str) or not value.strip():
            raise WireError(f"{name} must be non-blank text")
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            raise WireError(f"{name} exceeds {MAX_TEXT_BYTES} bytes")


def _validate_object(obj: object, expected: frozenset[str]) -> dict[str, Any]:
    """Require exactly ``expected`` keys, typed values and the size limit."""
    if not isinstance(obj, Mapping):
        raise WireError("wire object must be a mapping")
    keys = set(obj)
    if keys != expected:
        raise WireError(
            f"fields differ: missing={sorted(expected - keys)} extra={sorted(keys - expected)}"
        )
    for name, value in obj.items():
        _check_value(name, value)
    if "schema_version" in obj and obj["schema_version"] != SCHEMA_VERSION:
        raise WireError("schema_version must be the integer 1")
    if len(canonical_bytes(obj)) > MAX_WIRE_BYTES:
        raise WireError(f"object exceeds {MAX_WIRE_BYTES} bytes")
    return dict(obj)


PERMIT_REQUEST_FIELDS: Final = frozenset(_PERMIT_REQUEST_FIELDS)
FINALIZATION_REQUEST_FIELDS: Final = frozenset(_FINALIZATION_REQUEST_FIELDS)


def validate_permit_request_wire(obj: object) -> dict[str, Any]:
    """Validate the 12-field permit request the consumer sends and return a plain dict copy."""
    return _validate_object(obj, PERMIT_REQUEST_FIELDS)


def validate_finalization_request_wire(obj: object) -> dict[str, Any]:
    """Validate the 8-field finalization request the consumer sends and return a plain dict copy."""
    return _validate_object(obj, FINALIZATION_REQUEST_FIELDS)


def validate_permit_wire(obj: object) -> dict[str, Any]:
    """Validate the 21-field permit wire and return a plain dict copy."""
    return _validate_object(obj, PERMIT_WIRE_FIELDS)


def validate_finalization_wire(obj: object) -> dict[str, Any]:
    """Validate the 15-field finalization wire and return a plain dict copy."""
    return _validate_object(obj, FINALIZATION_WIRE_FIELDS)


def _validate_event_body(kind: object, body: object) -> None:
    """Validate an event body for its kind (a finalization body is exactly one field)."""
    if not isinstance(kind, str) or kind not in EVENT_KINDS:
        raise WireError("unknown event kind")
    if not isinstance(body, Mapping):
        raise WireError("event body must be an object")
    if kind == "finalization":
        if set(body) != {"finalization_id"}:
            raise WireError("a finalization event body is exactly {finalization_id}")
        _check_value("finalization_id", body["finalization_id"])
    elif kind == "revocation":
        if set(body) != {"subject_kind", "subject_id"}:
            raise WireError("a revocation body is exactly {subject_kind, subject_id}")
        if not isinstance(body["subject_kind"], str) or body["subject_kind"] not in SUBJECT_KINDS:
            raise WireError("subject_kind must be grant, approval or issuer")
        _require_identifier("subject_id", body["subject_id"])
    else:
        if set(body) != {"approval_id", "grant_ids", "issuer_authority_version"}:
            raise WireError("a cascade body is exactly {approval_id, grant_ids, issuer_authority_version}")
        _require_identifier("approval_id", body["approval_id"])
        grant_ids = body["grant_ids"]
        if not isinstance(grant_ids, list):
            raise WireError("grant_ids must be an array")
        for grant_id in grant_ids:
            _require_identifier("grant_ids element", grant_id)
        if any(earlier >= later for earlier, later in zip(grant_ids, grant_ids[1:])):
            raise WireError("grant_ids must be strictly ascending and duplicate-free")
        version = body["issuer_authority_version"]
        if not _is_int(version) or not 1 <= version <= MAX_SAFE_INTEGER:
            raise WireError("issuer_authority_version must be a safe integer of at least 1")


def is_canonical_identifier(value: object) -> bool:
    """Return True for a canonical identifier: printable ASCII without space, 1 to 1024 bytes."""
    return isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value) is not None


def _require_identifier(name: str, value: object) -> None:
    """Require a canonical identifier (see ``is_canonical_identifier``)."""
    if not is_canonical_identifier(value):
        raise WireError(f"{name} must be a canonical identifier")


def validate_event_wire(obj: object) -> dict[str, Any]:
    """Validate the 7-field event wire and return a plain dict copy."""
    if isinstance(obj, Mapping):
        _validate_event_body(obj.get("kind"), obj.get("body"))
    return _validate_object(obj, EVENT_WIRE_FIELDS)


def permit_body(wire: Mapping[str, Any]) -> dict[str, Any]:
    """Return the permit body: the wire without ``payload_digest`` and the signature."""
    return {k: v for k, v in wire.items() if k not in ("payload_digest", "issuer_signature")}


def permit_payload_digest(body: Mapping[str, Any]) -> str:
    """Return SHA-256 of the canonical permit body (the permit's payload digest)."""
    return _sha256_hex(canonical_bytes(body))


def finalization_body(wire: Mapping[str, Any]) -> dict[str, Any]:
    """Return the finalization body: the wire without its signature."""
    return {k: v for k, v in wire.items() if k != "issuer_signature"}


def finalization_digest(body: Mapping[str, Any]) -> str:
    """Return SHA-256 of the canonical finalization body (never a wire field)."""
    return _sha256_hex(canonical_bytes(body))


def event_preimage(
    version: int, kind: str, body: Mapping[str, Any], previous_event_digest: str
) -> bytes:
    """Return the canonical wrapper bytes that an event digest commits to."""
    _validate_event_body(kind, body)
    if not _is_int(version) or not 1 <= version <= MAX_SAFE_INTEGER:
        raise WireError("event version must be a positive safe integer")
    _check_value("previous_event_digest", previous_event_digest)
    return canonical_bytes(
        {
            "body": dict(body),
            "kind": kind,
            "previous_event_digest": previous_event_digest,
            "version": version,
        }
    )


def event_digest(
    version: int, kind: str, body: Mapping[str, Any], previous_event_digest: str
) -> str:
    """Return the SHA-256 of the canonical event wrapper object."""
    return _sha256_hex(event_preimage(version, kind, body, previous_event_digest))
