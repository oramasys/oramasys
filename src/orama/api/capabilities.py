"""R0-2 capability record reader and startup refusal matrix (DRAFT, not an activation record).

One runtime capability record carries five independent, default-deny bits. The reader is pure: it
takes bytes, text or a parsed mapping and returns a ``CapabilityView``; it never reads a file, an
environment variable or a clock, and it never infers one bit from another. A missing, unreadable,
malformed, unknown-schema, digest-mismatched or unsigned-enablement record makes every effective bit
``False`` and reports a stable reason code. ``serving`` never implies ``effects``.

``signature: null`` is only valid while every bit is ``False``. A ``True`` bit needs an operator
signature verified through the injected ``OperatorSignatureVerifier``; this repository wires none, so
in R0-2 any ``True`` bit is refused at startup with ``capability.unsigned_enablement``. This module
holds no signing path and no cryptography.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol

CAPABILITY_SCHEMA: Final = "orama-capability-record/v1"
CAPABILITY_BITS: Final[tuple[str, ...]] = (
    "serving", "effects", "transport", "continuation", "autonomous_settlement",
)

REASON_MISSING: Final = "capability.record_missing"
REASON_UNREADABLE: Final = "capability.record_unreadable"
REASON_MALFORMED: Final = "capability.record_malformed"
REASON_SCHEMA: Final = "capability.schema_unsupported"
REASON_BIT_MISSING: Final = "capability.bit_missing"
REASON_BIT_NOT_BOOLEAN: Final = "capability.bit_not_boolean"
REASON_DIGEST_MISMATCH: Final = "capability.digest_mismatch"
REASON_DIGEST_UNVERIFIED: Final = "capability.digest_unverified"
UNSIGNED_ENABLEMENT: Final = "capability.unsigned_enablement"

STARTUP_SERVING_WITHOUT_VERIFIER: Final = "startup.serving_without_verifier"
STARTUP_EFFECTS_WITHOUT_PERMIT_VERIFIER: Final = "startup.effects_without_permit_verifier"
STARTUP_TRANSPORT_WITHOUT_POLICY: Final = "startup.transport_without_policy"
STARTUP_AUTONOMY_WITHOUT_ACTIVATION: Final = "startup.autonomy_without_activation"
STARTUP_MONITORING_AS_PERMISSION: Final = "startup.monitoring_as_permission"
STARTUP_SERVING_IMPLIES_EFFECTS: Final = "startup.serving_implies_effects"

STARTUP_REFUSAL_CODES: Final[frozenset[str]] = frozenset({
    STARTUP_SERVING_WITHOUT_VERIFIER, STARTUP_EFFECTS_WITHOUT_PERMIT_VERIFIER,
    STARTUP_TRANSPORT_WITHOUT_POLICY, STARTUP_AUTONOMY_WITHOUT_ACTIVATION,
    STARTUP_MONITORING_AS_PERMISSION, STARTUP_SERVING_IMPLIES_EFFECTS, UNSIGNED_ENABLEMENT,
})

MONITORING_DENY: Final = "deny"
_DIGEST_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")
_RECORD_KEYS: Final = frozenset(
    {"schema", "record_id", "issued_at", "issuer", "capabilities", "binds", "signature"}
)
_RFC3339_UTC_RE: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z"
)
_MAX_RECORD_BYTES: Final = 64 * 1024


class OperatorSignatureVerifier(Protocol):
    """Injected port that verifies an operator signature over a record digest."""

    def verify(self, record_digest: str, signature: str) -> bool:
        """Return True only for a valid operator signature over ``record_digest``."""


class StartupRefused(Exception):
    """The composition was refused before dispatch; ``code`` is a stable startup code."""

    def __init__(self, code: str) -> None:
        """Record the stable refusal code (no paths, ids or policy internals)."""
        if code not in STARTUP_REFUSAL_CODES:
            raise ValueError(f"unknown startup refusal code {code!r}")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CapabilityView:
    """Effective capability bits plus the reason each differs from the record (if it does)."""

    effective: Mapping[str, bool]
    reasons: Mapping[str, str | None]
    record_state: str
    refusal: str | None = None

    def is_effective(self, bit: str) -> bool:
        """Return the effective value of ``bit``; an unknown name is False."""
        return self.effective.get(bit, False) is True

    def as_public(self) -> dict[str, Any]:
        """Return the non-sensitive readiness form: each bit, and why it differs from the record."""
        bits = {
            name: {"effective": self.is_effective(name), "reason": self.reasons.get(name)}
            for name in CAPABILITY_BITS
        }
        return {"record": self.record_state, "bits": bits}


@dataclass(frozen=True, slots=True)
class CapabilityConfig:
    """Everything the startup matrix inspects. Every field defaults to the denying value."""

    record: bytes | str | Mapping[str, Any] | None = None
    expected_binary_digest: str | None = None
    expected_config_digest: str | None = None
    signature_verifier: OperatorSignatureVerifier | None = None
    permit_verifier: object | None = None
    transport_policy: object | None = None
    activation_record: object | None = None
    monitoring_failure_mode: str = MONITORING_DENY
    effects_follow_serving: bool = False


def _deny(state: str) -> CapabilityView:
    """Return the all-false view for an unusable record, reporting ``state`` for every bit."""
    return CapabilityView(
        effective=MappingProxyType({name: False for name in CAPABILITY_BITS}),
        reasons=MappingProxyType({name: state for name in CAPABILITY_BITS}),
        record_state=state,
    )


def _parse(raw: bytes | str | Mapping[str, Any] | None) -> tuple[dict[str, Any] | None, str]:
    """Decode the raw record into a plain dict, or return the reason it cannot be used."""
    if raw is None:
        return None, REASON_MISSING
    if isinstance(raw, Mapping):
        return dict(raw), ""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > _MAX_RECORD_BYTES:
        return None, REASON_UNREADABLE
    try:
        decoded = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, REASON_UNREADABLE
    if not isinstance(decoded, dict):
        return None, REASON_MALFORMED
    return decoded, ""


def record_digest(record: Mapping[str, Any]) -> str:
    """Return the sha256 over the canonical record with its ``signature`` member removed."""
    body = {key: value for key, value in record.items() if key != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _shape_reason(record: Mapping[str, Any]) -> str | None:
    """Return the reason the record's shape is unusable, or None when it is well formed."""
    if record.get("schema") != CAPABILITY_SCHEMA:
        return REASON_SCHEMA
    if set(record) != _RECORD_KEYS:
        return REASON_MALFORMED
    for name in ("record_id", "issuer"):
        value = record[name]
        if not isinstance(value, str) or not value.strip():
            return REASON_MALFORMED
    issued = record["issued_at"]
    if not isinstance(issued, str) or not _RFC3339_UTC_RE.fullmatch(issued):
        return REASON_MALFORMED
    try:
        datetime.fromisoformat(issued.replace("Z", "+00:00"))
    except ValueError:
        return REASON_MALFORMED
    bits, binds = record["capabilities"], record["binds"]
    if not isinstance(bits, dict) or not isinstance(binds, dict):
        return REASON_MALFORMED
    if set(binds) != {"binary_digest", "config_digest"} or not all(
        isinstance(v, str) and _DIGEST_RE.fullmatch(v) for v in binds.values()
    ):
        return REASON_MALFORMED
    if any(name not in bits for name in CAPABILITY_BITS):
        return REASON_BIT_MISSING
    if set(bits) - set(CAPABILITY_BITS):
        return REASON_MALFORMED
    if any(type(bits[name]) is not bool for name in CAPABILITY_BITS):
        return REASON_BIT_NOT_BOOLEAN
    signature = record["signature"]
    if signature is not None and (not isinstance(signature, str) or not signature.strip()):
        return REASON_MALFORMED
    return None


def read_capability_record(
    raw: bytes | str | Mapping[str, Any] | None,
    *,
    expected_binary_digest: str | None = None,
    expected_config_digest: str | None = None,
    signature_verifier: OperatorSignatureVerifier | None = None,
) -> CapabilityView:
    """Pure reader: derive the effective bits from ``raw`` or deny every bit with a reason.

    Each bit is read on its own. No bit is derived from another. Any structural problem, an
    unknown schema, a non-boolean or missing bit, or a digest mismatch yields all-false. A true
    bit without an operator signature verified through ``signature_verifier`` yields all-false and
    ``refusal == "capability.unsigned_enablement"``, which startup turns into a refusal. When any
    bit is true the expected binary and config digests must be supplied and must match.
    """
    record, problem = _parse(raw)
    if record is None:
        return _deny(problem)
    shape = _shape_reason(record)
    if shape is not None:
        return _deny(shape)
    recorded = {name: record["capabilities"][name] for name in CAPABILITY_BITS}
    any_true = any(recorded.values())
    binds = record["binds"]
    for expected, actual in (
        (expected_binary_digest, binds["binary_digest"]),
        (expected_config_digest, binds["config_digest"]),
    ):
        if expected is not None and expected != actual:
            return _deny(REASON_DIGEST_MISMATCH)
        if expected is None and any_true:
            return _deny(REASON_DIGEST_UNVERIFIED)
    if any_true and not _signature_verified(record, signature_verifier):
        denied = _deny(UNSIGNED_ENABLEMENT)
        reasons = {n: (UNSIGNED_ENABLEMENT if recorded[n] else None) for n in CAPABILITY_BITS}
        return CapabilityView(
            denied.effective, MappingProxyType(reasons), UNSIGNED_ENABLEMENT, UNSIGNED_ENABLEMENT
        )
    return CapabilityView(
        effective=MappingProxyType(dict(recorded)),
        reasons=MappingProxyType({name: None for name in CAPABILITY_BITS}),
        record_state="valid",
    )


def _signature_verified(
    record: Mapping[str, Any], verifier: OperatorSignatureVerifier | None
) -> bool:
    """Return True only when the injected verifier accepts the record's signature."""
    signature = record["signature"]
    if verifier is None or not isinstance(signature, str):
        return False
    try:
        return verifier.verify(record_digest(record), signature) is True
    except Exception:  # noqa: BLE001 - an unavailable verifier is a deny, never an allow
        return False


def enforce_startup_matrix(
    view: CapabilityView, config: CapabilityConfig, *, verify_authority_available: bool
) -> None:
    """Raise ``StartupRefused`` for any forbidden combination, before anything is dispatched.

    Configuration contradictions are refused regardless of the bits: a monitoring failure mode
    other than ``deny`` and any wiring that derives ``effects`` from ``serving``. The bit-driven
    rows only fire for an effective ``True`` bit (which in R0-2 needs an injected, verified
    operator signature).
    """
    if view.refusal is not None:
        raise StartupRefused(view.refusal)
    if config.monitoring_failure_mode != MONITORING_DENY:
        raise StartupRefused(STARTUP_MONITORING_AS_PERMISSION)
    if config.effects_follow_serving:
        raise StartupRefused(STARTUP_SERVING_IMPLIES_EFFECTS)
    if view.is_effective("serving") and not verify_authority_available:
        raise StartupRefused(STARTUP_SERVING_WITHOUT_VERIFIER)
    if view.is_effective("effects") and config.permit_verifier is None:
        raise StartupRefused(STARTUP_EFFECTS_WITHOUT_PERMIT_VERIFIER)
    if view.is_effective("transport") and config.transport_policy is None:
        raise StartupRefused(STARTUP_TRANSPORT_WITHOUT_POLICY)
    if (
        view.is_effective("autonomous_settlement") or view.is_effective("continuation")
    ) and config.activation_record is None:
        raise StartupRefused(STARTUP_AUTONOMY_WITHOUT_ACTIVATION)


def capability_config_from_environ(environ: Mapping[str, str] = os.environ) -> CapabilityConfig:
    """Build a config from labels only: the record path and the two expected digests.

    A missing variable is a missing record; an unreadable file is passed on as unreadable bytes so
    the pure reader reports ``capability.record_unreadable``. Nothing here enables a bit.
    """
    path = environ.get("ORAMA_CAPABILITY_RECORD", "").strip()
    record: bytes | None = None
    if path:
        try:
            record = Path(path).read_bytes()
        except OSError:
            record = b"\xff"
    return CapabilityConfig(
        record=record,
        expected_binary_digest=environ.get("ORAMA_EXPECTED_BINARY_DIGEST") or None,
        expected_config_digest=environ.get("ORAMA_EXPECTED_CONFIG_DIGEST") or None,
    )


def evaluate(config: CapabilityConfig, *, verify_authority_available: bool) -> CapabilityView:
    """Read the record in ``config`` and enforce the startup matrix; return the view."""
    view = read_capability_record(
        config.record,
        expected_binary_digest=config.expected_binary_digest,
        expected_config_digest=config.expected_config_digest,
        signature_verifier=config.signature_verifier,
    )
    enforce_startup_matrix(view, config, verify_authority_available=verify_authority_available)
    return view
