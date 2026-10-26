"""Stable public error vocabulary for the serving surface (CONTRACT section 3; DRAFT).

Every body is exactly ``{"error": {"code", "correlation_id"}}`` plus ``"receipt_ref"`` inside the
error object when a durable audit record exists. Nothing else: no grant ids, key ids, paths or
policy internals. Internal verifier reasons are mapped to the closed public set here; an
unmapped reason is reported as ``deny.verifier_unavailable`` (deny, never allow).
"""
from __future__ import annotations

import uuid
from typing import Final

from fastapi.responses import JSONResponse

SERVING_NOT_READY: Final = "serving.not_ready"
SERVING_DISABLED: Final = "serving.disabled"
SERVING_ROUTE_NOT_EXPOSED: Final = "serving.route_not_exposed"

DENY_REVOCATION_STALE: Final = "deny.revocation_stale"
DENY_UNKNOWN_KEY: Final = "deny.unknown_key"
DENY_MALFORMED_GRANT: Final = "deny.malformed_grant"
DENY_REVOKED_GRANT: Final = "deny.revoked_grant"
DENY_MISSING_CAPABILITY_RECORD: Final = "deny.missing_capability_record"
DENY_UNAUTHORIZED_CALLER: Final = "deny.unauthorized_caller"
DENY_VERIFIER_UNAVAILABLE: Final = "deny.verifier_unavailable"

SERVING_CODES: Final[frozenset[str]] = frozenset(
    {SERVING_NOT_READY, SERVING_DISABLED, SERVING_ROUTE_NOT_EXPOSED}
)
DENY_CODES: Final[frozenset[str]] = frozenset({
    DENY_REVOCATION_STALE, DENY_UNKNOWN_KEY, DENY_MALFORMED_GRANT, DENY_REVOKED_GRANT,
    DENY_MISSING_CAPABILITY_RECORD, DENY_UNAUTHORIZED_CALLER, DENY_VERIFIER_UNAVAILABLE,
})
PUBLIC_CODES: Final[frozenset[str]] = SERVING_CODES | DENY_CODES

_INTERNAL_TO_PUBLIC: Final[dict[str, str]] = {
    "revocation.stale": DENY_REVOCATION_STALE,
    "grant.key_unknown": DENY_UNKNOWN_KEY,
    "grant.malformed": DENY_MALFORMED_GRANT,
    "grant.schema_unsupported": DENY_MALFORMED_GRANT,
    "grant.signature_invalid": DENY_MALFORMED_GRANT,
    "grant.expired": DENY_MALFORMED_GRANT,
    "grant.future_dated": DENY_MALFORMED_GRANT,
    "grant.revoked": DENY_REVOKED_GRANT,
    "verifier.unavailable": DENY_VERIFIER_UNAVAILABLE,
}


def public_denial_code(internal_reason: str) -> str:
    """Map a verifier-internal reason to the closed public set; unknown reasons deny as unavailable."""
    return _INTERNAL_TO_PUBLIC.get(internal_reason, DENY_VERIFIER_UNAVAILABLE)


def new_correlation_id() -> str:
    """Return a fresh opaque correlation id."""
    return str(uuid.uuid4())


def error_body(code: str, correlation_id: str, receipt_ref: str | None = None) -> dict[str, dict[str, str]]:
    """Build the one public error shape; ``code`` must be in the public vocabulary."""
    if code not in PUBLIC_CODES:
        raise ValueError(f"{code!r} is not a public error code")
    error = {"code": code, "correlation_id": correlation_id}
    if receipt_ref is not None:
        error["receipt_ref"] = receipt_ref
    return {"error": error}


def error_response(
    status_code: int, code: str, correlation_id: str, receipt_ref: str | None = None
) -> JSONResponse:
    """Return the public error as a JSON response with the given HTTP status."""
    return JSONResponse(status_code=status_code, content=error_body(code, correlation_id, receipt_ref))
