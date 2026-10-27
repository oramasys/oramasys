"""Stable public error vocabulary for the serving surface (CONTRACT section 3; DRAFT).

Every body is exactly ``{"error": {"code", "correlation_id"}}`` plus ``"receipt_ref"`` inside the
error object when a durable record exists (a denial audit record, or the attempt record of an
in-doubt effect dispatch). Nothing else: no grant ids, key ids, paths or
policy internals. Internal verifier reasons, and the reasons of the effect send path, are mapped
to the closed public set here; an unmapped reason is reported as ``deny.verifier_unavailable``
(deny, never allow). The mapping tables live in ``orama.graph.effect_denial_codes``, so the attempt
store can record the public code without importing this layer; they are re-exported here.
``DENY_STATUS`` is the one HTTP status table for the public denial codes.
"""
from __future__ import annotations

import uuid
from typing import Final

from fastapi.responses import JSONResponse

from orama.graph.effect_denial_codes import (  # noqa: F401 - re-exported public names
    DENY_MALFORMED_GRANT,
    DENY_MISSING_CAPABILITY_RECORD,
    DENY_REVOCATION_STALE,
    DENY_REVOKED_GRANT,
    DENY_UNAUTHORIZED_CALLER,
    DENY_UNKNOWN_KEY,
    DENY_VERIFIER_UNAVAILABLE,
    public_denial_code,
    public_effect_denial_code,
)

SERVING_NOT_READY: Final = "serving.not_ready"
SERVING_DISABLED: Final = "serving.disabled"
SERVING_ROUTE_NOT_EXPOSED: Final = "serving.route_not_exposed"

SERVING_CODES: Final[frozenset[str]] = frozenset(
    {SERVING_NOT_READY, SERVING_DISABLED, SERVING_ROUTE_NOT_EXPOSED}
)
DENY_CODES: Final[frozenset[str]] = frozenset({
    DENY_REVOCATION_STALE, DENY_UNKNOWN_KEY, DENY_MALFORMED_GRANT, DENY_REVOKED_GRANT,
    DENY_MISSING_CAPABILITY_RECORD, DENY_UNAUTHORIZED_CALLER, DENY_VERIFIER_UNAVAILABLE,
})
PUBLIC_CODES: Final[frozenset[str]] = SERVING_CODES | DENY_CODES

DENY_STATUS: Final[dict[str, int]] = {
    DENY_MALFORMED_GRANT: 400,
    DENY_UNAUTHORIZED_CALLER: 401,
    DENY_UNKNOWN_KEY: 403,
    DENY_REVOKED_GRANT: 403,
    DENY_MISSING_CAPABILITY_RECORD: 403,
    DENY_REVOCATION_STALE: 503,
    DENY_VERIFIER_UNAVAILABLE: 503,
}

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
