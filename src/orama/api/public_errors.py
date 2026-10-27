"""Stable public error vocabulary for the serving surface (CONTRACT section 3; DRAFT).

Every body is exactly ``{"error": {"code", "correlation_id"}}`` plus ``"receipt_ref"`` inside the
error object when a durable record exists (a denial audit record, or the attempt record of an
in-doubt effect dispatch). Nothing else: no grant ids, key ids, paths or
policy internals. Internal verifier reasons, and the reasons of the effect send path, are mapped
to the closed public set here; an unmapped reason is reported as ``deny.verifier_unavailable``
(deny, never allow). The mapping tables live in ``orama.graph.effect_denial_codes``, so the attempt
store can record the public code without importing this layer; they are re-exported here.
``DENY_STATUS`` is the one HTTP status table for the public denial codes.

``install_public_error_handlers`` makes this the only error envelope of the whole app: validation
errors, unknown routes, wrong methods, framework ``HTTPException`` and any unhandled error are
answered with a public code, so no response carries a ``"detail"`` key or an internal reason.
"""
from __future__ import annotations

import logging
import uuid
from typing import Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from orama.graph.effect_denial_codes import (  # noqa: F401 - re-exported public names
    DENY_GRANT_CONFLICT,
    DENY_MALFORMED_GRANT,
    DENY_MISSING_CAPABILITY_RECORD,
    DENY_REVOCATION_STALE,
    DENY_REVOKED_GRANT,
    DENY_UNAUTHORIZED_CALLER,
    DENY_UNKNOWN_KEY,
    DENY_VERIFIER_UNAVAILABLE,
    public_adjustment_denial_code,
    public_denial_code,
    public_effect_denial_code,
)

_log = logging.getLogger(__name__)

SERVING_NOT_READY: Final = "serving.not_ready"
SERVING_ROUTE_NOT_EXPOSED: Final = "serving.route_not_exposed"

SERVING_CODES: Final[frozenset[str]] = frozenset(
    {SERVING_NOT_READY, SERVING_ROUTE_NOT_EXPOSED}
)
DENY_CODES: Final[frozenset[str]] = frozenset({
    DENY_REVOCATION_STALE, DENY_UNKNOWN_KEY, DENY_MALFORMED_GRANT, DENY_REVOKED_GRANT,
    DENY_MISSING_CAPABILITY_RECORD, DENY_UNAUTHORIZED_CALLER, DENY_VERIFIER_UNAVAILABLE,
    DENY_GRANT_CONFLICT,
})
PUBLIC_CODES: Final[frozenset[str]] = SERVING_CODES | DENY_CODES

DENY_STATUS: Final[dict[str, int]] = {
    DENY_MALFORMED_GRANT: 400,
    DENY_UNAUTHORIZED_CALLER: 401,
    DENY_GRANT_CONFLICT: 409,
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


def install_public_error_handlers(app: FastAPI) -> None:
    """Make the public envelope the app's only error shape (CONTRACT section 3).

    ``RequestValidationError`` is ``400 deny.malformed_grant``; an unknown route or a wrong method
    (404/405) is ``404 serving.route_not_exposed`` so route existence is not revealed; a router's own
    request rejection (400/413/422) is ``400 deny.malformed_grant``; every other
    ``HTTPException`` and any unhandled error is ``503 deny.verifier_unavailable``. The framework
    messages and validation details are logged under the correlation id and never returned.
    """

    async def validation_error(request: Request, error: Exception) -> JSONResponse:
        """Answer a request that failed validation with the public malformed denial."""
        correlation_id = new_correlation_id()
        _log.warning("request invalid", extra={"correlation_id": correlation_id})
        return error_response(400, DENY_MALFORMED_GRANT, correlation_id)

    async def http_error(request: Request, error: Exception) -> JSONResponse:
        """Answer a framework or router ``HTTPException`` with a public code, never its detail."""
        correlation_id = new_correlation_id()
        status = getattr(error, "status_code", 500)
        _log.warning("request refused", extra={"correlation_id": correlation_id, "status": status})
        if status in (404, 405):
            return error_response(404, SERVING_ROUTE_NOT_EXPOSED, correlation_id)
        if status in (400, 413, 422):  # a rejected request, not an outage: always the fixed 400
            return error_response(DENY_STATUS[DENY_MALFORMED_GRANT], DENY_MALFORMED_GRANT, correlation_id)
        return error_response(DENY_STATUS[DENY_VERIFIER_UNAVAILABLE], DENY_VERIFIER_UNAVAILABLE, correlation_id)

    async def unhandled_error(request: Request, error: Exception) -> JSONResponse:
        """Answer an unexpected error with the public deny that never allows.

        The exception is logged server-side under the same correlation id; the body carries none of it.
        """
        correlation_id = new_correlation_id()
        _log.error(
            "request failed",
            extra={"correlation_id": correlation_id, "exception_type": type(error).__name__},
            exc_info=(type(error), error, error.__traceback__),
        )
        return error_response(DENY_STATUS[DENY_VERIFIER_UNAVAILABLE], DENY_VERIFIER_UNAVAILABLE, correlation_id)

    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(StarletteHTTPException, http_error)
    app.add_exception_handler(Exception, unhandled_error)
