"""One verification-only route: ``POST /grants/verify`` (DRAFT; never spends, never mutates).

The route calls the injected verify-only authority and reports only ``verified`` or a stable public
denial. It holds no ledger handle, so it cannot consume a grant, settle a hold or touch an effect
attempt. Unless the ``serving`` capability is effective the route answers ``404
serving.route_not_exposed``. Every denial is appended to the durable audit log (when one is wired)
and the response carries its opaque ``receipt_ref``. Grant text and identifiers never appear in a
response, a log line or the audit record.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from orama.api.authz import authenticated_control_plane_principal
from orama.api.capabilities import CapabilityView
from orama.api.denial_audit import DenialAuditLog
from orama.api.public_errors import (
    DENY_MALFORMED_GRANT,
    DENY_UNAUTHORIZED_CALLER,
    DENY_VERIFIER_UNAVAILABLE,
    SERVING_NOT_READY,
    SERVING_ROUTE_NOT_EXPOSED,
    error_response,
    new_correlation_id,
    public_denial_code,
)
from orama.graph.grant_verifier import (
    AdjustmentGrantRefused,
    AdjustmentGrantVerifier,
    RevocationObservation,
)

_log = logging.getLogger(__name__)

VERIFY_PATH: Final = "/grants/verify"
REVOCATION_MAX_AGE: Final = timedelta(seconds=60)
MAX_BODY_BYTES: Final = 65_536
_STATUS: Final[dict[str, int]] = {
    "deny.malformed_grant": 400,
    "deny.unauthorized_caller": 401,
    "deny.unknown_key": 403,
    "deny.revoked_grant": 403,
    "deny.missing_capability_record": 403,
    "deny.revocation_stale": 503,
    "deny.verifier_unavailable": 503,
}


class _Denied(Exception):
    """Internal control flow: the request is denied with this public code."""

    def __init__(self, code: str) -> None:
        """Record the public code."""
        super().__init__(code)
        self.code = code


def _verify_only(verifier: AdjustmentGrantVerifier, wire: bytes, now: datetime) -> None:
    """Verify the grant and its revocation freshness; raise ``_Denied`` for anything else.

    This function only reads: it calls ``verify`` and ``revocation`` and discards the facts.
    """
    try:
        verified = verifier.verify(wire)
        grant_id = verified.grant_id
        if verified.expires_at <= now:
            raise AdjustmentGrantRefused("grant.expired")
        observation = verifier.revocation(grant_id)
        if not isinstance(observation, RevocationObservation) or observation.grant_id != grant_id:
            raise _Denied(DENY_VERIFIER_UNAVAILABLE)
        if observation.revoked:
            raise AdjustmentGrantRefused("grant.revoked")
        if abs(now - observation.observed_at) > REVOCATION_MAX_AGE:
            raise AdjustmentGrantRefused("revocation.stale")
    except _Denied:
        raise
    except AdjustmentGrantRefused as refused:
        raise _Denied(public_denial_code(refused.code)) from None
    except Exception:  # noqa: BLE001 - an unavailable or misbehaving verifier is a deny
        raise _Denied(DENY_VERIFIER_UNAVAILABLE) from None


def _parse_grant(body: bytes) -> bytes:
    """Return the grant wire from ``{"grant": "<text>"}`` or raise ``_Denied`` (malformed)."""
    if len(body) > MAX_BODY_BYTES + 64:
        raise _Denied(DENY_MALFORMED_GRANT)
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _Denied(DENY_MALFORMED_GRANT) from None
    grant = decoded.get("grant") if isinstance(decoded, dict) and set(decoded) == {"grant"} else None
    if not isinstance(grant, str) or not 2 <= len(grant) <= MAX_BODY_BYTES:
        raise _Denied(DENY_MALFORMED_GRANT)
    return grant.encode("utf-8")


def install_verify_route(
    app: FastAPI,
    *,
    capabilities: CapabilityView,
    grant_verifier: AdjustmentGrantVerifier | None,
    audit: DenialAuditLog | None,
    clock: Callable[[], datetime] | None = None,
) -> None:
    """Register ``POST /grants/verify``; it answers 404 unless ``serving`` is effective."""
    now_of = clock or (lambda: datetime.now(UTC))

    def deny(correlation_id: str, code: str) -> JSONResponse:
        """Record the denial durably when possible and answer with the public error."""
        receipt_ref: str | None = None
        if audit is not None:
            try:
                receipt_ref = audit.record(correlation_id, code, now_of())
            except Exception:  # noqa: BLE001 - audit trouble must not turn a denial into an allow
                _log.warning("denial audit unavailable", extra={"correlation_id": correlation_id})
        _log.warning("verify denied", extra={"correlation_id": correlation_id, "code": code})
        return error_response(_STATUS[code], code, correlation_id, receipt_ref)

    @app.post(VERIFY_PATH)
    async def verify_grant(request: Request) -> JSONResponse:
        """Verify one grant for verification only; no spend, no ledger, no effect."""
        correlation_id = new_correlation_id()
        if not capabilities.is_effective("serving"):
            return error_response(404, SERVING_ROUTE_NOT_EXPOSED, correlation_id)
        if grant_verifier is None:
            return error_response(503, SERVING_NOT_READY, correlation_id)
        if authenticated_control_plane_principal(request) is None:
            return deny(correlation_id, DENY_UNAUTHORIZED_CALLER)
        try:
            wire = _parse_grant(await request.body())
            await asyncio.to_thread(_verify_only, grant_verifier, wire, now_of())
        except _Denied as denied:
            return deny(correlation_id, denied.code)
        return JSONResponse({"status": "verified", "correlation_id": correlation_id})
