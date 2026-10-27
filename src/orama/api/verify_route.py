"""One verification-only route: ``POST /grants/verify`` (DRAFT; never spends, never mutates).

The route calls the injected verify-only authority and reports only ``verified`` or a stable public
denial. It holds no ledger handle, so it cannot consume a grant, settle a hold or touch an effect
attempt. Unless the ``serving`` capability is effective the route answers ``404
serving.route_not_exposed``. Durable audit entries are bounded for repeated authentication failures;
other denials are appended when an audit log is wired. A recorded denial carries an opaque
``receipt_ref``. Grant text and identifiers never appear in a response, a log line or the audit
record.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
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
    DENY_STATUS,
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
    revocation_observation_fresh,
)

_log = logging.getLogger(__name__)

VERIFY_PATH: Final = "/grants/verify"
MAX_BODY_BYTES: Final = 65_536
_BODY_LIMIT: Final = MAX_BODY_BYTES + 64
_STATUS: Final[dict[str, int]] = DENY_STATUS
AUTH_FAILURE_AUDIT_WINDOW: Final = timedelta(minutes=1)
AUTH_FAILURE_AUDIT_LIMIT: Final = 60


class _Denied(Exception):
    """Internal control flow: the request is denied with this public code."""

    def __init__(self, code: str) -> None:
        """Record the public code."""
        super().__init__(code)
        self.code = code


def _verify_only(
    verifier: AdjustmentGrantVerifier, wire: bytes, now_of: Callable[[], datetime]
) -> None:
    """Verify the grant and its revocation freshness; raise ``_Denied`` for anything else.

    This function only reads: it calls ``verify`` and ``revocation`` and discards the facts. The
    order is verify, then fetch the observation by grant id, then freshness; ``now`` is read only
    after the observation is fetched, so time spent in the verifier or the fetch cannot make an old
    reading look fresh. The
    freshness rule is ``revocation_observation_fresh`` (stale if older than 60 s, more than 5 s in
    the future, or naive).
    """
    try:
        verified = verifier.verify(wire)
        grant_id = verified.grant_id
        observation = verifier.revocation(grant_id)
        now = now_of()
        if verified.expires_at <= now:
            raise AdjustmentGrantRefused("grant.expired")
        if not isinstance(observation, RevocationObservation) or observation.grant_id != grant_id:
            raise _Denied(DENY_VERIFIER_UNAVAILABLE)
        if observation.revoked:
            raise AdjustmentGrantRefused("grant.revoked")
        if not revocation_observation_fresh(now, observation.observed_at):
            raise AdjustmentGrantRefused("revocation.stale")
    except _Denied:
        raise
    except AdjustmentGrantRefused as refused:
        raise _Denied(public_denial_code(refused.code)) from None
    except Exception:  # noqa: BLE001 - an unavailable or misbehaving verifier is a deny
        raise _Denied(DENY_VERIFIER_UNAVAILABLE) from None


async def _read_bounded_body(request: Request) -> bytes:
    """Read the request body in chunks and stop as soon as it exceeds the size limit.

    A declared ``Content-Length`` over the limit is refused without reading; a streamed body is cut
    off at the limit, so a rejected upload never buffers more than the limit.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > _BODY_LIMIT:
                raise _Denied(DENY_MALFORMED_GRANT)
        except ValueError:
            raise _Denied(DENY_MALFORMED_GRANT) from None
    received = bytearray()
    async for chunk in request.stream():
        if len(received) + len(chunk) > _BODY_LIMIT:
            raise _Denied(DENY_MALFORMED_GRANT)
        received.extend(chunk)
    return bytes(received)


def _parse_grant(body: bytes) -> bytes:
    """Return the grant wire from ``{"grant": "<text>"}`` or raise ``_Denied`` (malformed)."""
    if len(body) > _BODY_LIMIT:
        raise _Denied(DENY_MALFORMED_GRANT)
    try:
        decoded = json.loads(body.decode("utf-8"))
        grant = (
            decoded.get("grant") if isinstance(decoded, dict) and set(decoded) == {"grant"} else None
        )
        if not isinstance(grant, str) or not 2 <= len(grant) <= MAX_BODY_BYTES:
            raise _Denied(DENY_MALFORMED_GRANT)
        return grant.encode("utf-8")
    except _Denied:
        raise
    except (ValueError, RecursionError, MemoryError):  # includes bad UTF-8 and lone surrogates
        raise _Denied(DENY_MALFORMED_GRANT) from None


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
    auth_failure_lock = threading.Lock()
    auth_failure_window_start: datetime | None = None
    audited_auth_failures = 0

    def audit_timestamp(code: str) -> datetime | None:
        """Return a timestamp when this denial may be appended to the durable audit log."""
        nonlocal auth_failure_window_start, audited_auth_failures
        now = now_of()
        if code != DENY_UNAUTHORIZED_CALLER:
            return now
        with auth_failure_lock:
            if auth_failure_window_start is None or now - auth_failure_window_start >= AUTH_FAILURE_AUDIT_WINDOW:
                auth_failure_window_start = now
                audited_auth_failures = 0
            elif now < auth_failure_window_start:
                return None
            if audited_auth_failures >= AUTH_FAILURE_AUDIT_LIMIT:
                return None
            audited_auth_failures += 1
        return now

    def deny(correlation_id: str, code: str) -> JSONResponse:
        """Record the denial durably when possible and answer with the public error."""
        receipt_ref: str | None = None
        audit_now = audit_timestamp(code)
        if audit is not None and audit_now is not None:
            try:
                receipt_ref = audit.record(correlation_id, code, audit_now)
            except Exception:  # noqa: BLE001 - audit trouble must not turn a denial into an allow
                _log.warning("denial audit unavailable", extra={"correlation_id": correlation_id})
        _log.warning("verify denied", extra={"correlation_id": correlation_id, "code": code})
        return error_response(_STATUS[code], code, correlation_id, receipt_ref)

    def on_auth_failure(request: Request) -> JSONResponse | None:
        """Answer a failed bearer check on this route with the public denial and its audit record.

        Only when the route is live (serving effective and a verifier wired); otherwise return None
        so the middleware keeps its plain 401. Bearer enforcement itself stays in the middleware.
        """
        if not capabilities.is_effective("serving") or grant_verifier is None:
            return None
        return deny(new_correlation_id(), DENY_UNAUTHORIZED_CALLER)

    handlers = getattr(app.state, "auth_failure_handlers", None)
    if not isinstance(handlers, dict):
        handlers = {}
        app.state.auth_failure_handlers = handlers
    handlers[VERIFY_PATH] = on_auth_failure

    @app.post(VERIFY_PATH)
    async def verify_grant(request: Request) -> JSONResponse:
        """Verify one grant for verification only; no spend, no ledger, no effect."""
        correlation_id = new_correlation_id()
        if not capabilities.is_effective("serving"):
            return error_response(404, SERVING_ROUTE_NOT_EXPOSED, correlation_id)
        if grant_verifier is None:
            return error_response(503, SERVING_NOT_READY, correlation_id)
        if authenticated_control_plane_principal(request) is None:
            return await asyncio.to_thread(deny, correlation_id, DENY_UNAUTHORIZED_CALLER)
        try:
            wire = _parse_grant(await _read_bounded_body(request))
            await asyncio.to_thread(_verify_only, grant_verifier, wire, now_of)
        except _Denied as denied:
            return await asyncio.to_thread(deny, correlation_id, denied.code)
        return JSONResponse({"status": "verified", "correlation_id": correlation_id})
