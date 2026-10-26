"""``POST /effects/inert``: one inert send through the sealed final boundary (DRAFT).

The route is dark (``404 serving.route_not_exposed``) unless BOTH an inert sender is wired AND the
R0-2 ``effects`` capability is effective. In R0-2 no operator signature verifier is wired, so the
``effects`` bit can never be effective and the route never answers anything but 404 outside tests.

The only sender it accepts is ``FinalBoundarySender``: the grant composer verifies and binds, and
the send goes through ``authorize_final_boundary`` and ``begin_bound_send``. A plain callable (for
example one wrapping ``InertEffectDriver``) is refused when the app is built.

The request carries only ``{"attempt_id": "<id>"}``; authority and scope are server-owned. Every
error uses the contract body ``{"error": {"code", "correlation_id"}}`` with a public code (see
``public_effect_denial_code``); no grant id, internal reason or verifier text reaches a response.
Success returns the redacted receipt ``{attempt_ref, outcome, receipt_digest, recorded_at}``.

In-doubt dispatch: when the send marker committed but the outcome could not be proven
(``SendOutcomeUnknown``: the simulation failed or its settlement could not be recorded), the
answer is still ``503 deny.verifier_unavailable`` and additionally carries ``receipt_ref``, the
opaque reference of the durable attempt record (``attempt_ref_for``; the same reference the startup
reconciliation report lists and the eventual receipt carries). That is the contract's "receipt_ref
where a durable record exists": it lets the caller tell an in-doubt dispatch, which must be
reconciled by an operator and never retried, from a pre-dispatch deny, which never carries one.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from orama.api.authz import authenticated_control_plane_principal
from orama.api.capabilities import CapabilityView
from orama.api.public_errors import (
    DENY_MALFORMED_GRANT,
    DENY_STATUS,
    DENY_UNAUTHORIZED_CALLER,
    DENY_VERIFIER_UNAVAILABLE,
    SERVING_ROUTE_NOT_EXPOSED,
    error_response,
    new_correlation_id,
    public_effect_denial_code,
)
from orama.graph.effect_grant_composition import FinalBoundarySender
from orama.graph.effect_receipts import RedactedReceipt, attempt_ref_for
from orama.graph.sealed_inert_driver import SendOutcomeUnknown

_log = logging.getLogger(__name__)

INERT_PATH: Final = "/effects/inert"
MAX_BODY_BYTES: Final = 4096


class InertSendRequest(BaseModel):
    """Identify an already prepared attempt; authority and scope are server-owned."""

    model_config = ConfigDict(extra="forbid", strict=True)

    attempt_id: str = Field(min_length=1, max_length=1024)


class _Denied(Exception):
    """Internal control flow: the request is denied with this public code."""

    def __init__(self, code: str) -> None:
        """Record the public code."""
        super().__init__(code)
        self.code = code


def _internal_reason(error: BaseException) -> str | None:
    """Return the stable internal code or reason an effect refusal carries, if any."""
    for name in ("code", "reason"):
        value = getattr(error, name, None)
        if isinstance(value, str) and value:
            return value
    return None


async def _attempt_id(request: Request) -> str:
    """Read a bounded body and return its attempt id, or raise ``_Denied`` (malformed)."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_BYTES:
                raise _Denied(DENY_MALFORMED_GRANT)
        except ValueError:
            raise _Denied(DENY_MALFORMED_GRANT) from None
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > MAX_BODY_BYTES:
            raise _Denied(DENY_MALFORMED_GRANT)
    try:
        decoded = json.loads(bytes(received).decode("utf-8"))
        return InertSendRequest.model_validate(decoded).attempt_id
    except (ValueError, ValidationError, RecursionError):  # bad UTF-8, JSON or shape
        raise _Denied(DENY_MALFORMED_GRANT) from None


def install_inert_effect_route(
    app: FastAPI, *, capabilities: CapabilityView, sender: FinalBoundarySender | None
) -> None:
    """Register ``POST /effects/inert``; it answers 404 unless a sender is wired and effects hold.

    Raises ``TypeError`` when ``sender`` is anything but a ``FinalBoundarySender``, so the plain
    inert driver can never be reached from HTTP without the final boundary.
    """
    if sender is not None and not isinstance(sender, FinalBoundarySender):
        raise TypeError("the inert route accepts only the final-boundary sender")
    live = sender is not None and capabilities.is_effective("effects")
    if sender is not None and not live:
        _log.warning("inert sender supplied but the effects capability is not effective; route stays dark")

    def deny(
        correlation_id: str, code: str, reason: str | None = None, receipt_ref: str | None = None
    ) -> JSONResponse:
        """Log the denial with its correlation id and answer with the public error.

        ``receipt_ref`` is set only for an in-doubt dispatch (a durable attempt record exists).
        """
        _log.warning(
            "inert send denied",
            extra={
                "correlation_id": correlation_id, "code": code, "reason": reason,
                "receipt_ref": receipt_ref,
            },
        )
        return error_response(DENY_STATUS[code], code, correlation_id, receipt_ref)

    def on_auth_failure(request: Request) -> JSONResponse | None:
        """Answer a failed bearer check with the public denial, but only while the route is live."""
        if not live:
            return None
        return deny(new_correlation_id(), DENY_UNAUTHORIZED_CALLER, "bearer")

    handlers = getattr(app.state, "auth_failure_handlers", None)
    if not isinstance(handlers, dict):
        handlers = {}
        app.state.auth_failure_handlers = handlers
    handlers[INERT_PATH] = on_auth_failure

    @app.post(INERT_PATH)
    async def send_inert(request: Request) -> JSONResponse:
        """Send only a prebound inert attempt as the authenticated control-plane caller."""
        correlation_id = new_correlation_id()
        if not live or sender is None:
            return error_response(404, SERVING_ROUTE_NOT_EXPOSED, correlation_id)
        principal = authenticated_control_plane_principal(request)
        if principal is None:
            return deny(correlation_id, DENY_UNAUTHORIZED_CALLER, "unauthenticated")
        try:
            attempt_id = await _attempt_id(request)
            receipt = await asyncio.to_thread(sender, attempt_id, principal)
        except _Denied as denied:
            return deny(correlation_id, denied.code, "request")
        except SendOutcomeUnknown as unknown:
            # The send marker committed: in doubt, not refused. Same status and code, plus the
            # opaque reference of the durable attempt record for operator reconciliation.
            return deny(
                correlation_id, DENY_VERIFIER_UNAVAILABLE, unknown.reason,
                receipt_ref=attempt_ref_for(attempt_id),
            )
        except Exception as error:  # noqa: BLE001 - every refusal or failure is a public deny
            reason = _internal_reason(error)
            code = DENY_VERIFIER_UNAVAILABLE if reason is None else public_effect_denial_code(reason)
            return deny(correlation_id, code, reason or type(error).__name__)
        if not isinstance(receipt, RedactedReceipt):
            return deny(correlation_id, DENY_VERIFIER_UNAVAILABLE, "receipt_invalid")
        return JSONResponse({"receipt": receipt.as_dict(), "correlation_id": correlation_id})
