"""Stable public error vocabulary for the serving surface (CONTRACT section 3; DRAFT).

Every body is exactly ``{"error": {"code", "correlation_id"}}`` plus ``"receipt_ref"`` inside the
error object when a durable audit record exists. Nothing else: no grant ids, key ids, paths or
policy internals. Internal verifier reasons, and the reasons of the effect send path, are mapped
to the closed public set here; an unmapped reason is reported as ``deny.verifier_unavailable``
(deny, never allow). ``DENY_STATUS`` is the one HTTP status table for the public denial codes.
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


DENY_STATUS: Final[dict[str, int]] = {
    DENY_MALFORMED_GRANT: 400,
    DENY_UNAUTHORIZED_CALLER: 401,
    DENY_UNKNOWN_KEY: 403,
    DENY_REVOKED_GRANT: 403,
    DENY_MISSING_CAPABILITY_RECORD: 403,
    DENY_REVOCATION_STALE: 503,
    DENY_VERIFIER_UNAVAILABLE: 503,
}

# Internal reasons of the effect send path (``POST /effects/inert``: the grant composer, the sealed
# final boundary and the attempt store) mapped to the closed public set. Contract section 3 has no
# finer code, so:
# * a caller that is not the attempt's bound principal is ``deny.unauthorized_caller``;
# * any binding, expiry, approval, replay or envelope difference (the attempt as presented cannot
#   be authorized) is ``deny.malformed_grant``;
# * any revocation fact is ``deny.revoked_grant``;
# * an attempt refused because the effects capability was not effective is
#   ``deny.missing_capability_record``;
# * a verifier, clock or outcome that cannot be vouched for is ``deny.verifier_unavailable``,
#   which is also the answer for every unmapped reason (deny, never allow).
# The verifier codes in ``_INTERNAL_TO_PUBLIC`` apply unchanged.
_EFFECT_TO_PUBLIC: Final[dict[str, str]] = {
    "effect.principal_mismatch": DENY_UNAUTHORIZED_CALLER,
    "principal_mismatch": DENY_UNAUTHORIZED_CALLER,
    **{
        reason: DENY_MALFORMED_GRANT
        for reason in (
            "effect.binding_mismatch", "effect_grant_binding_missing", "attempt_not_authorized",
            "attempt_refused", "send_already_started", "operation_digest_mismatch",
            "target_mismatch", "epoch_mismatch", "expiry_mismatch", "epoch_stale", "expired",
            "approval_not_verified", "approval_undeclared", "approval_missing",
            "approval_consumed", "approval_mismatch", "approval_expired", "inert_scope_required",
            "send_precondition_failed", "send_authority_expired_or_missing",
            "replay_envelope_mismatch", "effect_grant_bound_send_required",
        )
    },
    **{
        reason: DENY_REVOKED_GRANT
        for reason in (
            "grant_revoked", "issuer_revoked", "approval_revoked", "cascade_listed",
            "send_authority_revoked",
        )
    },
    "effects_denied": DENY_MISSING_CAPABILITY_RECORD,
    **{
        reason: DENY_VERIFIER_UNAVAILABLE
        for reason in (
            "approval_verifier_missing", "approval_verifier_unavailable",
            "send_clock_quarantined", "outcome_unknown", "evidence_invalid",
            "effect_grant_recheck_required",
        )
    },
}


def public_denial_code(internal_reason: str) -> str:
    """Map a verifier-internal reason to the closed public set; unknown reasons deny as unavailable."""
    return _INTERNAL_TO_PUBLIC.get(internal_reason, DENY_VERIFIER_UNAVAILABLE)


def public_effect_denial_code(internal_reason: str) -> str:
    """Map an effect send-path reason to the closed public set (see ``_EFFECT_TO_PUBLIC``).

    Sealed-envelope refusals (``envelope_*``) are ``deny.malformed_grant``; verifier codes map as in
    ``public_denial_code``; anything else is ``deny.verifier_unavailable``.
    """
    if internal_reason in _EFFECT_TO_PUBLIC:
        return _EFFECT_TO_PUBLIC[internal_reason]
    if internal_reason.startswith("envelope_"):
        return DENY_MALFORMED_GRANT
    return public_denial_code(internal_reason)


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
