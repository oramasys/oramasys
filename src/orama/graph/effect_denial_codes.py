"""Internal refusal reason to public ``deny.*`` code mapping (CONTRACT section 3; DRAFT).

This is a pure, dependency-free table so the attempt store (graph layer) can decide the public
code once, when it records a terminal refusal, without importing the serving layer. The serving
layer (``orama.api.public_errors``) re-exports these names; the closed public vocabulary and the
rule that an unmapped reason denies as ``deny.verifier_unavailable`` live here and nowhere else.
"""
from __future__ import annotations

from typing import Final

DENY_REVOCATION_STALE: Final = "deny.revocation_stale"
DENY_UNKNOWN_KEY: Final = "deny.unknown_key"
DENY_MALFORMED_GRANT: Final = "deny.malformed_grant"
DENY_REVOKED_GRANT: Final = "deny.revoked_grant"
DENY_MISSING_CAPABILITY_RECORD: Final = "deny.missing_capability_record"
DENY_UNAUTHORIZED_CALLER: Final = "deny.unauthorized_caller"
DENY_VERIFIER_UNAVAILABLE: Final = "deny.verifier_unavailable"
DENY_GRANT_CONFLICT: Final = "deny.grant_conflict"

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
# The verifier codes in ``_INTERNAL_TO_PUBLIC`` apply unchanged. An in-doubt dispatch (the send
# marker committed; ``outcome_unknown``, ``evidence_invalid``, ``outcome_unrecorded``) is also
# ``deny.verifier_unavailable`` (503), and the route adds the attempt's opaque ``receipt_ref``
# because a durable record exists. A pre-dispatch refusal that wrote the terminal refusal record also
# carries that record's ``receipt_ref`` (and replays with the stored code); a deny that left no
# durable record carries none.
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
            "replay_envelope_mismatch", "effect_grant_bound_send_required", "effect.lease_stale",
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
            "send_clock_quarantined", "outcome_unknown", "evidence_invalid", "outcome_unrecorded",
            "effect_grant_recheck_required", "send_authority_issuer_mismatch", "send_lease_unavailable",
        )
    },
}


# Adjustment-route refusals (``POST /adjustments``): a grant that verified but could not be consumed.
# The ledger's answer is definitive ("do not retry"), so it keeps HTTP 409, but the public code hides
# the internal reason: hold_ineligible, units_exceed_remaining, digest_conflict, epoch_fenced,
# basis_mismatch and store_mismatch are all ``deny.grant_conflict``. A caller that is not the grant's
# principal is ``deny.unauthorized_caller``, and a clock that cannot be vouched for is
# ``deny.verifier_unavailable``. Verification codes use ``public_denial_code`` unchanged.
_ADJUSTMENT_TO_PUBLIC: Final[dict[str, str]] = {
    "grant.principal_mismatch": DENY_UNAUTHORIZED_CALLER,
    "grant.clock_regressed": DENY_VERIFIER_UNAVAILABLE,
    **{
        reason: DENY_GRANT_CONFLICT
        for reason in (
            "grant.store_mismatch", "grant.epoch_fenced", "grant.hold_ineligible",
            "grant.basis_mismatch", "grant.units_exceed_remaining", "grant.digest_conflict",
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


def public_adjustment_denial_code(internal_reason: str) -> str:
    """Map an adjustment refusal code to the closed public set; unknown codes deny as unavailable.

    Ledger consumption refusals become ``deny.grant_conflict`` (409), the principal refusal
    ``deny.unauthorized_caller`` and any verification code maps as in ``public_denial_code``.
    """
    if internal_reason in _ADJUSTMENT_TO_PUBLIC:
        return _ADJUSTMENT_TO_PUBLIC[internal_reason]
    return public_denial_code(internal_reason)
