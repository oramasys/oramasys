"""Closed refusal vocabulary for the controller (doc 68 IC-24, contract section 7).

Every refusal carries a stable machine-readable code and the status class it maps to.
A refusal never carries proof material, lease tokens or request bodies.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

REFUSAL_STATUS: Mapping[str, int] = MappingProxyType({
    "envelope.invalid": 400,
    "envelope.projection_mismatch": 400,
    "transport.unverified": 401,
    "capability.missing": 401,
    "capability.invalid": 401,
    "capability.unverifiable": 401,
    "capability.expired": 401,
    "capability.revoked": 401,
    "capability.insufficient": 403,
    "capability.principal_mismatch": 403,
    "lease.principal_mismatch": 403,
    "lease.token_invalid": 403,
    "task.unknown": 404,
    "task.already_claimed": 409,
    "task.not_claimable": 409,
    "task.version_conflict": 409,
    "task.source_mismatch": 409,
    "task.declaration_conflict": 409,
    "lease.unknown": 409,
    "lease.not_active": 409,
    "lease.fenced": 409,
    "lease.expired": 409,
    "idempotency.key_reused": 409,
    "worker.owner_conflict": 409,
    "worker.fenced": 409,
    "controller.busy": 503,
})

CAPABILITY_DENIAL_CODES: frozenset[str] = frozenset({
    "capability.missing",
    "capability.invalid",
    "capability.unverifiable",
    "capability.expired",
    "capability.revoked",
    "capability.insufficient",
    "capability.principal_mismatch",
})


class ClaimRefused(Exception):
    """A determinate refusal: no claim state changed; ``code`` and ``status`` say why."""

    def __init__(self, code: str) -> None:
        """Bind a known refusal code to its status; an unknown code is a programming error."""
        if code not in REFUSAL_STATUS:
            raise ValueError(f"unknown refusal code: {code!r}")
        super().__init__(code)
        self.code = code
        self.status = REFUSAL_STATUS[code]
