"""E1 "C2" dispatch permit replay protection.

Per the C2 permit-replay spec: a unique ``grant_id`` stops a second row but
does not prove that a repeat request is the same request. The issuer
therefore persists a binding digest, computed over 9 immutable request
fields, alongside the permit. On any request for a grant that already has ANY
permit (terminal or not), the issuer recomputes the digest and compares it
with the stored one. Retry identity is the binding digest AND ``attempt_id``;
``attempt_id`` is deliberately not part of the nine-field digest:

- Equal binding, equal ``attempt_id`` and not expired: an identical retry.
  The stored permit is returned unchanged, including its original ``issued_at``, ``expires_at`` and
  ``requested_at``.
- Equal but expired: NOT treated as an identical retry (see
  ``ExpiredPermit`` below) -- an expired stored permit is never revived.
- Different binding, or a NEW ``attempt_id``: a conflicting request for the
  same grant. Refused with the closed permit refusal ``permit.conflict``. The
  stored permit is NOT returned, nothing is created or changed. This holds
  even when the stored permit is terminal (expired/abandoned): terminal
  history is never hidden, so an ordinary request cannot mint a second permit.
  Successor issuance belongs to the attested replacement path, not here.

``requested_at`` is excluded from the binding digest: it is the consumer's
own clock reading, recorded on the first request only, never used for
identity/freshness/expiry, and a later retry's value is ignored.

This module is a pure reference model: it is NOT an authority store.

Collaborator contract: the store must return any existing permit of the
requested grant, and ``issue_new`` must return a permit for that grant carrying
the digest it was handed. These are the ports' own documented postconditions.
``decide_permit`` fails closed with ``ValueError`` (never a permit) when either is
violated. That is a collaborator bug, not a protocol refusal, so it is
deliberately outside the closed ``permit.*`` refusal vocabulary.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Literal, Protocol, TypeAlias

from orama.graph.binding_digest import BindingDigestFields, compute_binding_digest

PermitRefusalCode: TypeAlias = Literal["permit.conflict"]

CLOSED_PERMIT_REFUSAL_CODES: frozenset[str] = frozenset({"permit.conflict"})

PermitState: TypeAlias = Literal["issued", "finalized", "expired", "abandoned"]

NONTERMINAL_PERMIT_STATES: frozenset[str] = frozenset({"issued", "finalized"})


class PermitRefused(Exception):
    """Fail-closed permit refusal with an explicit closed reason code."""

    def __init__(self, code: PermitRefusalCode) -> None:
        """Initialize refusal with a verified closed reason code."""
        if code not in CLOSED_PERMIT_REFUSAL_CODES:
            raise ValueError(f"invalid refusal code {code!r}; must be in closed vocabulary")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DispatchPermit:
    """The issuer's persisted record of a dispatch permit.

    One table/record shape per the C2 spec's "Issuer storage" section. A
    partial unique constraint (enforced by the store, not this type) permits
    at most one nonterminal permit (state in ``issued``/``finalized``) per
    ``grant_id`` at a time.
    """

    permit_id: str
    grant_id: str
    binding_digest: str
    reservation_id: str
    request_digest: str
    attempt_id: str
    r_p: str
    consumer_acked_through: str
    requested_at: datetime
    issued_at: datetime
    expires_at: datetime
    permit_bytes: str
    state: PermitState
    finalization_bytes: str | None = None
    finalization_id: str | None = None
    replaces_permit_id: str | None = None

    def __post_init__(self) -> None:
        """Fail closed on invalid field invariants."""
        if not self.permit_id.strip():
            raise ValueError("permit_id is required")
        if not self.grant_id.strip():
            raise ValueError("grant_id is required")
        if not self.binding_digest.strip() or len(self.binding_digest) != 64:
            raise ValueError("binding_digest must be a 64-character hex digest")
        if not self.reservation_id.strip():
            raise ValueError("reservation_id is required")
        if not self.request_digest.strip():
            raise ValueError("request_digest is required")
        if not self.attempt_id.strip():
            raise ValueError("attempt_id is required")
        if not self.r_p.strip():
            raise ValueError("r_p is required")
        if not self.consumer_acked_through.strip():
            raise ValueError("consumer_acked_through is required")
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("requested_at must be an aware UTC datetime")
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("issued_at must be an aware UTC datetime")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be an aware UTC datetime")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly greater than issued_at")
        if not self.permit_bytes.strip():
            raise ValueError("permit_bytes is required")
        if self.state not in NONTERMINAL_PERMIT_STATES | {"expired", "abandoned"}:
            raise ValueError(f"invalid permit state {self.state!r}")


@dataclass(frozen=True, slots=True)
class PermitRequest:
    """The request-time inputs needed to decide/issue a permit.

    Bundles the 9 immutable binding-digest fields plus ``attempt_id`` (retry
    identity, not in the digest) and ``requested_at`` (excluded from the
    binding digest and ignored on retry).
    """

    grant_id: str
    grant_payload_digest: str
    operation_id: str
    request_digest: str
    artifact_digest: str
    reservation_id: str
    ledger_store_id: str
    configuration_policy_epoch: int
    authority_epoch: int
    attempt_id: str
    requested_at: datetime

    def __post_init__(self) -> None:
        """Fail closed on a blank attempt_id."""
        if not isinstance(self.attempt_id, str) or not self.attempt_id.strip():
            raise ValueError("attempt_id is required")

    def binding_fields(self) -> BindingDigestFields:
        """Project the 9 immutable fields into the shared digest input type."""
        return BindingDigestFields(
            grant_id=self.grant_id,
            grant_payload_digest=self.grant_payload_digest,
            operation_id=self.operation_id,
            request_digest=self.request_digest,
            artifact_digest=self.artifact_digest,
            reservation_id=self.reservation_id,
            ledger_store_id=self.ledger_store_id,
            configuration_policy_epoch=self.configuration_policy_epoch,
            authority_epoch=self.authority_epoch,
        )


class PermitStore(Protocol):
    """Issuer storage port for dispatch permits, injectable for testing."""

    def get_permit_for_grant(self, grant_id: str) -> DispatchPermit | None:
        """Return any existing permit for the grant (terminal or not), if any."""
        ...

    def insert_permit(self, permit: DispatchPermit) -> None:
        """Persist a brand-new permit for a grant that has no permit at all."""
        ...


class ExpiredPermit(Exception):
    """Raised when the stored permit matching a request's binding digest is expired.

    Per the spec, an expired stored permit is NOT revived and NOT returned as
    "the identical retry" -- expiry must be checked before deciding to return
    the stored permit. This signals that distinct case to the caller, who
    decides how to proceed (e.g. mark it expired and issue a replacement).
    """

    def __init__(self, permit: DispatchPermit) -> None:
        """Carry the expired stored permit for the caller's inspection."""
        super().__init__(f"permit {permit.permit_id} for grant {permit.grant_id} is expired")
        self.permit = permit


def decide_permit(
    request: PermitRequest,
    store: PermitStore,
    *,
    now: datetime,
    issue_new: Callable[[PermitRequest, str], DispatchPermit],
) -> DispatchPermit:
    """Decide and return the dispatch permit for ``request``.

    - No permit of any state exists for ``request.grant_id``: ``issue_new`` is
      called with the request and the freshly computed binding digest to
      construct and persist a brand-new permit, which is returned.
    - A permit exists with equal binding digest AND equal ``attempt_id``, is
      nonterminal and not expired: the existing permit is returned UNCHANGED.
    - Same identity but the stored state is ``expired`` or ``expires_at`` has
      passed: raises ``ExpiredPermit`` (never revived).
    - Same identity but the stored permit is ``abandoned``: ``permit.conflict``.
    - A different binding digest, or a NEW ``attempt_id`` (terminal or not):
      ``PermitRefused("permit.conflict")``; nothing is returned or created.

    Collaborator guards raise ``ValueError`` and return or store nothing: the
    store returning a permit for a different grant, or ``issue_new`` returning
    a permit whose ``grant_id``, ``binding_digest`` or ``attempt_id`` is not
    the requested one. They run before any protocol decision, so a
    collaborator bug is never misreported as ``permit.conflict``.
    """
    digest = compute_binding_digest(request.binding_fields())
    existing = store.get_permit_for_grant(request.grant_id)

    if existing is None:
        permit = issue_new(request, digest)
        if permit.grant_id != request.grant_id or permit.binding_digest != digest:
            raise ValueError(
                "issue_new must return a permit for the requested grant and binding digest"
            )
        if permit.attempt_id != request.attempt_id:
            raise ValueError("issue_new must return a permit carrying the request attempt_id")
        store.insert_permit(permit)
        return permit

    if existing.grant_id != request.grant_id:
        raise ValueError("PermitStore returned a permit for a different grant")

    if existing.binding_digest != digest or existing.attempt_id != request.attempt_id:
        raise PermitRefused("permit.conflict")

    if existing.state == "expired" or existing.expires_at <= now:
        raise ExpiredPermit(existing)

    if existing.state not in NONTERMINAL_PERMIT_STATES:
        raise PermitRefused("permit.conflict")

    return existing
