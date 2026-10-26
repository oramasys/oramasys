"""Final-boundary authorization: re-verify the approval at the last step before dispatch (DRAFT).

Admission already asked the verifier once; that check is not the final check. Immediately before an
effect is sent, this boundary verifies again, bound to the exact attempt tuple: attempt id,
principal, operation digest, target, fencing epoch and expiry. Every field is compared with what the
store durably recorded at authorization. A changed field is a different attempt and is refused
without recording anything against the original attempt. Anything the boundary cannot prove (effects
denied, no permit verifier, verifier unavailable or unconvinced, revoked, stale epoch, expired) is
refused BEFORE dispatch and, because it concerns this very attempt, recorded as a terminal refusal.
There is no "verify later". A revocation never touches work already in doubt: an attempt whose send
started stays ``unknown`` and is reported as ``send_already_started``.

Product code stays Phylax-free: the approval verifier, the effects switch and the revocation port
are injected. This module performs no I/O of its own.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol

from orama.graph.effect_fencing import StoredRefusal
from orama.graph.effect_outcomes import OutcomeRefused

TERMINAL_REASONS: Final[frozenset[str]] = frozenset({
    "effects_denied", "approval_verifier_missing", "approval_verifier_unavailable",
    "approval_not_verified", "epoch_stale", "expired", "grant_revoked", "issuer_revoked",
    "approval_revoked", "cascade_listed", "approval_undeclared",
})


class FinalBoundaryRefused(OutcomeRefused):
    """The final boundary refused before dispatch; ``reason`` is a stable code.

    ``terminal`` is True when the refusal is (or already was) recorded against the attempt itself.
    """

    def __init__(self, reason: str, *, terminal: bool = False) -> None:
        """Store the stable reason and whether it is terminal for the attempt."""
        super().__init__(reason)
        self.terminal = terminal


@dataclass(frozen=True, slots=True)
class FinalBoundaryBinding:
    """The exact tuple a final-boundary verification and a single-use approval are bound to."""

    attempt_id: str
    principal: str
    operation_digest: str
    target: str
    epoch: int
    expires_at: datetime

    def __post_init__(self) -> None:
        """Refuse a blank, mistyped or naive binding before it can be compared or verified."""
        for name in ("attempt_id", "principal", "operation_digest", "target"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-blank text")
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or self.epoch < 1:
            raise ValueError("epoch must be an integer of at least 1")
        if (
            not isinstance(self.expires_at, datetime)
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise ValueError("expires_at must be an aware datetime")


class ApprovalVerifier(Protocol):
    """Injected port that verifies the bound approval; the composition root adapts Phylax to it."""

    def verify(self, binding: FinalBoundaryBinding) -> bool:
        """Return True only if the approval for exactly this binding is valid and unrevoked."""


class RevocationLookup(Protocol):
    """Injected view of acknowledged issuer revocations (same shape as the store's port)."""

    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        """Return True if an acknowledged event revokes the grant, its approval chain or issuer."""


@dataclass(frozen=True, slots=True)
class StoredBinding:
    """What the attempt store durably recorded for an attempt; ``None`` fields were never recorded."""

    attempt_id: str
    state: str
    grant_id: str
    principal: str | None
    operation_digest: str | None
    target: str | None
    expires_at: datetime | None
    epoch: int | None
    current_epoch: int | None
    send_started: bool
    outcome: str | None
    refusal: StoredRefusal | None


class BindingStore(Protocol):
    """The slice of the attempt store the final boundary needs."""

    def attempt_binding(self, attempt_id: str) -> StoredBinding | None:
        """Return the durable binding for the attempt, or None when the attempt is unknown."""

    def revocation_refusal(self, attempt_id: str, issuer_id: str) -> str | None:
        """Return the locally recorded revocation reason for the attempt, or None."""

    def record_terminal_refusal(
        self, attempt_id: str, kind: str, rule: str | None, reason: str, now: datetime
    ) -> StoredRefusal:
        """Record a terminal refusal for the attempt identity."""


def _normal_digest(value: str) -> str:
    """Return the ``sha256:``-prefixed form of a digest for comparison."""
    return value if value.startswith("sha256:") else f"sha256:{value}"


def check_store_facts(stored: StoredBinding | None, binding: FinalBoundaryBinding, now: datetime) -> None:
    """Compare ``binding`` with the durable record; raise ``FinalBoundaryRefused`` on any difference.

    This is the store-visible half of the boundary. It is pure, so the attempt store can run it again
    inside the transaction that starts the send, closing the check-then-act gap.
    """
    if stored is None or stored.state != "authorized":
        raise FinalBoundaryRefused("attempt_not_authorized")
    if stored.refusal is not None:
        raise FinalBoundaryRefused(stored.refusal.reason, terminal=True)
    if stored.send_started:
        raise FinalBoundaryRefused("send_already_started")
    if stored.principal != binding.principal:
        raise FinalBoundaryRefused("principal_mismatch")
    if stored.operation_digest is None or _normal_digest(stored.operation_digest) != _normal_digest(
        binding.operation_digest
    ):
        raise FinalBoundaryRefused("operation_digest_mismatch")
    if stored.target != binding.target:
        raise FinalBoundaryRefused("target_mismatch")
    if stored.epoch is None or stored.epoch != binding.epoch:
        raise FinalBoundaryRefused("epoch_mismatch")
    if stored.expires_at is None or stored.expires_at != binding.expires_at.astimezone(UTC):
        raise FinalBoundaryRefused("expiry_mismatch")
    if stored.current_epoch is None or stored.current_epoch != stored.epoch:
        raise FinalBoundaryRefused("epoch_stale", terminal=True)
    if now.astimezone(UTC) >= stored.expires_at:
        raise FinalBoundaryRefused("expired", terminal=True)


def _effects_allowed(probe: Callable[[], bool] | None) -> bool:
    """Return True only when the effects switch answers exactly True; absence or failure denies."""
    if probe is None:
        return False
    try:
        return probe() is True
    except Exception:  # noqa: BLE001 - a failing switch is a deny
        return False


def authorize_final_boundary(
    store: BindingStore,
    binding: FinalBoundaryBinding,
    *,
    effects_allowed: Callable[[], bool] | None,
    approval_verifier: ApprovalVerifier | None,
    revocations: RevocationLookup | None,
    issuer_id: str,
    now: datetime,
) -> None:
    """Re-verify the bound approval at the last step; return only if dispatch may begin.

    Order: durable facts (a mismatch is a different attempt and is not recorded), then the effects
    switch, then revocation, then the injected approval verifier. Any refusal that concerns this
    attempt is recorded as terminal before it is raised.
    """
    stored = store.attempt_binding(binding.attempt_id)
    try:
        check_store_facts(stored, binding, now)
        if not _effects_allowed(effects_allowed):
            raise FinalBoundaryRefused("effects_denied", terminal=True)
        local = store.revocation_refusal(binding.attempt_id, issuer_id)
        if local is not None:
            raise FinalBoundaryRefused(local, terminal=True)
        _verify_revocation_and_approval(stored, binding, approval_verifier, revocations, issuer_id)
    except FinalBoundaryRefused as refusal:
        if refusal.terminal and refusal.reason in TERMINAL_REASONS and stored is not None \
                and stored.refusal is None:
            _record_terminal_refusal(store, binding.attempt_id, refusal.reason, now)
        raise


def _record_terminal_refusal(
    store: BindingStore, attempt_id: str, reason: str, now: datetime
) -> None:
    """Record a boundary refusal unless another caller already started the send."""
    # dispatch_attempts imports this module, so resolve its state error only after both load.
    from orama.graph.dispatch_attempts import AttemptStateError

    try:
        store.record_terminal_refusal(attempt_id, "final_boundary", None, reason, now)
    except AttemptStateError as error:
        if str(error) != "send_already_started":
            raise
        raise FinalBoundaryRefused("send_already_started") from error


def _verify_revocation_and_approval(
    stored: StoredBinding | None,
    binding: FinalBoundaryBinding,
    approval_verifier: ApprovalVerifier | None,
    revocations: RevocationLookup | None,
    issuer_id: str,
) -> None:
    """Ask the injected revocation view and approval verifier; refuse unless both are positive."""
    if stored is None:
        raise FinalBoundaryRefused("attempt_not_authorized")
    if revocations is None:
        raise FinalBoundaryRefused("approval_verifier_unavailable", terminal=True)
    try:
        revoked = revocations.revoked(grant_id=stored.grant_id, issuer_id=issuer_id)
    except Exception:  # noqa: BLE001 - an unavailable revocation view is a deny
        raise FinalBoundaryRefused("approval_verifier_unavailable", terminal=True) from None
    if revoked is not False:
        raise FinalBoundaryRefused("grant_revoked", terminal=True)
    if approval_verifier is None:
        raise FinalBoundaryRefused("approval_verifier_missing", terminal=True)
    try:
        verified = approval_verifier.verify(binding)
    except Exception:  # noqa: BLE001 - an unavailable verifier refuses; it never degrades to later
        raise FinalBoundaryRefused("approval_verifier_unavailable", terminal=True) from None
    if verified is not True:
        raise FinalBoundaryRefused("approval_not_verified", terminal=True)
