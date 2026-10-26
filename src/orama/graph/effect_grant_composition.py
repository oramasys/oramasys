"""The consumer's fail-closed boundary for signed v2 effect grants: verify and bind only.

This module deliberately owns no signing, issuer transport, or effect driver.
It accepts only a verifier projection, checks every request-bound fact before
durable state changes, and then passes the verified approval binding into the
existing attempt store.

There is ONE canonical send path. ``TrustedEffectGrantComposer`` verifies the
durable signed grant again and derives the attempt's final-boundary binding;
the send itself always goes through the sealed final boundary
(``authorize_final_boundary`` and ``SqliteAttemptStore.begin_bound_send`` via
``SealedInertDriver``). The signed grant is re-verified a second time inside the
send transaction, so a revocation cannot slip between the check and the send
marker. ``FinalBoundarySender`` is the only sender the HTTP route accepts; the
plain ``InertEffectDriver`` is never reachable from it. The store enforces the
single path in code: an attempt with an effect-grant binding is refused by the
plain ``begin_send``, and ``begin_bound_send`` refuses it without the signed-grant
recheck (``authority_check``).

Internal refusal codes are closed. Besides the verifier's own codes there are two
consumer-side codes, mapped to the public vocabulary in ``orama.api.public_errors``:

* ``effect.principal_mismatch``: the authenticated caller or the verified grant names a
  different principal than the one bound to the attempt (public ``deny.unauthorized_caller``);
* ``effect.binding_mismatch``: a verified fact differs from the bound request or attempt
  (public ``deny.malformed_grant``).

Two distinct epochs gate a send and neither implies the other. The **lease epoch** is the grant's
verified ``consumer_lease_epoch``; the send-time recheck compares it with the consumer's current
lease for the run (the injected ``lease_epoch_of`` view) and refuses ``effect.lease_stale`` on any
difference, and refuses ``verifier.unavailable`` when no view is wired or it fails. The **fencing
epoch** is owned by the attempt store (``effect_fencing``) and enforced by the final boundary
(``epoch_stale``). They are never compared with, derived from or stored in each other.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any, Protocol

from orama.graph.dispatch_attempts import SqliteAttemptStore, VerifiedDispatchGrant
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.dispatch_consumer_wire import is_canonical_identifier
from orama.graph.effect_receipts import RedactedReceipt
from orama.graph.final_boundary import (
    ApprovalVerifier,
    FinalBoundaryBinding,
    FinalBoundaryRefused,
    RevocationLookup,
)
from orama.graph.sealed_envelope import seal
from orama.graph.sealed_inert_driver import SealedInertDriver

PRINCIPAL_MISMATCH = "effect.principal_mismatch"
BINDING_MISMATCH = "effect.binding_mismatch"
LEASE_STALE = "effect.lease_stale"
INERT_EFFECT_CLASS = "inert.simulation"

_REFUSAL_CODES = frozenset({
    "grant.malformed", "grant.schema_unsupported", "grant.key_unknown",
    "grant.signature_invalid", "grant.expired", "grant.future_dated",
    "grant.revoked", "revocation.stale", "verifier.unavailable",
    PRINCIPAL_MISMATCH, BINDING_MISMATCH, LEASE_STALE,
})


class EffectGrantRefused(Exception):
    """A closed-vocabulary refusal from effect-grant composition."""

    def __init__(self, code: str) -> None:
        """Reject unknown codes so an implementation detail cannot cross the boundary."""
        if code not in _REFUSAL_CODES:
            raise ValueError("effect-grant refusal code is not closed")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class VerifiedEffectGrant:
    """Only v2 effect facts needed to bind one durable dispatch attempt."""

    grant_id: str
    principal: str
    run_id: str
    operation_id: str
    request_digest: str
    effect_class: str
    use_limit: int
    ledger_store_id: str
    consumer_lease_epoch: int
    second_approval_ref: str
    issued_at: datetime
    expires_at: datetime
    payload_digest: str
    verifier_id: str

    def __post_init__(self) -> None:
        """Refuse incomplete verifier projections before comparing caller context."""
        for name in (
            "grant_id", "principal", "run_id", "operation_id", "request_digest",
            "effect_class", "ledger_store_id", "payload_digest", "verifier_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        if any(len(value) != 64 or any(char not in "0123456789abcdef" for char in value) for value in (self.request_digest, self.payload_digest)):
            raise ValueError("effect-grant digests must be SHA-256 hex")
        if type(self.use_limit) is not int or self.use_limit != 1:
            raise ValueError("effect grants must have exactly one use")
        if type(self.consumer_lease_epoch) is not int or not 1 <= self.consumer_lease_epoch <= 2**53 - 1:
            raise ValueError("consumer_lease_epoch must be positive")
        if not isinstance(self.second_approval_ref, str):
            raise ValueError("second_approval_ref must be text")
        if self.second_approval_ref and not is_canonical_identifier(self.second_approval_ref):
            raise ValueError("second_approval_ref must be canonical")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("effect-grant timestamps must be aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("effect-grant expiry must follow issuance")


class EffectGrantVerifier(Protocol):
    """The narrow verifier port supplied by the Phylax composition root."""

    def verify(self, wire: bytes) -> VerifiedEffectGrant:
        """Return verified v2 facts or raise a closed refusal."""


def _refusal(error: BaseException) -> EffectGrantRefused:
    """Normalize foreign verifier failures without exposing their details."""
    raw = getattr(error, "reason", None) or getattr(error, "code", None)
    code = str(getattr(raw, "value", raw)) if raw is not None else ""
    return EffectGrantRefused(code if code in _REFUSAL_CODES else "verifier.unavailable")


def _projection(value: object) -> VerifiedEffectGrant:
    """Copy a foreign projection into consumer-owned validated data."""
    try:
        return VerifiedEffectGrant(**{field.name: getattr(value, field.name) for field in fields(VerifiedEffectGrant)})
    except (AttributeError, TypeError, ValueError) as error:
        raise EffectGrantRefused("grant.malformed") from error


def _mismatch_code(names: list[str]) -> str:
    """Name a principal difference distinctly from any other bound-fact difference."""
    return PRINCIPAL_MISMATCH if "principal" in names else BINDING_MISMATCH


def _sha256_form(digest: str) -> str:
    """Return the ``sha256:``-prefixed form of a stored operation digest for the sealed envelope."""
    return digest if digest.startswith("sha256:") else f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class FinalBoundaryPorts:
    """The injected ports the sealed final boundary needs; R0-2 wires none of them.

    A composition root that cannot supply all three refuses at startup
    (``startup.effects_without_permit_verifier``) instead of wiring a sender.
    """

    approval_verifier: ApprovalVerifier
    revocations: RevocationLookup
    issuer_id: str

    def __post_init__(self) -> None:
        """Refuse an incomplete set of ports before anything can be wired."""
        if self.approval_verifier is None or self.revocations is None:
            raise ValueError("final-boundary ports must all be supplied")
        if not isinstance(self.issuer_id, str) or not self.issuer_id.strip():
            raise ValueError("issuer_id must be non-blank text")


class TrustedEffectGrantComposer:
    """Verify and bind a v2 effect grant; every send goes through the sealed final boundary."""

    def __init__(
        self,
        verifier: EffectGrantVerifier,
        *,
        clock: Callable[[], datetime] | None = None,
        lease_epoch_of: Callable[[str], int | None] | None = None,
    ) -> None:
        """Keep only the public verifier port, never issuer or signing capabilities.

        ``lease_epoch_of(run_id)`` returns the consumer's current lease epoch for the run (or None
        when it holds none). Without it no bound attempt can be sent: lease validity is unknown.
        """
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lease_epoch_of = lease_epoch_of

    def _check_lease(self, grant: VerifiedEffectGrant) -> None:
        """Refuse unless the grant's lease epoch is the consumer's current lease epoch for its run."""
        if self._lease_epoch_of is None:
            raise EffectGrantRefused("verifier.unavailable")
        try:
            current = self._lease_epoch_of(grant.run_id)
        except Exception as error:  # noqa: BLE001 - an unreadable lease view is a deny
            raise EffectGrantRefused("verifier.unavailable") from error
        if type(current) is not int or current != grant.consumer_lease_epoch:
            raise EffectGrantRefused(LEASE_STALE)

    def _verified(self, wire: bytes) -> VerifiedEffectGrant:
        """Verify the wire and return the validated projection, or raise a closed refusal."""
        try:
            return _projection(self._verifier.verify(wire))
        except EffectGrantRefused:
            raise
        except Exception as error:
            raise _refusal(error) from error

    def create_attempt(
        self,
        store: SqliteAttemptStore,
        *,
        attempt_id: str,
        reservation_id: str,
        wire: bytes,
        principal: str,
        run_id: str,
        operation_id: str,
        request_digest: str,
        effect_class: str,
        ledger_store_id: str,
        consumer_lease_epoch: int,
    ) -> None:
        """Persist a dispatch attempt only when every grant fact matches its request.

        The attempt and its effect-grant binding are committed in one store transaction
        (``create_bound_attempt``), so an authorization can never see the attempt without the
        binding and skip the effect-grant cross-check.
        """
        grant = self._verified(wire)
        expected: dict[str, Any] = {
            "principal": principal,
            "run_id": run_id,
            "operation_id": operation_id,
            "request_digest": request_digest,
            "effect_class": effect_class,
            "ledger_store_id": ledger_store_id,
            "consumer_lease_epoch": consumer_lease_epoch,
            "payload_digest": grant.payload_digest,
        }
        differing = [name for name, value in expected.items() if getattr(grant, name) != value]
        if differing:
            raise EffectGrantRefused(_mismatch_code(differing))
        store.create_bound_attempt(
            attempt_id,
            VerifiedDispatchGrant(grant.grant_id, grant.second_approval_ref),
            reservation_id,
            wire=wire,
            context=expected,
        )

    def _check_bound(
        self, grant: VerifiedEffectGrant, context: dict[str, Any], grant_id: str,
        second_approval_ref: str | None,
    ) -> None:
        """Refuse unless the verified grant still equals the durable binding, is live and inert, and holds the lease."""
        if grant.grant_id != grant_id or grant.second_approval_ref != (second_approval_ref or ""):
            raise EffectGrantRefused(BINDING_MISMATCH)
        differing = [name for name, value in context.items() if getattr(grant, name) != value]
        if differing:
            raise EffectGrantRefused(_mismatch_code(differing))
        if grant.effect_class != INERT_EFFECT_CLASS:
            raise EffectGrantRefused(BINDING_MISMATCH)
        if self._clock() >= grant.expires_at:
            raise EffectGrantRefused("grant.expired")
        self._check_lease(grant)

    def bound_binding(
        self, store: SqliteAttemptStore, attempt_id: str, *, authenticated_principal: str
    ) -> tuple[FinalBoundaryBinding, Callable[[], None]]:
        """Re-verify durable signed authority; return the final-boundary binding and its recheck.

        The binding carries the authenticated principal and the tuple the store durably recorded
        at authorization, so the final boundary compares the caller with the attempt's principal.
        The returned recheck verifies the signed grant again; the sealed driver runs it inside the
        send transaction. An attempt that is not (or not fully) authorized is refused with
        ``attempt_not_authorized`` before anything is recorded.
        """
        wire, context = store.effect_grant_binding(attempt_id)
        if context.get("principal") != authenticated_principal:
            raise EffectGrantRefused(PRINCIPAL_MISMATCH)
        attempt = store.get_attempt(attempt_id)
        if attempt is None:
            raise EffectGrantRefused(BINDING_MISMATCH)
        grant_id, second_ref = attempt.grant_id, attempt.second_approval_ref

        def recheck() -> None:
            """Verify the signed grant again and require it to still match the binding."""
            self._check_bound(self._verified(wire), context, grant_id, second_ref)

        recheck()
        stored = store.attempt_binding(attempt_id)
        if (
            stored is None or stored.state != "authorized" or stored.operation_digest is None
            or stored.target is None or stored.epoch is None or stored.expires_at is None
        ):
            raise FinalBoundaryRefused("attempt_not_authorized")
        binding = FinalBoundaryBinding(
            attempt_id=attempt_id, principal=authenticated_principal,
            operation_digest=_sha256_form(stored.operation_digest), target=stored.target,
            epoch=stored.epoch, expires_at=stored.expires_at,
        )
        return binding, recheck

    def send(
        self, driver: SealedInertDriver, attempt_id: str, *, authenticated_principal: str
    ) -> RedactedReceipt:
        """Send one bound attempt through the sealed final boundary, or refuse.

        There is no other send path: the envelope is sealed from the durable tuple and handed to
        ``SealedInertDriver``, which re-verifies at the final boundary, consumes the single-use
        approval and starts the send in one transaction that also re-runs the signed-grant check.
        """
        if not isinstance(driver, SealedInertDriver):
            raise TypeError("the send must go through the sealed final boundary")
        binding, recheck = self.bound_binding(
            driver.store, attempt_id, authenticated_principal=authenticated_principal
        )
        envelope = seal(
            binding.attempt_id, binding.operation_digest, binding.epoch, binding.expires_at,
            binding.target,
        )
        return driver.send(
            envelope.raw, envelope.digest, principal=authenticated_principal,
            authority_check=recheck,
        )


class AttemptRefused(Exception):
    """The attempt holds a terminal refusal record; it is answered from that record, every time.

    ``code`` is the stored public ``deny.*`` code and ``receipt_ref`` the stored opaque reference.
    Nothing internal (kind, rule, reason) is carried.
    """

    def __init__(self, code: str, receipt_ref: str) -> None:
        """Keep the stored public code and the opaque receipt reference."""
        super().__init__(code)
        self.code = code
        self.receipt_ref = receipt_ref


class FinalBoundarySender:
    """The only sender ``POST /effects/inert`` accepts: verify-and-bind, then the final boundary."""

    def __init__(self, composer: TrustedEffectGrantComposer, driver: SealedInertDriver) -> None:
        """Hold the verify-and-bind composer and the sealed driver over the attempt store."""
        if not isinstance(composer, TrustedEffectGrantComposer):
            raise TypeError("composer must be a TrustedEffectGrantComposer")
        if not isinstance(driver, SealedInertDriver):
            raise TypeError("driver must be a SealedInertDriver")
        self._composer = composer
        self._driver = driver

    def __call__(self, attempt_id: str, principal: str) -> RedactedReceipt:
        """Send the attempt as the authenticated principal through the canonical path.

        A refusal at or after the final boundary is answered from the attempt's terminal refusal
        record when one exists (``AttemptRefused``): the first request that was refused and every
        replay get the same stored public code and ``receipt_ref``. A caller that is not the
        attempt's principal never learns of the record, and an in-doubt dispatch
        (``SendOutcomeUnknown``) is never converted into a refusal.
        """
        try:
            return self._composer.send(self._driver, attempt_id, authenticated_principal=principal)
        except (FinalBoundaryRefused, OutcomeRefused) as refusal:
            if getattr(refusal, "reason", None) in ("principal_mismatch", "attempt_not_authorized"):
                raise
            stored = self._driver.store.terminal_refusal(attempt_id)
            if stored is None:
                raise
            raise AttemptRefused(stored.refusal_code, stored.receipt_ref) from refusal
