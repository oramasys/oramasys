"""The consumer's fail-closed boundary for signed v2 effect grants.

This module deliberately owns no signing, issuer transport, or effect driver.
It accepts only a verifier projection, checks every request-bound fact before
durable state changes, and then passes the verified approval binding into the
existing attempt store.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any, Protocol

from orama.graph.dispatch_attempts import SqliteAttemptStore, VerifiedDispatchGrant
from orama.graph.dispatch_consumer_wire import is_canonical_identifier


_REFUSAL_CODES = frozenset({
    "grant.malformed", "grant.schema_unsupported", "grant.key_unknown",
    "grant.signature_invalid", "grant.expired", "grant.future_dated",
    "grant.revoked", "revocation.stale", "verifier.unavailable",
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


class TrustedEffectGrantComposer:
    """Verify and bind a v2 effect grant before an attempt can exist."""

    def __init__(self, verifier: EffectGrantVerifier) -> None:
        """Keep only the public verifier port, never issuer or signing capabilities."""
        self._verifier = verifier

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
        """Persist a dispatch attempt only when every grant fact matches its request."""
        try:
            grant = _projection(self._verifier.verify(wire))
        except EffectGrantRefused:
            raise
        except Exception as error:
            raise _refusal(error) from error
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
        if any(getattr(grant, name) != value for name, value in expected.items()):
            raise EffectGrantRefused("grant.schema_unsupported")
        store.create_attempt(
            attempt_id,
            VerifiedDispatchGrant(grant.grant_id, grant.second_approval_ref),
            reservation_id,
        )
        store.bind_effect_grant(attempt_id, wire, expected)

    def send(self, store: SqliteAttemptStore, attempt_id: str, *, authenticated_principal: str) -> str:
        """Reverify durable signed authority and authenticated ownership immediately before send."""
        from orama.graph.inert_effect_driver import InertEffectDriver
        wire, context = store.effect_grant_binding(attempt_id)
        if context["principal"] != authenticated_principal:
            raise EffectGrantRefused("grant.schema_unsupported")
        try:
            grant = _projection(self._verifier.verify(wire))
        except EffectGrantRefused:
            raise
        except Exception as error:
            raise _refusal(error) from error
        attempt = store.get_attempt(attempt_id)
        if attempt is None or grant.grant_id != attempt.grant_id or grant.second_approval_ref != attempt.second_approval_ref:
            raise EffectGrantRefused("grant.malformed")
        if any(getattr(grant, name) != value for name, value in context.items()):
            raise EffectGrantRefused("grant.schema_unsupported")
        if grant.effect_class != "inert.simulation" or datetime.now(UTC) >= grant.expires_at:
            raise EffectGrantRefused("grant.expired")
        return InertEffectDriver(store).send(attempt_id)
