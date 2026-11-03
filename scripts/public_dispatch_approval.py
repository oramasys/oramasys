"""Opt-in, public-only R3 approval adapters; never installed into the serving root.

The trusted caller supplies issuer-scoped current public keys, a grant verifier,
and a complete current revocation view. No signing material, issuance, transport,
approval consumption or activation belongs here. Successful verification proves
only the retained issuer chain for an already-authorized inert attempt; the sealed
driver still owns the effects gate, single-use approval and transactional send.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.dispatch_consumer_wire import parse_timestamp
from orama.graph.effect_grant_composition import TrustedEffectGrantComposer
from orama.graph.final_boundary import (
    FinalBoundaryBinding,
    RevocationLookup,
    RevocationUnavailable,
    check_store_facts,
)

PublicKeyFor = Callable[[str, str], bytes | None]


class IssuerDispatchVerifier:
    """Resolve each signature key in one explicitly configured issuer's trust scope."""

    def __init__(self, issuer_id: str, public_key_for: PublicKeyFor) -> None:
        """Bind an issuer and a current trusted resolver, never a key from the payload."""
        if not isinstance(issuer_id, str) or not issuer_id.strip() or not callable(public_key_for):
            raise ValueError("issuer_id and a trusted public-key resolver are required")
        self.issuer_id = issuer_id
        self._public_key_for = public_key_for

    def _verify(self, kind: str, key_id: str, body: Any, signature: str) -> bool:
        """Use Phylax's public primitive under the current issuer-key binding or deny."""
        try:
            from phylax import dispatch_wire

            public = self._public_key_for(self.issuer_id, key_id)
            if not isinstance(public, bytes) or len(public) != 32:
                return False
            verify = getattr(dispatch_wire, f"verify_{kind}")
            return verify(public, body, signature) is True
        except Exception:
            return False

    def verify_permit(self, key_id: str, body: Mapping[str, Any], signature: str) -> bool:
        """Verify only the frozen permit domain with an issuer-authorized key."""
        return self._verify("permit", key_id, body, signature)

    def verify_finalization(self, key_id: str, body: Mapping[str, Any], signature: str) -> bool:
        """Verify only the frozen finalization domain with an issuer-authorized key."""
        return self._verify("finalization", key_id, body, signature)

    def verify_event(self, key_id: str, digest: str, signature: str) -> bool:
        """Verify only the frozen event domain with an issuer-authorized key."""
        return self._verify("event", key_id, digest, signature)


class RetainedApprovalVerifier:
    """Reverify retained signed authority against current grants, revocations and store facts."""

    def __init__(
        self,
        store: SqliteAttemptStore,
        *,
        signatures: IssuerDispatchVerifier,
        composer: TrustedEffectGrantComposer,
        revocations: RevocationLookup,
        clock: Callable[[], datetime],
    ) -> None:
        """Inject public-only authorities; this constructor opens and activates nothing."""
        self._store, self._signatures = store, signatures
        self._composer, self._revocations, self._clock = composer, revocations, clock

    def verify(self, binding: FinalBoundaryBinding) -> bool:
        """Return exactly True only for a live, unchanged, verified inert dispatch chain."""
        try:
            now = self._clock()
            retained = self._store.retained_dispatch_authority(binding.attempt_id)
            if retained is None or retained.issuer_id != self._signatures.issuer_id:
                return False
            if retained.reverify(self._signatures) is not True:
                return False
            for signed in (retained.permit, retained.finalization):
                if not parse_timestamp(signed["issued_at"]) <= now < parse_timestamp(signed["expires_at"]):
                    return False
            current, _recheck = self._composer.bound_binding(
                self._store, binding.attempt_id, authenticated_principal=binding.principal,
            )
            if current != binding:
                return False
            check_store_facts(self._store.attempt_binding(binding.attempt_id), binding, now)
            _wire, context = self._store.effect_grant_binding(binding.attempt_id)
            permit = retained.permit
            attempt = self._store.get_attempt(binding.attempt_id)
            if attempt is None or permit["grant_id"] != attempt.grant_id:
                return False
            if any(permit[left] != context[right] for left, right in (
                ("grant_payload_digest", "payload_digest"), ("operation_id", "operation_id"),
                ("request_digest", "request_digest"), ("ledger_store_id", "ledger_store_id"),
            )):
                return False
            if self._store.revocation_refusal(binding.attempt_id, retained.issuer_id) is not None:
                return False
            return self._revocations.revoked(
                grant_id=retained.grant_id, issuer_id=retained.issuer_id,
            ) is False
        except RevocationUnavailable:
            raise
        except Exception:
            # A broken reader/verifier never becomes permission or leaks provider errors.
            return False

    def prepare_recheck(self, binding: FinalBoundaryBinding) -> Callable[[], bool]:
        """Snapshot evidence outside the store lock for a store-free send-time trust check.

        The sealed driver combines this with the existing transactional grant
        check. Key and revocation resolvers must be bounded local public reads,
        never network calls or calls back into the attempt store.
        """
        retained = self._store.retained_dispatch_authority(binding.attempt_id)

        def recheck() -> bool:
            """Recheck current public trust and expiry without re-entering the attempt store."""
            try:
                if retained is None or retained.issuer_id != self._signatures.issuer_id:
                    return False
                if retained.reverify(self._signatures) is not True:
                    return False
                now = self._clock()
                if any(not parse_timestamp(wire["issued_at"]) <= now < parse_timestamp(wire["expires_at"])
                       for wire in (retained.permit, retained.finalization)):
                    return False
                return self._revocations.revoked(
                    grant_id=retained.grant_id, issuer_id=retained.issuer_id,
                ) is False
            except RevocationUnavailable:
                raise
            except Exception:
                return False

        return recheck
