"""Sealed-envelope inert driver (DRAFT): one local, inert, dry-run send; never executes text.

This sits beside ``InertEffectDriver`` and does not change it. It accepts only a sealed envelope
(see ``sealed_envelope``), re-verifies the bound approval at the final boundary, starts the single
send inside one transaction that re-checks the durable tuple, runs an in-process pure simulation and
settles with a redacted receipt written in the same transaction as the outcome.

What it will not do: run a shell, touch the network or the filesystem, call a provider, accept a target other than
``inert://simulation``, send an attempt twice, or turn an unproven outcome into a failure. If the
simulation raises (a timeout, say) after the send started, the outcome stays ``unknown``, is never
rolled back and is never retried as a new effect.

Replay: an exact replay (same attempt and same envelope digest) returns the stored receipt without
dispatching anything; a different envelope for a settled attempt is refused.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Final

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.effect_receipts import RedactedReceipt
from orama.graph.final_boundary import (
    TERMINAL_REASONS,
    ApprovalVerifier,
    FinalBoundaryBinding,
    FinalBoundaryRefused,
    RevocationLookup,
    authorize_final_boundary,
)
from orama.graph.sealed_envelope import SealedEnvelope, open_envelope

_log = logging.getLogger(__name__)

INERT_EVIDENCE: Final = "inert-simulation:v1"
_EVIDENCE_PREFIX: Final = "inert-simulation:"
Simulation = Callable[[SealedEnvelope], str]
Publisher = Callable[[RedactedReceipt], None]


class SealedDriverRefused(OutcomeRefused):
    """The sealed driver refused before dispatch; ``reason`` is a stable code."""


class SendOutcomeUnknown(Exception):
    """The send started but its outcome could not be proven; the durable record stays ``unknown``."""

    def __init__(self, reason: str) -> None:
        """Store the stable reason. The attempt is NOT failed, rolled back or retried."""
        super().__init__(reason)
        self.reason = reason


def default_simulation(envelope: SealedEnvelope) -> str:
    """Return the fixed evidence label of a simulated send; touches nothing outside memory."""
    return INERT_EVIDENCE


class SealedInertDriver:
    """Drive one attempt through the real outbox lifecycle without any external side effect."""

    def __init__(
        self,
        store: SqliteAttemptStore,
        *,
        effects_allowed: Callable[[], bool] | None,
        approval_verifier: ApprovalVerifier | None,
        revocations: RevocationLookup | None,
        issuer_id: str,
        simulation: Simulation = default_simulation,
        publisher: Publisher | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Use the caller-owned store and injected ports; every power defaults to deny."""
        self._store = store
        self._effects_allowed = effects_allowed
        self._approvals = approval_verifier
        self._revocations = revocations
        self._issuer_id = issuer_id
        self._simulation = simulation
        self._publisher = publisher
        self._clock = clock or (lambda: datetime.now(UTC))

    def send(self, raw: bytes | str, digest: str, *, principal: str) -> RedactedReceipt:
        """Validate the envelope, pass the final boundary, send once, and return the receipt.

        An exact replay returns the stored receipt. Raises ``EnvelopeRefused``,
        ``FinalBoundaryRefused``, ``SealedDriverRefused`` or ``OutcomeRefused`` before any dispatch,
        and ``SendOutcomeUnknown`` when the send began but could not be proven.
        """
        envelope = open_envelope(raw, digest)
        now = self._clock()
        replay = self._replay(envelope, principal)
        if replay is not None:
            return replay
        binding = FinalBoundaryBinding(
            attempt_id=envelope.attempt_id, principal=principal,
            operation_digest=envelope.operation_digest, target=envelope.target,
            epoch=envelope.epoch, expires_at=envelope.expires_at,
        )
        authorize_final_boundary(
            self._store, binding, effects_allowed=self._effects_allowed,
            approval_verifier=self._approvals, revocations=self._revocations,
            issuer_id=self._issuer_id, now=now,
        )
        try:
            self._store.begin_bound_send(
                binding, now, issuer_id=self._issuer_id, clock=self._clock,
                envelope_digest=envelope.digest,
            )
        except FinalBoundaryRefused as refusal:
            if refusal.terminal and refusal.reason in TERMINAL_REASONS:
                self._store.record_terminal_refusal(
                    binding.attempt_id, "final_boundary", None, refusal.reason, self._clock()
                )
            raise
        evidence = self._run(envelope)
        receipt = self._store.settle_with_receipt(
            envelope.attempt_id, "confirmed", evidence, envelope.digest, self._clock()
        )
        self._publish(envelope.attempt_id, receipt)
        return receipt

    def publish_pending(self, limit: int = 100) -> int:
        """Deliver receipts whose publication never completed; bounded, idempotent, report-only.

        Publication is observation: it never settles, retries or alters an effect. Returns the
        number delivered in this call.
        """
        delivered = 0
        for stored in self._store.unpublished_receipts(limit):
            if self._publish(stored.attempt_id, stored.receipt):
                delivered += 1
        return delivered

    def _replay(self, envelope: SealedEnvelope, principal: str) -> RedactedReceipt | None:
        """Return the stored receipt for an exact replay; refuse a different envelope or principal."""
        stored = self._store.receipt(envelope.attempt_id)
        if stored is None:
            return None
        recorded = self._store.attempt_binding(envelope.attempt_id)
        if recorded is None or recorded.principal != principal:
            raise SealedDriverRefused("principal_mismatch")
        if stored.envelope_digest != envelope.digest:
            raise SealedDriverRefused("replay_envelope_mismatch")
        return stored.receipt

    def _run(self, envelope: SealedEnvelope) -> str:
        """Run the pure simulation after the send marker; any failure leaves the outcome unknown."""
        try:
            evidence = self._simulation(envelope)
        except Exception as error:  # noqa: BLE001 - after dispatch every failure is "unproven"
            raise SendOutcomeUnknown("outcome_unknown") from error
        if (
            not isinstance(evidence, str)
            or not evidence.startswith(_EVIDENCE_PREFIX)
            or len(evidence) > 128
            or not evidence.isprintable()
        ):
            raise SendOutcomeUnknown("evidence_invalid")
        return evidence

    def _publish(self, attempt_id: str, receipt: RedactedReceipt) -> bool:
        """Deliver one receipt to the observer and stamp it; a failure leaves it for ``publish_pending``."""
        if self._publisher is None:
            return False
        try:
            self._publisher(receipt)
        except Exception:  # noqa: BLE001 - observation trouble never changes the effect record
            _log.warning("receipt publication failed", extra={"attempt_ref": receipt.attempt_ref})
            return False
        return self._store.mark_receipt_published(attempt_id, self._clock())
