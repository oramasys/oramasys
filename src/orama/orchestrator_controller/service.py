"""The controller's admission pipeline: envelope, transport, capability, then the store.

Order is fixed and every step precedes any task or idempotency lookup (IC-3, IC-4, IC-28):

1. strict envelope validation and projection equality (``400``);
2. the Telos transport port (``401 transport.unverified``);
3. the Phylax capability port, after which the controller re-checks the decision's
   principal, operation, task scope, audience, revocation and expiry (``401``/``403``);
4. the atomic store transition (``404``/``409`` or a receipt).

Any port that raises or answers with something unusable is a denial. Every refusal is
audited with an opaque principal (or ``unknown``), the operation and the code, never with
proof material (IC-25).
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from orama.orchestrator_controller.envelope import ClaimRequest, OPERATIONS, validate_opaque_id
from orama.orchestrator_controller.ports import (
    CapabilityDecision,
    CapabilityQuery,
    CapabilityVerifier,
    DenyAllCapabilityVerifier,
    DenyAllTransportVerifier,
    TransportAttestation,
    TransportDecision,
    TransportVerifier,
)
from orama.orchestrator_controller.refusals import CAPABILITY_DENIAL_CODES, ClaimRefused
from orama.orchestrator_controller.store import Admission, ClaimReceipt, Clock, ControllerStore


class ControllerService:
    """Admit requests through the Telos and Phylax ports and apply them to the store."""

    def __init__(
        self,
        store: ControllerStore,
        *,
        audience: str,
        clock: Clock,
        capability_verifier: CapabilityVerifier | None = None,
        transport_verifier: TransportVerifier | None = None,
    ) -> None:
        """Compose the service; missing ports default to deny-all adapters.

        ``audience`` is this controller's opaque identity that every capability must name.
        ``clock`` is the time used to re-check capability expiry.
        """
        self._store = store
        self._audience = validate_opaque_id(audience, "audience")
        self._clock = clock
        self._capability = capability_verifier or DenyAllCapabilityVerifier()
        self._transport = transport_verifier or DenyAllTransportVerifier()

    def submit(self, body: Mapping[str, object], *, transport: TransportAttestation | None) -> ClaimReceipt:
        """Admit and apply one request, returning its receipt or raising ``ClaimRefused``."""
        operation, principal_hint = _hints(body)
        try:
            request = ClaimRequest.from_mapping(body)
            self._check_transport(transport)
            admission = self._check_capability(request)
            return self._store.apply_admitted(request, admission)
        except ClaimRefused as refusal:
            self._store.record_refusal(operation, principal_hint, refusal.code)
            raise

    def _check_transport(self, attestation: TransportAttestation | None) -> None:
        """Require a transport attestation the Telos port verifies."""
        if not isinstance(attestation, TransportAttestation):
            raise ClaimRefused("transport.unverified")
        try:
            decision = self._transport.verify(attestation)
        except Exception as error:  # noqa: BLE001 - a failing port is a denial
            raise ClaimRefused("transport.unverified") from error
        if not isinstance(decision, TransportDecision) or decision.verified is not True:
            raise ClaimRefused("transport.unverified")

    def _check_capability(self, request: ClaimRequest) -> Admission:
        """Ask the Phylax port, then re-check every binding of its decision."""
        if request.capability_proof is None:
            raise ClaimRefused("capability.missing")
        now = self._clock()
        query = CapabilityQuery(
            proof=request.capability_proof,
            principal_id=request.principal,
            operation=request.operation,
            task_id=request.task_id,
            audience=self._audience,
            at=now,
        )
        try:
            decision = self._capability.verify(query)
        except Exception as error:  # noqa: BLE001 - a failing port is a denial
            raise ClaimRefused("capability.unverifiable") from error
        if not isinstance(decision, CapabilityDecision):
            raise ClaimRefused("capability.unverifiable")
        if decision.allowed is not True:
            code = decision.denial_code
            raise ClaimRefused(code if code in CAPABILITY_DENIAL_CODES else "capability.invalid")
        if decision.revoked:
            raise ClaimRefused("capability.revoked")
        if decision.principal_id != request.principal:
            raise ClaimRefused("capability.principal_mismatch")
        expires = decision.expires_at
        if not isinstance(expires, datetime) or expires.tzinfo is None or expires.utcoffset() is None:
            raise ClaimRefused("capability.unverifiable")
        post_verify_now = self._clock()
        if post_verify_now >= expires:
            raise ClaimRefused("capability.expired")
        if (
            request.operation not in decision.operations
            or request.task_id not in decision.task_ids
            or decision.audience != self._audience
        ):
            raise ClaimRefused("capability.insufficient")
        return Admission(principal_id=request.principal, expires_at=expires)


def _hints(body: object) -> tuple[str, str | None]:
    """Return a safe operation label and principal hint for auditing a refused body."""
    if not isinstance(body, Mapping):
        return "unknown", None
    operation = body.get("operation")
    principal = body.get("principal")
    return (
        operation if operation in OPERATIONS else "unknown",
        principal if isinstance(principal, str) else None,
    )
