"""Test doubles for the controller's Telos and Phylax ports (no real adapters)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from orama.orchestrator_controller.ports import (
    CapabilityDecision,
    CapabilityQuery,
    TransportAttestation,
    TransportDecision,
)

AUDIENCE = "controller-audience-1"
ATTESTED = TransportAttestation(channel_ref="channel-1")


@dataclass
class Grant:
    """One principal's capability as a Phylax double would report it."""

    operations: frozenset[str]
    task_ids: frozenset[str]
    expires_at: datetime
    proof: str = "proof-secret-material"
    revoked: bool = False
    audience: str = AUDIENCE


@dataclass
class GrantTableVerifier:
    """A capability verifier double backed by an in-memory grant table, with a call log."""

    grants: dict[str, Grant] = field(default_factory=dict)
    calls: list[CapabilityQuery] = field(default_factory=list)

    def verify(self, query: CapabilityQuery) -> CapabilityDecision:
        """Decide like a strict issuer: unknown or wrong proof is invalid, revocation wins."""
        self.calls.append(query)
        grant = self.grants.get(query.principal_id)
        if grant is None or grant.proof != query.proof:
            return CapabilityDecision(allowed=False, denial_code="capability.invalid")
        if grant.revoked:
            return CapabilityDecision(allowed=False, denial_code="capability.revoked")
        return CapabilityDecision(
            allowed=True,
            principal_id=query.principal_id,
            operations=grant.operations,
            task_ids=grant.task_ids,
            audience=grant.audience,
            expires_at=grant.expires_at,
        )


@dataclass
class FixedDecisionVerifier:
    """A capability verifier double that returns (or raises) one fixed answer."""

    answer: object

    def verify(self, query: CapabilityQuery) -> CapabilityDecision:
        """Return the configured answer, raising it when it is an exception."""
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer  # type: ignore[return-value]


@dataclass
class TransportDouble:
    """A Telos transport verifier double with a configurable verdict."""

    verified: bool = True
    raises: bool = False

    def verify(self, attestation: TransportAttestation) -> TransportDecision:
        """Return the configured verdict for any attestation."""
        if self.raises:
            raise RuntimeError("transport verifier down")
        return TransportDecision(verified=self.verified)
