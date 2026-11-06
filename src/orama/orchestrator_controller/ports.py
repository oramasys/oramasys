"""Ports for Telos (transport) and Phylax (principal capability) decisions (doc 68 section 5).

This package owns the ports and imports nothing from ``telos`` or ``phylax``: real adapters
are composed outside ``src/orama`` (see ``scripts/serve_with_effect_grants.py`` for the
pattern). The controller consumes decisions; it never creates its own HTTP/TLS stack and
never verifies credentials itself.

Both defaults deny everything. A verified transport is necessary but never sufficient: a
channel, host or local topology cannot create a principal, capability or lease (IC-6), so
the capability query deliberately carries no transport or topology data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class TransportAttestation:
    """Evidence a Telos-backed transport hands over for one inbound request.

    ``channel_ref`` is an opaque reference; ``evidence`` is adapter-specific and never logged.
    """

    channel_ref: str
    evidence: object = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class TransportDecision:
    """Whether the transport adapter verified the attestation."""

    verified: bool


class TransportVerifier(Protocol):
    """The Telos port: verify that a request arrived over an authorized secure channel."""

    def verify(self, attestation: TransportAttestation) -> TransportDecision:
        """Return the transport decision; raising is treated as a denial."""
        ...


@dataclass(frozen=True, slots=True)
class CapabilityQuery:
    """What the controller asks Phylax: may this principal do this operation on this task?

    ``proof`` is excluded from ``repr``; the controller never stores or emits it.
    """

    proof: str = field(repr=False)
    principal_id: str
    operation: str
    task_id: str
    audience: str
    at: datetime


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    """Phylax's answer, re-checked by the controller even when ``allowed`` is true.

    The binding fields (principal, operations, task ids, audience, expiry) must cover the
    query exactly; ``denial_code`` should be one of ``CAPABILITY_DENIAL_CODES``.
    """

    allowed: bool
    denial_code: str | None = None
    principal_id: str | None = None
    operations: frozenset[str] = frozenset()
    task_ids: frozenset[str] = frozenset()
    audience: str | None = None
    expires_at: datetime | None = None
    revoked: bool = False


class CapabilityVerifier(Protocol):
    """The Phylax port: verify a principal capability bound to operation, task and audience."""

    def verify(self, query: CapabilityQuery) -> CapabilityDecision:
        """Return the capability decision; raising is treated as unverifiable."""
        ...


class DenyAllTransportVerifier:
    """Default transport port: no attestation is ever verified."""

    def verify(self, attestation: TransportAttestation) -> TransportDecision:
        """Refuse every attestation."""
        return TransportDecision(verified=False)


class DenyAllCapabilityVerifier:
    """Default capability port: nothing is ever admitted."""

    def verify(self, query: CapabilityQuery) -> CapabilityDecision:
        """Refuse every query as unverifiable (no issuer is composed)."""
        return CapabilityDecision(allowed=False, denial_code="capability.unverifiable")
