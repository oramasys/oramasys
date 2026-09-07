"""Dedicated model-server dialer (Gate 4 Half A, doc 66).

A DNS-resolving, address-class-aware dial primitive for model-server
endpoints. Telos owns endpoint-use authorization (``EndpointUseRequest`` /
``EndpointUseDecision``); this module is what *executes* an authorized dial
and adds the one thing Telos deliberately does not do (see the telos boundary
record): resolve DNS and classify the addresses actually dialed.

Rules enforced here (doc 66 "Dialer contract (first cut)"):

1. Every A/AAAA answer for the endpoint host is resolved before any
   connection is opened.
2. Every resolved address is classified; prohibited classes (unspecified,
   link-local incl. the cloud-metadata address, multicast, reserved,
   broadcast, IPv4-mapped IPv6 mapping to any prohibited v4 class) are
   rejected before dispatch. Loopback/RFC1918/ULA are allowed only when the
   purpose's policy permits local addresses.
3. Redirects are not followed. A future purpose that needs them must
   revalidate every hop's resolved address independently; the first hop's
   classification is never trusted for subsequent hops.
4. No connector is invoked for an endpoint that failed classification or
   Telos authorization -- there is no window in which credentials could be
   forwarded to a rejected address, even transiently.
5. ``Telos.authorize()`` is the decision gate. The dialer never decides
   authorization on its own; it refuses to dial without a fresh, matching
   ``allowed`` decision.

Only ``config_read`` and ``health_probe`` are in Gate 4 scope.
``model_egress`` requires the paid-dispatch accounting gate (doc 66,
"Explicitly out of scope") and is rejected at request construction.

All injectable I/O (DNS resolver, connector) are async callables so tests run
against controlled DNS and HTTP-client fakes, never a real metadata service
or the workstation resolver (doc 65/66 test constraint).
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from telos import (
    EndpointPurpose,
    EndpointRef,
    EndpointUseDecision,
    EndpointUseRequest,
    TelosPort,
)

GATE4_PURPOSES = (EndpointPurpose.CONFIG_READ, EndpointPurpose.HEALTH_PROBE)

#: Purposes whose policy permits loopback/RFC1918/ULA model servers.
LOCAL_PERMITTED_PURPOSES = frozenset(GATE4_PURPOSES)

REASON_PROHIBITED_ADDRESS = "prohibited_address"
REASON_PUBLIC_NOT_PERMITTED = "public_endpoint_not_permitted"
REASON_TELOS_DENIED = "telos_denied"
REASON_TELOS_ENDPOINT_MISMATCH = "telos_decision_endpoint_mismatch"
REASON_PURPOSE_OUT_OF_SCOPE = "purpose_not_in_gate4_scope"
REASON_NO_ANSWERS = "dns_no_answers"
REASON_CONNECTOR_REFUSED = "connector_refused"
REASON_DIAL_TIMEOUT = "dial_timeout"

#: Default deadline for DNS resolution + connector I/O combined (Gate 4 scope
#: is config_read/health_probe -- both lightweight, bounded probes). Without
#: this, a hung resolver or connector holds the caller's routing-key claim
#: open indefinitely, since the claim happens before this dial (CodeRabbit
#: finding on oramasys#3).
DEFAULT_DIAL_TIMEOUT_SECONDS = 10.0

#: Rejection reasons the dialer produces itself (not connector/Telos text).
DIALER_REJECTION_REASONS = frozenset(
    {
        REASON_PROHIBITED_ADDRESS,
        REASON_PUBLIC_NOT_PERMITTED,
        REASON_TELOS_DENIED,
        REASON_TELOS_ENDPOINT_MISMATCH,
        REASON_PURPOSE_OUT_OF_SCOPE,
        REASON_NO_ANSWERS,
        REASON_DIAL_TIMEOUT,
    }
)

DnsResolver = Callable[[str], Awaitable[Sequence[str]]]


class DialConnector(Protocol):
    """Opens the actual connection to a *classified* address.

    Implementations MUST NOT follow redirects (rule 3). ``address`` is the
    specific resolved IP that passed classification, not the original
    hostname. The returned string is an opaque ``provider_ref`` for audit.
    """

    async def connect(
        self, *, address: str, port: int, purpose: EndpointPurpose
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class ModelServerDialRequest:
    """Request to dial a model-server endpoint (doc 66 first-cut contract).

    ``allow_public`` is the caller's own opt-in state, never inferred from
    the endpoint or environment.
    """

    endpoint: EndpointRef
    purpose: EndpointPurpose
    allow_public: bool
    actor_id: str = "gateway_lifecycle"
    workflow_id: str = "gateway_lifecycle"
    run_id: str = ""
    dial_timeout_seconds: float = DEFAULT_DIAL_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if _validate_purpose(self.purpose) is not None:
            raise ValueError(f"purpose {self.purpose} is not in Gate 4 scope")
        if not self.run_id.strip():
            raise ValueError("run_id is required")


@dataclass(frozen=True, slots=True)
class ModelServerDialResult:
    allowed: bool
    reason_code: str
    resolved_address: str | None = None
    provider_ref: str | None = None


class ModelServerDialer:
    """Executes a Telos-authorized, DNS-classified model-server dial."""

    def __init__(
        self,
        *,
        telos: TelosPort,
        resolver: DnsResolver,
        connector: DialConnector,
    ) -> None:
        self._telos = telos
        self._resolver = resolver
        self._connector = connector

    async def dial(self, request: ModelServerDialRequest) -> ModelServerDialResult:
        out_of_scope = _validate_purpose(request.purpose)
        if out_of_scope is not None:
            return ModelServerDialResult(False, out_of_scope)

        # Rule 5: Telos is the decision gate; a dial never proceeds without
        # a fresh allowed decision for exactly this endpoint.
        decision: EndpointUseDecision = await self._telos.authorize(
            EndpointUseRequest(
                actor_id=request.actor_id,
                workflow_id=request.workflow_id,
                purpose=request.purpose,
                endpoint=request.endpoint,
                run_id=request.run_id,
            )
        )
        if not decision.allowed:
            return ModelServerDialResult(False, f"{REASON_TELOS_DENIED}:{decision.reason_code}")
        if decision.endpoint != request.endpoint:
            return ModelServerDialResult(False, REASON_TELOS_ENDPOINT_MISMATCH)

        # DNS resolution and connector I/O share one deadline so neither a
        # hung resolver nor a hung connector can hold the caller's routing-
        # key claim open indefinitely -- the claim happens before dial() is
        # even called, and this dial has no deadline of its own otherwise
        # (CodeRabbit finding on oramasys#3).
        try:
            async with asyncio.timeout(request.dial_timeout_seconds):
                # Rule 1: resolve every answer before any connection is opened.
                answers = list(await self._resolver(request.endpoint.host))
                if not answers:
                    return ModelServerDialResult(False, REASON_NO_ANSWERS)

                # Rule 2: classify every answer; one prohibited answer rejects
                # the whole host before dispatch.
                chosen: str | None = None
                for answer_text in answers:
                    reason, is_local = _classify(answer_text)
                    if reason == REASON_PROHIBITED_ADDRESS:
                        return ModelServerDialResult(False, REASON_PROHIBITED_ADDRESS)
                    if not is_local and not request.allow_public:
                        return ModelServerDialResult(False, REASON_PUBLIC_NOT_PERMITTED)
                    if not is_local and not _endpoint_is_public_declared(request.endpoint):
                        # A public-routable answer for an endpoint asserted
                        # private is a rebinding-shaped contradiction: fail
                        # closed.
                        return ModelServerDialResult(False, REASON_PROHIBITED_ADDRESS)
                    if chosen is None:
                        chosen = answer_text

                # Rule 4: the connector is invoked only after every answer in
                # the answer set passed classification, so no credential-
                # bearing work can observe a rejected address.
                try:
                    provider_ref = await self._connector.connect(
                        address=chosen or "",
                        port=request.endpoint.port,
                        purpose=request.purpose,
                    )
                except Exception:
                    return ModelServerDialResult(False, REASON_CONNECTOR_REFUSED, chosen)
                return ModelServerDialResult(
                    True, "dialed", resolved_address=chosen, provider_ref=provider_ref
                )
        except TimeoutError:
            return ModelServerDialResult(False, REASON_DIAL_TIMEOUT)


def _endpoint_is_public_declared(endpoint: EndpointRef) -> bool:
    return endpoint.is_public


def _classify(address_text: str) -> tuple[str, bool]:
    """Classify one resolved address.

    Returns ``(reason_code, is_local_ok)``. ``reason_code`` is
    ``REASON_PROHIBITED_ADDRESS`` for prohibited classes, ``""`` otherwise.
    ``is_local_ok`` is True for loopback/RFC1918/ULA addresses.
    """
    address = ipaddress.ip_address(address_text)

    # IPv4-mapped IPv6 must be judged by its embedded IPv4 class.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or address == ipaddress.ip_address("255.255.255.255")
    ):
        return REASON_PROHIBITED_ADDRESS, False

    if address.is_loopback or address.is_private:
        # Python's is_private covers rfc1918, ULA (fc00::/7) and loopback;
        # the prohibited classes above were already rejected.
        return "", True
    return "", False


def _validate_purpose(purpose: EndpointPurpose) -> str | None:
    if purpose not in GATE4_PURPOSES:
        return REASON_PURPOSE_OUT_OF_SCOPE
    return None
