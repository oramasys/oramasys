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
   authorization on its own; it refuses to dial without a fresh, unexpired,
   matching ``allowed`` decision. Telos binds the purpose to the exact
   ``EndpointRef`` (scheme, host, and port); this module intentionally does
   not maintain a competing endpoint allowlist.

Only ``config_read`` and ``health_probe`` are in Gate 4 scope.
``model_egress`` requires the paid-dispatch accounting gate (doc 66,
"Explicitly out of scope") and is rejected at request construction.

All injectable I/O (DNS resolver, connector) are async callables so tests run
against controlled DNS and HTTP-client fakes, never a real metadata service
or the workstation resolver (doc 65/66 test constraint).

The dialer provides an independent transport floor in addition to Telos's
exact endpoint authorization. Gate 4 currently supports local Ollama
(``http:11434``), LM Studio (``http:1234``), and the OpenClaw control gateway
(``http:18789``), plus an explicitly opted-in TLS reverse proxy
(``https:443``) for the model-server providers. MLX's ``http:8081`` convention
is not included because MLX is not yet a Gateway Lifecycle provider; paid
online LLM egress remains out of scope. A new provider or non-default port
must extend the lifecycle contract and this evidence-backed table together,
rather than silently broadening a generic TCP dial.

Reviewed and accepted for Gate 4's current scope (Claude review, 2026-09-07):
folding ``"openclaw_gateway"`` into ``GatewayLifecycleRequest.provider_kind``
is a real, known modeling overload -- that field's other two callers
(``AgatePort.resolve_placement``, ``ClaudeProviderPort.ensure_ready``) expect
an actual model-serving backend, not the control-plane gateway that owns the
lifecycle itself. It is safe today only because Gate 4 keeps Agate/Claude
behind fakes with no real placement/readiness behavior yet (doc 66's own
"do not yet authorize... provider dispatch, or hardware placement"). Gate 5
(``ResolvedRoute``), which wires real Agate/Claude implementations, MUST
separate "control-plane dial target" from "model-serving provider selection"
before this overload becomes load-bearing -- do not carry it forward silently.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from telos import (
    EndpointPurpose,
    EndpointRef,
    EndpointUseDecision,
    EndpointUseRequest,
    TelosPort,
)

from orama.gateway.contracts import ModelServerProvider

GATE4_PURPOSES = (EndpointPurpose.CONFIG_READ, EndpointPurpose.HEALTH_PROBE)

_TCP_SCHEMES = frozenset({"http", "https"})
_MODEL_SERVER_TRANSPORT_PORTS = frozenset(
    {
        ("http", 11434),  # Ollama
        ("http", 1234),  # LM Studio
        ("http", 18789),  # OpenClaw control gateway
        ("https", 443),  # explicitly opted-in TLS reverse proxy
    }
)

# Both Gate 4 operations query the same model-server control surface today.
# Keep the table purpose-keyed so a later provider operation must make any
# broader port need explicit instead of inheriting a generic TCP capability.
PURPOSE_ALLOWED_TRANSPORT_PORTS: dict[EndpointPurpose, frozenset[tuple[str, int]]] = {
    purpose: _MODEL_SERVER_TRANSPORT_PORTS for purpose in GATE4_PURPOSES
}

# The purpose table keeps the external capability narrow; this table prevents
# accidentally treating one local runtime's port as another runtime's API.
_PROVIDER_ALLOWED_TRANSPORT_PORTS: dict[ModelServerProvider, frozenset[tuple[str, int]]] = {
    "ollama": frozenset({("http", 11434), ("https", 443)}),
    "lm_studio": frozenset({("http", 1234), ("https", 443)}),
    "openclaw_gateway": frozenset({("http", 18789)}),
}

#: Purposes whose policy permits loopback/RFC1918/ULA model servers.
LOCAL_PERMITTED_PURPOSES = frozenset(GATE4_PURPOSES)

REASON_PROHIBITED_ADDRESS = "prohibited_address"
REASON_PUBLIC_NOT_PERMITTED = "public_endpoint_not_permitted"
REASON_TELOS_DENIED = "telos_denied"
REASON_TELOS_ENDPOINT_MISMATCH = "telos_decision_endpoint_mismatch"
REASON_PURPOSE_OUT_OF_SCOPE = "purpose_not_in_gate4_scope"
REASON_NO_ANSWERS = "dns_no_answers"
REASON_DNS_INVALID_ANSWER = "dns_invalid_answer"
REASON_TRANSPORT_NOT_PERMITTED = "transport_not_permitted"
REASON_PORT_NOT_PERMITTED = "port_not_permitted"
REASON_CONNECTOR_REFUSED = "connector_refused"
REASON_DIAL_TIMEOUT = "dial_timeout"
REASON_TELOS_DECISION_EXPIRED = "telos_decision_expired"

# These ranges are neither ordinary local addresses nor ordinary public
# endpoints. Teredo and 6to4 encode or route through other addresses; shared
# carrier space is not a caller-controlled local network. Reject all three
# rather than letting Python's broad ``is_private`` classification decide a
# model-server egress boundary.
_IPV4_PROHIBITED_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"),)
_IPV6_PROHIBITED_NETWORKS = (
    ipaddress.ip_network("2001::/32"),  # Teredo
    ipaddress.ip_network("2002::/16"),  # 6to4
)

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
        REASON_DNS_INVALID_ANSWER,
        REASON_TRANSPORT_NOT_PERMITTED,
        REASON_PORT_NOT_PERMITTED,
        REASON_DIAL_TIMEOUT,
        REASON_TELOS_DECISION_EXPIRED,
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
    provider_kind: ModelServerProvider
    allow_public: bool
    actor_id: str = "gateway_lifecycle"
    workflow_id: str = "gateway_lifecycle"
    run_id: str = ""
    dial_timeout_seconds: float = DEFAULT_DIAL_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if _validate_purpose(self.purpose) is not None:
            raise ValueError(f"purpose {self.purpose} is not in Gate 4 scope")
        if self.provider_kind not in _PROVIDER_ALLOWED_TRANSPORT_PORTS:
            raise ValueError(f"unsupported model server provider {self.provider_kind}")
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
        if decision_is_expired(decision):
            return ModelServerDialResult(False, REASON_TELOS_DECISION_EXPIRED)
        transport_error = _validate_transport_and_port(request)
        if transport_error is not None:
            return ModelServerDialResult(False, transport_error)

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
                    try:
                        reason, is_local = _classify(answer_text)
                    except ValueError:
                        return ModelServerDialResult(False, REASON_DNS_INVALID_ANSWER)
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

                # Every path out of the classification loop either returned a
                # rejection or set `chosen`; assert the invariant so strict
                # type checkers narrow str | None to str for the connector
                # protocol (CodeRabbit nitpick on oramasys#3, dialer.py:239).
                assert chosen is not None

                # Rule 4: the connector is invoked only after every answer in
                # the answer set passed classification, so no credential-
                # bearing work can observe a rejected address.
                try:
                    provider_ref = await self._connector.connect(
                        address=chosen,
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


def decision_is_expired(decision: EndpointUseDecision) -> bool:
    """Fail closed on expired or timezone-ambiguous authorization decisions."""
    expires_at = decision.expires_at
    return expires_at is not None and (
        expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or expires_at <= datetime.now(UTC)
    )


def _validate_transport_and_port(request: ModelServerDialRequest) -> str | None:
    """Return a stable denial reason for a non-Gate-4 transport capability."""
    endpoint = request.endpoint
    if endpoint.scheme not in _TCP_SCHEMES:
        return REASON_TRANSPORT_NOT_PERMITTED
    transport_port = endpoint.scheme, endpoint.port
    if transport_port not in PURPOSE_ALLOWED_TRANSPORT_PORTS[request.purpose]:
        return REASON_PORT_NOT_PERMITTED
    if transport_port not in _PROVIDER_ALLOWED_TRANSPORT_PORTS[request.provider_kind]:
        return REASON_PORT_NOT_PERMITTED
    return None


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

    # Loopback is checked before the prohibited-class predicates below:
    # CPython's ipaddress module reports ``::1`` (IPv6 loopback) as
    # is_reserved == True (verified on 3.13; a real interpreter quirk, not
    # a documentation error), which would otherwise unconditionally reject
    # the single most common config_read/health_probe target. Loopback is
    # always local-permitted, never prohibited -- doc 66's own rule text.
    if address.is_loopback:
        return "", True

    prohibited_networks = (
        _IPV6_PROHIBITED_NETWORKS
        if isinstance(address, ipaddress.IPv6Address)
        else _IPV4_PROHIBITED_NETWORKS
    )

    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or any(address in network for network in prohibited_networks)
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
