"""Compatibility façade for Gateway model-server dials.

Endpoint-security mechanics are owned by :mod:`telos`. This module keeps the
historical Gateway request/result/class names and the application-level
provider/purpose/port capability matrix, then delegates every destination-
security decision and dial invariant to ``telos.SecureDialer``.

Do not add DNS, IP classification, SSRF, pinning, redirect, proxy, TLS, or
endpoint-authorization logic here. Extend Telos and consume it here instead.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from telos import (
    EndpointPurpose,
    EndpointRef,
    SecureDialConnector,
    SecureDialRequest,
    SecureDialResult,
    SecureDialer,
)

from orama.gateway.contracts import ModelServerProvider, TelosPort

GATE4_PURPOSES = (EndpointPurpose.CONFIG_READ, EndpointPurpose.HEALTH_PROBE)

_MODEL_SERVER_TRANSPORT_PORTS = frozenset(
    {
        ("http", 11434),
        ("http", 1234),
        ("http", 18789),
        ("https", 443),
    }
)

PURPOSE_ALLOWED_TRANSPORT_PORTS: dict[EndpointPurpose, frozenset[tuple[str, int]]] = {
    purpose: _MODEL_SERVER_TRANSPORT_PORTS for purpose in GATE4_PURPOSES
}

_PROVIDER_ALLOWED_TRANSPORT_PORTS: dict[
    ModelServerProvider, frozenset[tuple[str, int]]
] = {
    "ollama": frozenset({("http", 11434), ("https", 443)}),
    "lm_studio": frozenset({("http", 1234), ("https", 443)}),
    "openclaw_gateway": frozenset({("http", 18789)}),
}

DEFAULT_DIAL_TIMEOUT_SECONDS = 10.0

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
REASON_PEER_PIN_MISMATCH = "peer_pin_mismatch"

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
        REASON_CONNECTOR_REFUSED,
        REASON_DIAL_TIMEOUT,
        REASON_TELOS_DECISION_EXPIRED,
        REASON_PEER_PIN_MISMATCH,
    }
)

DnsResolver = Callable[[str], Awaitable[Sequence[str]]]
DialConnector = SecureDialConnector


@dataclass(frozen=True, slots=True)
class ModelServerDialRequest:
    endpoint: EndpointRef
    purpose: EndpointPurpose
    provider_kind: ModelServerProvider
    allow_public: bool
    actor_id: str = "gateway_lifecycle"
    workflow_id: str = "gateway_lifecycle"
    run_id: str = ""
    dial_timeout_seconds: float = DEFAULT_DIAL_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if self.purpose not in GATE4_PURPOSES:
            raise ValueError(f"purpose {self.purpose} is not in Gate 4 scope")
        if self.provider_kind not in _PROVIDER_ALLOWED_TRANSPORT_PORTS:
            raise ValueError(f"unsupported model server provider {self.provider_kind}")
        if not self.run_id.strip():
            raise ValueError("run_id is required")
        if self.dial_timeout_seconds <= 0:
            raise ValueError("dial_timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class ModelServerDialResult:
    allowed: bool
    reason_code: str
    resolved_address: str | None = None
    provider_ref: str | None = None
    policy_version: str | None = None
    decision_ref: str | None = None


class ModelServerDialer:
    """Thin Gateway adapter over the Telos secure-dial authority."""

    def __init__(
        self,
        *,
        telos: TelosPort,
        resolver: DnsResolver,
        connector: DialConnector,
    ) -> None:
        self._secure_dialer = SecureDialer(
            authorizer=telos,
            resolver=resolver,
            connector=connector,
        )

    async def dial(self, request: ModelServerDialRequest) -> ModelServerDialResult:
        application_denial = _validate_application_capability(request)
        if application_denial is not None:
            return ModelServerDialResult(False, application_denial)

        result = await self._secure_dialer.dial(
            SecureDialRequest(
                endpoint=request.endpoint,
                purpose=request.purpose,
                actor_id=request.actor_id,
                workflow_id=request.workflow_id,
                run_id=request.run_id,
                allow_public=request.allow_public,
                allow_private=True,
                allow_loopback=True,
                require_https_for_public=True,
                timeout_seconds=request.dial_timeout_seconds,
            )
        )
        return _translate_result(result)


def _validate_application_capability(request: ModelServerDialRequest) -> str | None:
    purpose_allowed = PURPOSE_ALLOWED_TRANSPORT_PORTS[request.purpose]
    provider_allowed = _PROVIDER_ALLOWED_TRANSPORT_PORTS[request.provider_kind]
    allowed_schemes = {scheme for scheme, _ in purpose_allowed & provider_allowed}
    if request.endpoint.scheme not in allowed_schemes:
        return REASON_TRANSPORT_NOT_PERMITTED

    transport_port = request.endpoint.scheme, request.endpoint.port
    if transport_port not in purpose_allowed:
        return REASON_PORT_NOT_PERMITTED
    if transport_port not in provider_allowed:
        return REASON_PORT_NOT_PERMITTED
    return None


def _translate_result(result: SecureDialResult) -> ModelServerDialResult:
    reason = _translate_reason(result.reason_code)
    resolved_address = None
    identity = result.endpoint_identity
    if identity is not None and identity.resolved_addresses:
        resolved_address = identity.resolved_addresses[0]
    policy_version = result.decision.policy_version if result.decision is not None else None
    decision_ref = result.decision.decision_ref if result.decision is not None else None
    return ModelServerDialResult(
        allowed=result.allowed,
        reason_code=reason,
        resolved_address=resolved_address,
        provider_ref=result.provider_ref,
        policy_version=policy_version,
        decision_ref=decision_ref,
    )


def _translate_reason(reason: str) -> str:
    if reason == "dialed":
        return reason
    if reason.startswith("purpose_denied:"):
        suffix = reason.split(":", 1)[1]
        return f"{REASON_TELOS_DENIED}:{suffix}"
    if reason == "authorization_endpoint_mismatch":
        return REASON_TELOS_ENDPOINT_MISMATCH
    if reason == "authorization_expired":
        return REASON_TELOS_DECISION_EXPIRED
    if reason == "public_denied":
        return REASON_PUBLIC_NOT_PERMITTED
    if reason == "dns_resolution_failed":
        return REASON_NO_ANSWERS
    if reason == "invalid_ip":
        return REASON_DNS_INVALID_ANSWER
    if reason == "connector_refused":
        return REASON_CONNECTOR_REFUSED
    if reason == "dial_timeout":
        return REASON_DIAL_TIMEOUT
    if reason == "peer_pin_mismatch":
        return REASON_PEER_PIN_MISMATCH
    if reason == "https_required":
        return REASON_TRANSPORT_NOT_PERMITTED
    if reason in {
        "metadata_denied",
        "transition_network_denied",
        "unspecified_denied",
        "multicast_denied",
        "loopback_denied",
        "link_local_denied",
        "private_denied",
        "special_use_denied",
        "mixed_address_classification",
    }:
        return REASON_PROHIBITED_ADDRESS
    return reason
