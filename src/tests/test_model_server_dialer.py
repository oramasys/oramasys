"""Gateway compatibility tests for the Telos-owned secure dial boundary.

Deep endpoint-security behavior is tested authoritatively in ``oramasys/telos``.
These tests prove that the Gateway compatibility façade preserves application
capability policy, translates Telos outcomes stably, and does not recreate a
second DNS/address-security implementation.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from telos import ConnectedPeer, EndpointPurpose, EndpointRef, EndpointUseDecision

import orama.gateway.dialer as gateway_dialer_module
from orama.gateway.dialer import (
    REASON_CONNECTOR_REFUSED,
    REASON_DIAL_TIMEOUT,
    REASON_DNS_INVALID_ANSWER,
    REASON_NO_ANSWERS,
    REASON_PEER_PIN_MISMATCH,
    REASON_PORT_NOT_PERMITTED,
    REASON_PROHIBITED_ADDRESS,
    REASON_PUBLIC_NOT_PERMITTED,
    REASON_TELOS_DENIED,
    REASON_TELOS_DECISION_EXPIRED,
    REASON_TELOS_ENDPOINT_MISMATCH,
    ModelServerDialer,
    ModelServerDialRequest,
)
from tests.test_gateway_lifecycle import TelosFake


@dataclass
class FakeResolver:
    answers: dict[str, list[str]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        return self.answers.get(host, [])


@dataclass
class FakeConnector:
    provider_ref: str = "provider:fake"
    peer_override: str | None = None
    fail: bool = False
    calls: list[tuple[EndpointRef, str, EndpointPurpose, float]] = field(
        default_factory=list
    )

    async def connect(
        self,
        *,
        endpoint: EndpointRef,
        pinned_address: str,
        purpose: EndpointPurpose,
        timeout_seconds: float,
    ) -> ConnectedPeer:
        self.calls.append((endpoint, pinned_address, purpose, timeout_seconds))
        if self.fail:
            raise ConnectionRefusedError("connector refused")
        return ConnectedPeer(
            provider_ref=self.provider_ref,
            peer_address=self.peer_override or pinned_address,
        )


LOCAL = EndpointRef("http", "ollama.local", 11434)
PUBLIC = EndpointRef("https", "models.example.com", 443)


def dial_request(
    endpoint: EndpointRef = LOCAL,
    purpose: EndpointPurpose = EndpointPurpose.HEALTH_PROBE,
    provider_kind: str = "ollama",
    allow_public: bool = False,
) -> ModelServerDialRequest:
    return ModelServerDialRequest(
        endpoint=endpoint,
        purpose=purpose,
        provider_kind=provider_kind,
        allow_public=allow_public,
        run_id="run-test",
    )


def make_dialer(
    *,
    telos: TelosFake | None = None,
    resolver: FakeResolver | None = None,
    connector: FakeConnector | None = None,
) -> tuple[ModelServerDialer, TelosFake, FakeResolver, FakeConnector]:
    telos = telos or TelosFake()
    resolver = resolver or FakeResolver({LOCAL.host: ["127.0.0.1"]})
    connector = connector or FakeConnector()
    return (
        ModelServerDialer(
            telos=telos,
            resolver=resolver.resolve,
            connector=connector,
        ),
        telos,
        resolver,
        connector,
    )


@pytest.mark.asyncio
async def test_local_success_is_delegated_to_telos_secure_dialer() -> None:
    dialer, telos, _, connector = make_dialer()

    result = await dialer.dial(dial_request())

    assert result.allowed
    assert result.reason_code == "dialed"
    assert result.provider_ref == "provider:fake"
    assert result.resolved_address == "127.0.0.1"
    assert result.policy_version == "telos-v1"
    assert result.decision_ref is not None
    assert len(telos.calls) == 1
    assert telos.calls[0].endpoint.endpoint == LOCAL
    assert connector.calls[0][0] == LOCAL
    assert connector.calls[0][1] == "127.0.0.1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answers", "reason"),
    [
        (["169.254.169.254"], REASON_PROHIBITED_ADDRESS),
        (["127.0.0.1", "169.254.169.254"], REASON_PROHIBITED_ADDRESS),
        (["::ffff:169.254.169.254"], REASON_PROHIBITED_ADDRESS),
        (["100.64.0.1"], REASON_PROHIBITED_ADDRESS),
        (["192.88.99.1"], REASON_PROHIBITED_ADDRESS),
        (["2001::1"], REASON_PROHIBITED_ADDRESS),
        (["2002::1"], REASON_PROHIBITED_ADDRESS),
        ([], REASON_NO_ANSWERS),
        (["not-an-ip"], REASON_DNS_INVALID_ANSWER),
    ],
)
async def test_telos_security_outcomes_are_preserved_by_compatibility_translation(
    answers: list[str], reason: str
) -> None:
    resolver = FakeResolver({LOCAL.host: answers})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == reason
    assert connector.calls == []


@pytest.mark.asyncio
async def test_public_endpoint_requires_explicit_gateway_opt_in() -> None:
    resolver = FakeResolver({PUBLIC.host: ["8.8.8.8"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    denied = await dialer.dial(dial_request(PUBLIC, allow_public=False))
    allowed = await dialer.dial(dial_request(PUBLIC, allow_public=True))

    assert denied.reason_code == REASON_PUBLIC_NOT_PERMITTED
    assert allowed.allowed
    assert connector.calls[-1][1] == "8.8.8.8"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("endpoint", "provider_kind"),
    [
        (EndpointRef("http", "ollama.local", 11434), "ollama"),
        (EndpointRef("http", "lm.local", 1234), "lm_studio"),
        (EndpointRef("http", "openclaw.local", 18789), "openclaw_gateway"),
        (EndpointRef("https", "models.example.com", 443), "ollama"),
        (EndpointRef("https", "models.example.com", 443), "lm_studio"),
    ],
)
async def test_documented_provider_transport_pairs_remain_application_policy(
    endpoint: EndpointRef, provider_kind: str
) -> None:
    is_public = endpoint.scheme == "https"
    resolver = FakeResolver(
        {endpoint.host: ["8.8.8.8"] if is_public else ["127.0.0.1"]}
    )
    dialer, _, _, _ = make_dialer(resolver=resolver)

    result = await dialer.dial(
        dial_request(endpoint, provider_kind=provider_kind, allow_public=is_public)
    )

    assert result.allowed


@pytest.mark.asyncio
async def test_provider_port_crossing_is_rejected_before_telos_dns() -> None:
    endpoint = EndpointRef("http", "openclaw.local", 18789)
    resolver = FakeResolver({endpoint.host: ["127.0.0.1"]})
    dialer, telos, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(endpoint, provider_kind="ollama"))

    assert not result.allowed
    assert result.reason_code == REASON_PORT_NOT_PERMITTED
    assert resolver.calls == []
    assert telos.calls == []
    assert connector.calls == []


@pytest.mark.asyncio
async def test_unknown_model_server_port_is_rejected_before_telos_dns() -> None:
    endpoint = EndpointRef("http", "ollama.local", 6379)
    resolver = FakeResolver({endpoint.host: ["127.0.0.1"]})
    dialer, telos, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(endpoint))

    assert result.reason_code == REASON_PORT_NOT_PERMITTED
    assert resolver.calls == []
    assert telos.calls == []
    assert connector.calls == []


@pytest.mark.asyncio
async def test_telos_denial_is_translated_without_connector_fallback() -> None:
    telos = TelosFake(allowed=False)
    dialer, _, _, connector = make_dialer(telos=telos)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == f"{REASON_TELOS_DENIED}:endpoint_denied"
    assert connector.calls == []


class MismatchTelosFake(TelosFake):
    async def authorize(self, request):
        decision = await super().authorize(request)
        wrong = request.endpoint.__class__(
            endpoint=EndpointRef("http", "other.local", 11434),
            resolved_addresses=request.endpoint.resolved_addresses,
            is_public=request.endpoint.is_public,
            resolution_ref=request.endpoint.resolution_ref,
        )
        return EndpointUseDecision(
            allowed=decision.allowed,
            policy_version=decision.policy_version,
            decision_ref=decision.decision_ref,
            endpoint=wrong,
            reason_code=decision.reason_code,
        )


@pytest.mark.asyncio
async def test_telos_endpoint_mismatch_is_fail_closed_in_telos() -> None:
    dialer, _, _, connector = make_dialer(telos=MismatchTelosFake())

    result = await dialer.dial(dial_request())

    assert result.reason_code == REASON_TELOS_ENDPOINT_MISMATCH
    assert connector.calls == []


class ExpiredTelosFake(TelosFake):
    async def authorize(self, request):
        decision = await super().authorize(request)
        return EndpointUseDecision(
            allowed=True,
            policy_version=decision.policy_version,
            decision_ref=decision.decision_ref,
            endpoint=request.endpoint,
            reason_code="allowed",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )


@pytest.mark.asyncio
async def test_expired_telos_decision_is_fail_closed_in_telos() -> None:
    dialer, _, _, connector = make_dialer(telos=ExpiredTelosFake())

    result = await dialer.dial(dial_request())

    assert result.reason_code == REASON_TELOS_DECISION_EXPIRED
    assert connector.calls == []


@pytest.mark.asyncio
async def test_connector_failure_is_stably_translated() -> None:
    connector = FakeConnector(fail=True)
    dialer, _, _, _ = make_dialer(connector=connector)

    result = await dialer.dial(dial_request())

    assert result.reason_code == REASON_CONNECTOR_REFUSED


@pytest.mark.asyncio
async def test_connected_peer_mismatch_is_stably_translated() -> None:
    connector = FakeConnector(peer_override="127.0.0.2")
    dialer, _, _, _ = make_dialer(connector=connector)

    result = await dialer.dial(dial_request())

    assert result.reason_code == REASON_PEER_PIN_MISMATCH


@dataclass
class HangingResolver(FakeResolver):
    async def resolve(self, host: str) -> list[str]:
        import asyncio

        await asyncio.sleep(60)
        return []


@pytest.mark.asyncio
async def test_dial_timeout_is_enforced_by_telos() -> None:
    resolver = HangingResolver({})
    dialer, _, _, _ = make_dialer(resolver=resolver)
    request = dial_request().__class__(
        endpoint=LOCAL,
        purpose=EndpointPurpose.HEALTH_PROBE,
        provider_kind="ollama",
        allow_public=False,
        run_id="run-test",
        dial_timeout_seconds=0.001,
    )

    result = await dialer.dial(request)

    assert result.reason_code == REASON_DIAL_TIMEOUT


def test_gateway_dialer_contains_no_independent_address_security_engine() -> None:
    source = inspect.getsource(gateway_dialer_module)

    assert "import ipaddress" not in source
    assert "_IPV4_PROHIBITED_NETWORKS" not in source
    assert "_IPV6_PROHIBITED_NETWORKS" not in source
    assert "def _classify(" not in source
    assert "EndpointUseRequest(" not in source
    assert "SecureDialer" in source
