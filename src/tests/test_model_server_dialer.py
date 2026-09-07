"""ModelServerDialer + Gate 4 dial-path wiring tests.

All DNS and connections run through controlled fakes -- no test contacts a
real metadata service or depends on the workstation resolver (doc 65/66).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

import pytest
from telos import EndpointPurpose, EndpointRef, EndpointUseRequest

from orama.gateway.dialer import (
    REASON_CONNECTOR_REFUSED,
    REASON_DIAL_TIMEOUT,
    REASON_DNS_INVALID_ANSWER,
    REASON_NO_ANSWERS,
    REASON_PROHIBITED_ADDRESS,
    REASON_PUBLIC_NOT_PERMITTED,
    REASON_PORT_NOT_PERMITTED,
    REASON_TELOS_DENIED,
    REASON_TELOS_DECISION_EXPIRED,
    REASON_TELOS_ENDPOINT_MISMATCH,
    REASON_TRANSPORT_NOT_PERMITTED,
    ModelServerDialer,
    ModelServerDialRequest,
)
from orama.gateway.lifecycle import GatewayLifecycle

from tests.test_gateway_lifecycle import (
    AgateFake,
    ClaudeFake,
    EventSink,
    MemoryStore,
    PhylaxFake,
    TelosFake,
    request as gateway_request,
)


@dataclass
class FakeResolver:
    """Controlled DNS: host -> ordered A/AAAA answer list."""

    answers: dict[str, list[str]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        return self.answers.get(host, [])


@dataclass
class FakeConnector:
    """Controlled connection: records the exact addresses it was handed."""

    provider_ref: str = "provider:fake"
    calls: list[tuple[str, int, EndpointPurpose]] = field(default_factory=list)
    fail: bool = False

    async def connect(self, *, address: str, port: int, purpose: EndpointPurpose) -> str:
        self.calls.append((address, port, purpose))
        if self.fail:
            raise ConnectionRefusedError("connector refused")
        return self.provider_ref


LOCAL = EndpointRef("http", "ollama.local", 11434, is_public=False)
PUBLIC = EndpointRef("https", "models.example.com", 443, is_public=True)


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
    telos: TelosFake | None = None,
    resolver: FakeResolver | None = None,
    connector: FakeConnector | None = None,
) -> tuple[ModelServerDialer, TelosFake, FakeResolver, FakeConnector]:
    telos = telos or TelosFake()
    resolver = resolver or FakeResolver()
    connector = connector or FakeConnector()
    dialer = ModelServerDialer(telos=telos, resolver=resolver.resolve, connector=connector)
    return dialer, telos, resolver, connector


@pytest.mark.asyncio
async def test_local_answer_for_local_purpose_is_dialed_with_resolved_address():
    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, telos, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert result.allowed and result.provider_ref == "provider:fake"
    assert result.resolved_address == "127.0.0.1"
    assert connector.calls == [("127.0.0.1", 11434, EndpointPurpose.HEALTH_PROBE)]
    assert [call.purpose for call in telos.calls] == [EndpointPurpose.HEALTH_PROBE]


@pytest.mark.asyncio
async def test_hostname_resolving_to_metadata_address_is_rejected_before_dispatch():
    resolver = FakeResolver({"ollama.local": ["169.254.169.254"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []  # nothing was dialed


@pytest.mark.asyncio
async def test_multiple_answers_with_one_prohibited_rejects_whole_host():
    resolver = FakeResolver({"ollama.local": ["10.0.0.8", "169.254.169.254"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []


@pytest.mark.asyncio
async def test_prohibited_answer_after_first_good_answer_still_rejects():
    resolver = FakeResolver({"ollama.local": ["192.168.1.10", "fe80::1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []


@pytest.mark.asyncio
async def test_public_endpoint_with_opt_in_is_allowed_after_classification():
    resolver = FakeResolver({"models.example.com": ["8.8.8.8"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(PUBLIC, allow_public=True))

    assert result.allowed
    assert result.resolved_address == "8.8.8.8"
    assert connector.calls == [("8.8.8.8", 443, EndpointPurpose.HEALTH_PROBE)]


@pytest.mark.asyncio
async def test_public_endpoint_without_opt_in_is_rejected():
    resolver = FakeResolver({"models.example.com": ["8.8.8.8"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(PUBLIC, allow_public=False))

    assert not result.allowed
    assert result.reason_code == REASON_PUBLIC_NOT_PERMITTED
    assert connector.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("endpoint", "provider_kind"),
    [
        (EndpointRef("http", "ollama.local", 11434, is_public=False), "ollama"),
        (EndpointRef("http", "lm-studio.local", 1234, is_public=False), "lm_studio"),
        (
            EndpointRef("http", "openclaw.local", 18789, is_public=False),
            "openclaw_gateway",
        ),
        (EndpointRef("https", "models.example.com", 443, is_public=True), "ollama"),
    ],
)
async def test_documented_gate4_transport_port_pairs_are_dialed(
    endpoint: EndpointRef, provider_kind: str
):
    resolver = FakeResolver({endpoint.host: ["8.8.8.8"] if endpoint.is_public else ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(
        dial_request(endpoint, provider_kind=provider_kind, allow_public=endpoint.is_public)
    )

    assert result.allowed
    assert connector.calls == [(result.resolved_address, endpoint.port, EndpointPurpose.HEALTH_PROBE)]


@pytest.mark.asyncio
async def test_non_model_server_port_is_rejected_before_dns_resolution():
    endpoint = EndpointRef("http", "ollama.local", 6379, is_public=False)
    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(endpoint))

    assert not result.allowed
    assert result.reason_code == REASON_PORT_NOT_PERMITTED
    assert resolver.calls == []
    assert connector.calls == []


@pytest.mark.asyncio
async def test_provider_port_conventions_cannot_be_crossed():
    endpoint = EndpointRef("http", "openclaw.local", 18789, is_public=False)
    resolver = FakeResolver({"openclaw.local": ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(endpoint, provider_kind="ollama"))

    assert not result.allowed
    assert result.reason_code == REASON_PORT_NOT_PERMITTED
    assert resolver.calls == []
    assert connector.calls == []


@pytest.mark.asyncio
async def test_non_tcp_transport_is_rejected_before_dns_resolution():
    endpoint = EndpointRef("udp", "ollama.local", 11434, is_public=False)
    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(endpoint))

    assert not result.allowed
    assert result.reason_code == REASON_TRANSPORT_NOT_PERMITTED
    assert resolver.calls == []
    assert connector.calls == []


@pytest.mark.asyncio
async def test_ipv4_mapped_ipv6_metadata_answer_is_rejected():
    resolver = FakeResolver({"ollama.local": ["::ffff:169.254.169.254"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "255.255.255.255",
        "100.64.0.1",
        "2001::1",
        "2002:0808:0808::1",
    ],
)
async def test_transition_and_shared_address_space_are_rejected_before_dispatch(address: str):
    resolver = FakeResolver({"ollama.local": [address]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []


@pytest.mark.asyncio
async def test_malformed_dns_answer_is_denied_with_a_stable_reason():
    resolver = FakeResolver({"ollama.local": ["not-an-ip-address"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_DNS_INVALID_ANSWER
    assert connector.calls == []


@pytest.mark.asyncio
async def test_ipv6_loopback_is_treated_as_local_not_prohibited():
    """Regression: CPython's ipaddress module reports ``::1`` as
    is_reserved == True (verified on 3.13), which the prohibited-class check
    would otherwise reject unconditionally -- the single most common
    config_read/health_probe target for an IPv6-only local model server.
    Found while adding mixed-family test coverage; not caught by three prior
    review passes (author, CodeRabbit, independent adversarial review)."""
    resolver = FakeResolver({"ollama.local": ["::1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert result.allowed
    assert connector.calls[0][0] == "::1"


@pytest.mark.asyncio
async def test_benchmark_range_198_18_is_treated_as_local_not_prohibited():
    """RFC 2544 benchmark space (198.18.0.0/15) is not real Internet-routable
    traffic; Python's ipaddress.is_private already classifies it as private,
    so it is dialed without requiring allow_public -- pinning this as a
    deliberate, verified classification (F13/F08), not an oversight."""
    resolver = FakeResolver({"ollama.local": ["198.18.0.1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert result.allowed
    assert connector.calls[0][0] == "198.18.0.1"


@pytest.mark.asyncio
async def test_mixed_family_answer_set_on_a_permitted_host_dials_the_first_answer():
    """A host with both A and AAAA records must classify every answer (one
    prohibited answer rejects the whole host, per rule 2) before dispatch,
    and dial the first answer once the full set clears classification."""
    resolver = FakeResolver({"ollama.local": ["127.0.0.1", "::1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert result.allowed
    assert result.resolved_address == "127.0.0.1"
    assert connector.calls[0][0] == "127.0.0.1"


@pytest.mark.asyncio
async def test_empty_dns_answer_set_fails_closed():
    resolver = FakeResolver({})  # no answers for any host
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_NO_ANSWERS
    assert connector.calls == []


@pytest.mark.asyncio
async def test_telos_denial_blocks_the_dial():
    telos = TelosFake(allowed=False)
    dialer, _, _, connector = make_dialer(telos=telos)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == f"{REASON_TELOS_DENIED}:endpoint_denied"
    assert connector.calls == []
    assert len(telos.calls) == 1  # the dialer consulted Telos, the decision gate


@pytest.mark.asyncio
async def test_telos_decision_for_different_endpoint_port_is_refused():
    @dataclass
    class MismatchingTelos(TelosFake):
        async def authorize(self, request: EndpointUseRequest):
            decision = await super().authorize(request)
            return replace(
                decision,
                endpoint=EndpointRef("http", "ollama.local", 443, is_public=False),
            )

    dialer, _, _, connector = make_dialer(telos=MismatchingTelos())

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_TELOS_ENDPOINT_MISMATCH
    assert connector.calls == []


@pytest.mark.asyncio
async def test_public_answer_for_a_private_declared_endpoint_is_rejected_even_with_opt_in():
    resolver = FakeResolver({"ollama.local": ["8.8.8.8"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(allow_public=True))

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []


@pytest.mark.asyncio
async def test_expired_telos_decision_is_refused_before_dns_resolution():
    @dataclass
    class ExpiredTelos(TelosFake):
        async def authorize(self, request: EndpointUseRequest):
            decision = await super().authorize(request)
            return replace(decision, expires_at=datetime.now(UTC) - timedelta(seconds=1))

    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(telos=ExpiredTelos(), resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_TELOS_DECISION_EXPIRED
    assert resolver.calls == []
    assert connector.calls == []


@pytest.mark.asyncio
async def test_timezone_ambiguous_telos_expiry_is_refused_before_dns_resolution():
    @dataclass
    class NaiveExpiryTelos(TelosFake):
        async def authorize(self, request: EndpointUseRequest):
            decision = await super().authorize(request)
            return replace(decision, expires_at=datetime.now())

    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(telos=NaiveExpiryTelos(), resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_TELOS_DECISION_EXPIRED
    assert resolver.calls == []
    assert connector.calls == []


def test_model_egress_purpose_is_out_of_gate4_scope():
    with pytest.raises(ValueError):
        dial_request(purpose=EndpointPurpose.MODEL_EGRESS)


@pytest.mark.asyncio
async def test_config_read_purpose_is_in_scope_and_dialed():
    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request(purpose=EndpointPurpose.CONFIG_READ))

    assert result.allowed
    assert connector.calls[0][2] == EndpointPurpose.CONFIG_READ


@pytest.mark.asyncio
async def test_connector_failure_is_reported_not_raised():
    connector = FakeConnector(fail=True)
    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, _ = make_dialer(resolver=resolver, connector=connector)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_CONNECTOR_REFUSED
    assert result.resolved_address == "127.0.0.1"


@dataclass
class HangingResolver:
    """CodeRabbit finding: a resolver that never returns must not hold the
    caller's routing-key claim open indefinitely -- dial() has no deadline
    of its own, and the claim happens before dial() is even called."""

    async def resolve(self, host: str) -> list[str]:
        await asyncio.sleep(3600)
        return []  # pragma: no cover -- never reached


@pytest.mark.asyncio
async def test_dial_times_out_instead_of_hanging_forever_on_a_stuck_resolver():
    dialer, _, _, connector = make_dialer(resolver=HangingResolver())

    result = await dialer.dial(replace(dial_request(), dial_timeout_seconds=0.05))

    assert not result.allowed
    assert result.reason_code == REASON_DIAL_TIMEOUT
    assert connector.calls == []


@dataclass
class HangingConnector:
    async def connect(self, *, address: str, port: int, purpose: EndpointPurpose) -> str:
        await asyncio.sleep(3600)
        return "unreachable"  # pragma: no cover -- never reached


@pytest.mark.asyncio
async def test_dial_times_out_instead_of_hanging_forever_on_a_stuck_connector():
    resolver = FakeResolver({"ollama.local": ["127.0.0.1"]})
    dialer, _, _, _ = make_dialer(resolver=resolver, connector=HangingConnector())

    result = await dialer.dial(replace(dial_request(), dial_timeout_seconds=0.05))

    assert not result.allowed
    assert result.reason_code == REASON_DIAL_TIMEOUT


# ---------------------------------------------------------------------------
# Gate 4 wiring: GatewayLifecycle.run() dials through the dialer
# ---------------------------------------------------------------------------


def lifecycle_with_dialer(
    *,
    resolver: FakeResolver,
    telos: TelosFake | None = None,
    connector: FakeConnector | None = None,
):
    dialer, telos, _, connector = make_dialer(
        telos=telos, resolver=resolver, connector=connector
    )
    claude = ClaudeFake()
    sink = EventSink()
    runner = GatewayLifecycle(
        telos=telos,
        phylax=PhylaxFake(),
        agate=AgateFake(),
        claude=claude,
        store=MemoryStore(),
        events=sink,
        dialer=dialer,
    )
    return runner, connector, telos, claude, sink


@pytest.mark.asyncio
async def test_lifecycle_dials_both_endpoints_through_telos_before_readiness():
    resolver = FakeResolver({"127.0.0.1": ["127.0.0.1"]})
    runner, connector, telos, claude, sink = lifecycle_with_dialer(resolver=resolver)

    result = await runner.run(gateway_request())

    assert result.status == "ready"
    assert claude.calls == 1  # readiness only after the dial path passed
    purposes = [call.purpose for call in telos.calls]
    assert purposes.count(EndpointPurpose.CONFIG_READ) == 2  # authorize + dial
    assert purposes.count(EndpointPurpose.HEALTH_PROBE) == 2
    assert {call[2] for call in connector.calls} == {
        EndpointPurpose.CONFIG_READ,
        EndpointPurpose.HEALTH_PROBE,
    }
    dialed = [event for event in sink.events if event.phase == "endpoints_dialed"]
    assert dialed
    # Event details pass through Phylax redaction: only the key names survive,
    # never the raw resolved address (correlated, not leaked).
    assert "config_resolved_address" in dialed[0].details["keys"]
    assert "127.0.0.1" not in str(dialed[0].details)


@pytest.mark.asyncio
async def test_lifecycle_fails_closed_when_dial_resolves_prohibited_address():
    resolver = FakeResolver({"127.0.0.1": ["169.254.169.254"]})
    runner, connector, _, claude, _ = lifecycle_with_dialer(resolver=resolver)

    result = await runner.run(gateway_request())

    assert (result.status, result.reason_code) == ("denied", REASON_PROHIBITED_ADDRESS)
    assert connector.calls == []
    assert claude.calls == 0  # readiness never started


@pytest.mark.asyncio
async def test_lifecycle_fails_closed_when_a_model_endpoint_uses_an_unapproved_port():
    resolver = FakeResolver({"127.0.0.1": ["127.0.0.1"]})
    runner, connector, _, claude, _ = lifecycle_with_dialer(resolver=resolver)
    non_model_request = gateway_request().model_copy(
        update={
            "config_endpoint": EndpointRef("http", "127.0.0.1", 6379, is_public=False),
        }
    )

    result = await runner.run(non_model_request)

    assert (result.status, result.reason_code) == ("denied", REASON_PORT_NOT_PERMITTED)
    assert connector.calls == []
    assert claude.calls == 0


@pytest.mark.asyncio
async def test_lifecycle_requires_explicit_public_model_server_opt_in():
    resolver = FakeResolver({"models.example.com": ["8.8.8.8"]})
    runner, connector, _, claude, _ = lifecycle_with_dialer(resolver=resolver)
    public_request = gateway_request().model_copy(
        update={
            "provider_kind": "ollama",
            "config_endpoint": PUBLIC,
            "health_endpoint": PUBLIC,
        }
    )

    result = await runner.run(public_request)

    assert (result.status, result.reason_code) == ("denied", REASON_PUBLIC_NOT_PERMITTED)
    assert connector.calls == []
    assert claude.calls == 0


@pytest.mark.asyncio
async def test_lifecycle_dials_declared_public_model_servers_only_after_opt_in():
    resolver = FakeResolver({"models.example.com": ["8.8.8.8"]})
    runner, connector, _, claude, _ = lifecycle_with_dialer(resolver=resolver)
    public_request = gateway_request().model_copy(
        update={
            "provider_kind": "ollama",
            "config_endpoint": PUBLIC,
            "health_endpoint": PUBLIC,
            "allow_public_model_servers": True,
        }
    )

    result = await runner.run(public_request)

    assert result.status == "ready"
    assert len(connector.calls) == 2
    assert claude.calls == 1


@pytest.mark.asyncio
async def test_lifecycle_maps_connector_failure_to_a_generic_dial_denial():
    resolver = FakeResolver({"127.0.0.1": ["127.0.0.1"]})
    runner, connector, _, claude, _ = lifecycle_with_dialer(
        resolver=resolver, connector=FakeConnector(fail=True)
    )

    result = await runner.run(gateway_request())

    assert (result.status, result.reason_code) == ("denied", "dial_denied")
    assert len(connector.calls) == 1
    assert claude.calls == 0


@pytest.mark.asyncio
async def test_lifecycle_dial_uses_gateway_id_as_the_authorizing_actor():
    """CodeRabbit finding: the dial request must carry the same actor Telos
    already authorized against (request.gateway_id), not the dataclass
    default -- otherwise the fresh dial authorization silently authorizes a
    different actor than the one the caller actually is."""
    resolver = FakeResolver({"127.0.0.1": ["127.0.0.1"]})
    runner, _, telos, _, _ = lifecycle_with_dialer(resolver=resolver)

    result = await runner.run(gateway_request())

    assert result.status == "ready"
    # 4 calls: config/health authorize (pre-dial) + config/health dial-time
    # re-authorize -- every one of them must carry the caller's real actor,
    # not the dialer's own dataclass default.
    assert len(telos.calls) == 4
    assert all(c.actor_id == "local-model-gateway" for c in telos.calls)


@pytest.mark.asyncio
async def test_lifecycle_without_dialer_keeps_existing_behavior():
    claude = ClaudeFake()
    runner = GatewayLifecycle(
        telos=TelosFake(),
        phylax=PhylaxFake(),
        agate=AgateFake(),
        claude=claude,
        store=MemoryStore(),
        events=EventSink(),
    )

    result = await runner.run(gateway_request())

    assert result.status == "ready"
    assert claude.calls == 1
