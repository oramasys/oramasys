"""ModelServerDialer + Gate 4 dial-path wiring tests.

All DNS and connections run through controlled fakes -- no test contacts a
real metadata service or depends on the workstation resolver (doc 65/66).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

import pytest
from telos import EndpointPurpose, EndpointRef, EndpointUseRequest

from orama.gateway.dialer import (
    REASON_CONNECTOR_REFUSED,
    REASON_NO_ANSWERS,
    REASON_PROHIBITED_ADDRESS,
    REASON_PUBLIC_NOT_PERMITTED,
    REASON_TELOS_DENIED,
    REASON_TELOS_ENDPOINT_MISMATCH,
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
PUBLIC = EndpointRef("http", "models.example.com", 443, is_public=True)


def dial_request(
    endpoint: EndpointRef = LOCAL,
    purpose: EndpointPurpose = EndpointPurpose.HEALTH_PROBE,
    allow_public: bool = False,
) -> ModelServerDialRequest:
    return ModelServerDialRequest(
        endpoint=endpoint,
        purpose=purpose,
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
async def test_ipv4_mapped_ipv6_metadata_answer_is_rejected():
    resolver = FakeResolver({"ollama.local": ["::ffff:169.254.169.254"]})
    dialer, _, _, connector = make_dialer(resolver=resolver)

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_PROHIBITED_ADDRESS
    assert connector.calls == []


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
async def test_telos_decision_for_different_endpoint_is_refused():
    @dataclass
    class MismatchingTelos(TelosFake):
        async def authorize(self, request: EndpointUseRequest):
            decision = await super().authorize(request)
            return replace(
                decision,
                endpoint=EndpointRef("http", "other.local", 1, is_public=False),
            )

    dialer, _, _, connector = make_dialer(telos=MismatchingTelos())

    result = await dialer.dial(dial_request())

    assert not result.allowed
    assert result.reason_code == REASON_TELOS_ENDPOINT_MISMATCH
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
