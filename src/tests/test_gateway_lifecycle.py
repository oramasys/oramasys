"""Gateway Lifecycle contract and orchestration tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest
from pydantic import ValidationError

from orama.gateway.compat import PerpetuaToolsGatewayFacade
from orama.gateway.contracts import (
    ArtifactPin,
    GatewayLifecycleRequest,
    GatewayProgressEvent,
    OperatorConsent,
    PhylaxDecision,
    PlacementDecision,
    ProviderReadiness,
    RoutingState,
    TelosDecision,
)
from orama.gateway.lifecycle import GatewayLifecycle


@dataclass
class MemoryStore:
    states: dict[str, RoutingState] = field(default_factory=dict)
    in_progress: set[str] = field(default_factory=set)
    saves: int = 0
    aborts: int = 0
    _condition: asyncio.Condition = field(default_factory=asyncio.Condition)

    async def claim(self, key: str) -> RoutingState | None:
        async with self._condition:
            while key in self.in_progress and key not in self.states:
                await self._condition.wait()
            if key in self.states:
                return self.states[key]
            self.in_progress.add(key)
            return None

    async def complete(self, key: str, state: RoutingState) -> None:
        async with self._condition:
            self.states[key] = state
            self.in_progress.discard(key)
            self.saves += 1
            self._condition.notify_all()

    async def abort(self, key: str) -> None:
        async with self._condition:
            self.in_progress.discard(key)
            self.aborts += 1
            self._condition.notify_all()


class FailingClaimStore(MemoryStore):
    async def claim(self, key: str) -> RoutingState | None:
        raise RuntimeError("state store unavailable")


@dataclass
class SlowClaimStore(MemoryStore):
    """Reserves the key immediately (like a real store would), then blocks
    before returning -- so a cancellation can land in the window between the
    store committing the reservation and the lifecycle's claim() await
    resuming. Reproduces the exact race the cancellation-safety fix closes."""

    entered_claim: asyncio.Event | None = None
    release_claim: asyncio.Event | None = None

    async def claim(self, key: str) -> RoutingState | None:
        async with self._condition:
            while key in self.in_progress and key not in self.states:
                await self._condition.wait()
            if key in self.states:
                return self.states[key]
            self.in_progress.add(key)  # reservation committed here
        if self.entered_claim is not None:
            self.entered_claim.set()
        if self.release_claim is not None:
            await self.release_claim.wait()
        return None


@dataclass
class EventSink:
    events: list[GatewayProgressEvent] = field(default_factory=list)
    fail_on_phase: str | None = None

    async def emit(self, event: GatewayProgressEvent) -> None:
        if event.phase == self.fail_on_phase:
            self.fail_on_phase = None
            raise RuntimeError("event sink unavailable")
        self.events.append(event)


class MutatingEventSink(EventSink):
    async def emit(self, event: GatewayProgressEvent) -> None:
        event.details["sink_mutation"] = True
        self.events.append(event)


@dataclass
class TelosFake:
    allowed: bool = True
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def authorize(self, *, purpose: str, endpoint: str) -> TelosDecision:
        self.calls.append((purpose, endpoint))
        return TelosDecision(
            allowed=self.allowed,
            policy_version="telos-v1",
            endpoint_ref=f"telos:{purpose}",
            reason_code="allowed" if self.allowed else "endpoint_denied",
        )


@dataclass
class PhylaxFake:
    artifact_allowed: bool = True
    admission_allowed: bool = True
    artifact_calls: int = 0
    admission_calls: int = 0
    redaction_calls: int = 0

    async def verify_artifact(self, artifact: ArtifactPin) -> PhylaxDecision:
        self.artifact_calls += 1
        return PhylaxDecision(
            allowed=self.artifact_allowed,
            policy_version="phylax-v1",
            decision_ref="phylax:artifact",
            reason_code="allowed" if self.artifact_allowed else "artifact_denied",
        )

    async def admit_runtime(
        self, *, artifact: ArtifactPin, placement_ref: str
    ) -> PhylaxDecision:
        self.admission_calls += 1
        return PhylaxDecision(
            allowed=self.admission_allowed,
            policy_version="phylax-v1",
            decision_ref="phylax:admission",
            reason_code="allowed" if self.admission_allowed else "runtime_denied",
        )

    async def redact(self, details: dict[str, object]) -> dict[str, object]:
        self.redaction_calls += 1
        return {"redacted": True, "keys": sorted(details)}


@dataclass
class AgateFake:
    calls: int = 0

    async def resolve_placement(
        self, *, provider_kind: str, model_hint: str | None
    ) -> PlacementDecision:
        self.calls += 1
        return PlacementDecision(
            allowed=True,
            policy_version="agate-v1",
            placement_ref="agate:local-gpu",
            reason_code="allowed",
        )


@dataclass
class ClaudeFake:
    ready: bool = True
    timed_out: bool = False
    calls: int = 0
    raise_timeout: bool = False
    entered: asyncio.Event | None = None
    release: asyncio.Event | None = None

    async def ensure_ready(
        self,
        *,
        provider_kind: str,
        placement_ref: str,
        config_endpoint_ref: str,
        health_endpoint_ref: str,
        timeout_seconds: int,
    ) -> ProviderReadiness:
        self.calls += 1
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            await self.release.wait()
        if self.raise_timeout:
            raise TimeoutError("provider readiness exceeded deadline")
        return ProviderReadiness(
            ready=self.ready,
            timed_out=self.timed_out,
            provider_ref="claude:ollama" if self.ready else None,
            reason_code=(
                "ready" if self.ready else "readiness_timeout" if self.timed_out else "error"
            ),
        )


def request(*, consent: bool = True, version: str = "1.2.3") -> GatewayLifecycleRequest:
    return GatewayLifecycleRequest(
        gateway_id="local-model-gateway",
        artifact=ArtifactPin(
            artifact_id="alphaclaw",
            version=version,
            digest="sha256:" + "a" * 64,
        ),
        operator_consent=OperatorConsent(
            accepted=consent,
            artifact_id="alphaclaw",
            version=version,
            digest="sha256:" + "a" * 64,
        ),
        provider_kind="ollama",
        config_endpoint="http://127.0.0.1:18789/config",
        health_endpoint="http://127.0.0.1:18789/health",
        model_hint="qwen3.5:9b",
        readiness_timeout_seconds=30,
    )


def lifecycle(
    *,
    telos: TelosFake | None = None,
    phylax: PhylaxFake | None = None,
    agate: AgateFake | None = None,
    claude: ClaudeFake | None = None,
    store: MemoryStore | None = None,
    sink: EventSink | None = None,
) -> tuple[GatewayLifecycle, TelosFake, PhylaxFake, AgateFake, ClaudeFake, MemoryStore, EventSink]:
    ports = (
        telos or TelosFake(),
        phylax or PhylaxFake(),
        agate or AgateFake(),
        claude or ClaudeFake(),
        store or MemoryStore(),
        sink or EventSink(),
    )
    return GatewayLifecycle(
        telos=ports[0],
        phylax=ports[1],
        agate=ports[2],
        claude=ports[3],
        store=ports[4],
        events=ports[5],
    ), *ports


def test_artifact_pin_rejects_mutable_versions_and_bad_digests():
    for version in (
        "latest",
        "beta",
        "nightly",
        "1.x.0",
        "^1.2.3",
        ">=1.2.3",
        "v1.2.3",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-01",
        "1٢.2.3",
        "1.2.3-١a",
    ):
        with pytest.raises(ValidationError):
            ArtifactPin(
                artifact_id="alphaclaw",
                version=version,
                digest="sha256:" + "a" * 64,
            )
    with pytest.raises(ValidationError):
        ArtifactPin(artifact_id="alphaclaw", version="1.2.3", digest="sha256:abc")

    pin = ArtifactPin(
        artifact_id="alphaclaw",
        version="1.2.3-alpha-beta.1+build-7",
        digest="sha256:" + "b" * 64,
    )
    assert pin.version == "1.2.3-alpha-beta.1+build-7"


@pytest.mark.asyncio
async def test_success_uses_each_semantic_owner_and_materializes_routing_state():
    runner, telos, phylax, agate, claude, store, sink = lifecycle()

    result = await runner.run(request())

    assert result.status == "ready"
    assert result.routing_state is not None
    assert result.routing_state.provider_ref == "claude:ollama"
    assert result.routing_state.placement_ref == "agate:local-gpu"
    assert telos.calls == [
        ("config", "http://127.0.0.1:18789/config"),
        ("health", "http://127.0.0.1:18789/health"),
    ]
    assert (phylax.artifact_calls, phylax.admission_calls) == (1, 1)
    assert (agate.calls, claude.calls, store.saves) == (1, 1, 1)
    assert [event.sequence for event in sink.events] == list(range(1, len(sink.events) + 1))
    assert sink.events[-1].phase == "completed"
    assert any(event.details.get("redacted") is True for event in sink.events)
    serialized_events = " ".join(str(event.details) for event in sink.events)
    assert "agate:local-gpu" not in serialized_events
    assert "claude:ollama" not in serialized_events


@pytest.mark.asyncio
async def test_repeat_run_returns_stored_route_without_repeating_owner_calls():
    runner, telos, phylax, agate, claude, store, _ = lifecycle()
    first = await runner.run(request())
    counts = (
        len(telos.calls),
        phylax.artifact_calls,
        phylax.admission_calls,
        agate.calls,
        claude.calls,
        phylax.redaction_calls,
    )

    second = await runner.run(request())

    assert first.routing_state == second.routing_state
    assert second.status == "already_ready"
    assert store.saves == 1
    assert counts == (
        len(telos.calls),
        phylax.artifact_calls,
        phylax.admission_calls,
        agate.calls,
        claude.calls,
        phylax.redaction_calls,
    )


@pytest.mark.asyncio
async def test_missing_consent_denies_before_any_owner_or_state_call():
    runner, telos, phylax, agate, claude, store, _ = lifecycle()

    result = await runner.run(request(consent=False))

    assert (result.status, result.reason_code) == ("denied", "operator_consent_required")
    assert telos.calls == []
    assert (phylax.artifact_calls, agate.calls, claude.calls, store.saves) == (0, 0, 0, 0)


@pytest.mark.asyncio
async def test_consent_must_match_the_exact_artifact_version():
    runner, telos, phylax, agate, claude, store, _ = lifecycle()
    mismatched = request().model_copy(
        update={
            "operator_consent": OperatorConsent(
                accepted=True,
                artifact_id="alphaclaw",
                version="1.2.4",
                digest="sha256:" + "a" * 64,
            )
        }
    )

    result = await runner.run(mismatched)

    assert (result.status, result.reason_code) == ("denied", "operator_consent_required")
    assert telos.calls == []
    assert (phylax.artifact_calls, agate.calls, claude.calls, store.saves) == (0, 0, 0, 0)


@pytest.mark.asyncio
async def test_consent_must_match_the_exact_artifact_digest():
    """Regression test: OperatorConsent previously scoped only artifact_id +
    version, so a same-version artifact swap with a different digest was not
    caught by consent (CodeRabbit finding, CWE-863 on oramasys/oramasys#1)."""
    runner, telos, phylax, agate, claude, store, _ = lifecycle()
    mismatched = request().model_copy(
        update={
            "operator_consent": OperatorConsent(
                accepted=True,
                artifact_id="alphaclaw",
                version="1.2.3",
                digest="sha256:" + "b" * 64,
            )
        }
    )

    result = await runner.run(mismatched)

    assert (result.status, result.reason_code) == ("denied", "operator_consent_required")
    assert telos.calls == []
    assert (phylax.artifact_calls, agate.calls, claude.calls, store.saves) == (0, 0, 0, 0)


@pytest.mark.asyncio
async def test_telos_denial_stops_without_admission_or_provider_fallback():
    runner, _, phylax, agate, claude, store, _ = lifecycle(telos=TelosFake(allowed=False))

    result = await runner.run(request())

    assert (result.status, result.reason_code) == ("denied", "endpoint_denied")
    assert (phylax.artifact_calls, agate.calls, claude.calls, store.saves) == (0, 0, 0, 0)


@pytest.mark.asyncio
async def test_readiness_timeout_is_explicit_and_does_not_write_routing_state():
    runner, _, _, _, _, store, sink = lifecycle(
        claude=ClaudeFake(ready=False, timed_out=True)
    )

    result = await runner.run(request())

    assert (result.status, result.reason_code) == ("timed_out", "readiness_timeout")
    assert result.routing_state is None
    assert store.saves == 0
    assert sink.events[-1].status == "timed_out"


@pytest.mark.asyncio
async def test_raised_readiness_timeout_is_mapped_to_timed_out():
    runner, _, _, _, _, store, _ = lifecycle(
        claude=ClaudeFake(ready=False, raise_timeout=True)
    )

    result = await runner.run(request())

    assert (result.status, result.reason_code) == ("timed_out", "readiness_timeout")
    assert (store.saves, store.aborts) == (0, 1)


@pytest.mark.asyncio
async def test_concurrent_identical_runs_execute_owner_operations_once():
    entered = asyncio.Event()
    release = asyncio.Event()
    runner, telos, phylax, agate, claude, store, _ = lifecycle(
        claude=ClaudeFake(entered=entered, release=release)
    )
    first_task = asyncio.create_task(runner.run(request()))
    await entered.wait()
    second_task = asyncio.create_task(runner.run(request()))
    await asyncio.sleep(0)
    release.set()

    first, second = await asyncio.gather(first_task, second_task)

    assert {first.status, second.status} == {"ready", "already_ready"}
    assert len(telos.calls) == 2
    assert (phylax.artifact_calls, phylax.admission_calls) == (1, 1)
    assert (agate.calls, claude.calls, store.saves) == (1, 1, 1)


@pytest.mark.asyncio
async def test_cancellation_releases_claim_so_a_waiter_can_retry():
    entered = asyncio.Event()
    release = asyncio.Event()
    runner, _, _, _, claude, store, _ = lifecycle(
        claude=ClaudeFake(entered=entered, release=release)
    )
    cancelled = asyncio.create_task(runner.run(request()))
    await entered.wait()
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled

    release.set()
    retry = await runner.run(request())

    assert retry.status == "ready"
    assert store.aborts == 1
    assert claude.calls == 2


@pytest.mark.asyncio
async def test_cancellation_during_claim_reservation_still_releases_the_key():
    """The store commits its reservation (adds the key to in_progress)
    BEFORE the lifecycle's `await self._store.claim(key)` resumes. A
    cancellation delivered in that exact window previously left `claimed`
    False, so the CancelledError handler skipped abort() and the key was
    stranded forever -- a later identical request would block indefinitely.

    The current implementation (commit 7dfdb6b, "close review remediation
    gaps") waits for the shielded claim task to actually settle before
    calling abort(), rather than aborting immediately on cancellation --
    closing a narrower race the earlier asyncio.shield-only fix left open
    (abort() racing ahead of a claim that reserves the key moments later).
    That means release_claim must be set BEFORE awaiting the cancelled task,
    not after: the run() task's own cancellation handling is blocked on the
    claim task settling, so awaiting `cancelled` first would deadlock."""
    entered_claim = asyncio.Event()
    release_claim = asyncio.Event()
    store = SlowClaimStore(entered_claim=entered_claim, release_claim=release_claim)
    runner, _, _, _, claude, _, _ = lifecycle(store=store)

    cancelled = asyncio.create_task(runner.run(request()))
    await entered_claim.wait()  # store has committed the reservation now
    cancelled.cancel()
    release_claim.set()  # let the in-flight claim() call settle so cleanup can proceed
    with pytest.raises(asyncio.CancelledError):
        await cancelled

    assert store.aborts == 1
    assert store.in_progress == set()

    retry = await runner.run(request())

    assert retry.status == "ready"
    assert claude.calls == 1


@pytest.mark.asyncio
async def test_corrupt_stored_route_is_never_accepted_as_ready():
    runner, _, _, _, _, store, _ = lifecycle()
    first = await runner.run(request())
    assert first.routing_state is not None
    key = first.routing_state.idempotency_key
    store.states[key] = first.routing_state.model_copy(update={"gateway_id": "wrong"})

    result = await runner.run(request())

    assert (result.status, result.reason_code) == ("error", "routing_state_corrupt")


@pytest.mark.asyncio
async def test_post_commit_event_failure_preserves_ready_business_outcome():
    sink = EventSink(fail_on_phase="routing_state_written")
    runner, _, _, _, _, store, _ = lifecycle(sink=sink)

    result = await runner.run(request())

    assert result.status == "ready"
    assert result.reason_code == "ready_with_event_delivery_error"
    assert result.routing_state is not None
    assert store.saves == 1


@pytest.mark.asyncio
async def test_event_sink_cannot_mutate_result_event_history():
    sink = MutatingEventSink()
    runner, *_ = lifecycle(sink=sink)

    result = await runner.run(request())

    assert result.status == "ready"
    assert all("sink_mutation" not in event.details for event in result.events)
    assert any("sink_mutation" in event.details for event in sink.events)


@pytest.mark.asyncio
async def test_state_store_failure_returns_terminal_error_instead_of_escaping():
    runner, *_ = lifecycle(store=FailingClaimStore())

    result = await runner.run(request())

    assert (result.status, result.reason_code) == ("error", "owner_unavailable")


@pytest.mark.asyncio
async def test_pt_facade_propagates_denial_without_legacy_fallback():
    runner, telos, *_ = lifecycle(telos=TelosFake(allowed=False))
    facade = PerpetuaToolsGatewayFacade(runner)

    result = await facade.run(request())

    assert (result.status, result.reason_code) == ("denied", "endpoint_denied")
    assert len(telos.calls) == 1


@pytest.mark.asyncio
async def test_repeated_cancellation_does_not_bypass_claim_cleanup():
    """CodeRabbit finding: a SECOND Task.cancel() lands while the
    cancellation handler is itself awaiting the shielded claim_task drain.
    asyncio.CancelledError is a BaseException, not an Exception, so the
    prior code's `except Exception: pass` around that inner await did NOT
    catch it -- the second cancellation propagated straight past both the
    claim_task drain AND the abort(key) call below it, silently skipping
    cleanup. Reproduces CodeRabbit's own repro shape but against the real
    GatewayLifecycle/SlowClaimStore harness instead of a standalone script."""
    entered_claim = asyncio.Event()
    release_claim = asyncio.Event()
    store = SlowClaimStore(entered_claim=entered_claim, release_claim=release_claim)
    runner, _, _, _, claude, _, _ = lifecycle(store=store)

    cancelled = asyncio.create_task(runner.run(request()))
    await entered_claim.wait()  # store has committed the reservation now

    cancelled.cancel()
    await asyncio.sleep(0)  # let the first cancellation reach the handler
    cancelled.cancel()  # second cancellation, while the handler awaits cleanup

    with pytest.raises(asyncio.CancelledError):
        await cancelled

    release_claim.set()  # let the (still-running, shielded) claim() settle

    # Give the shielded cleanup task -- detached from the outer task's own
    # cancellation by the fix -- a few turns to actually finish running.
    for _ in range(5):
        await asyncio.sleep(0)

    assert store.aborts == 1
    assert store.in_progress == set()

    retry = await runner.run(request())

    assert retry.status == "ready"
    assert claude.calls == 1
