"""Outbound decision ledger + seam containment tests (migration debt).

Closes the four outbound-ledger coverage gaps recorded in
references/2026-09-11-oramasys-consumer-pin-and-outbound-ledger-review.md:
(1) per-run dispatch records persist, (2) hung invocations are contained by
the dispatch deadline, (3) concurrent run_ids interleave without crosstalk,
(4) the Telos policy version surfaces in provider results.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from perpetua_core.discovery import Backend, BackendHealth, BackendKind
from perpetua_core.state import PerpetuaState

from orama.graph.perpetua_graph import build_graph
from orama.providers import (
    InMemoryOutboundLedger,
    OutboundLedgerEntry,
    ProviderInvocationRequest,
    ProviderInvocationResult,
)
from orama.providers.contracts import AbortableProviderInvoker


class _Registry:
    def __init__(self, backend: Backend) -> None:
        self._backend = backend

    def online(self) -> list[Backend]:
        return [self._backend]


def _backend() -> Backend:
    return Backend(
        name="ollama-local",
        base_url="http://localhost:11434/v1",
        kind=BackendKind.OLLAMA,
        models=("qwen-test",),
        health=BackendHealth.ONLINE,
        last_seen=datetime.now(UTC),
    )


def _state(session_id: str) -> PerpetuaState:
    return PerpetuaState(
        session_id=session_id,
        task_type="reasoning",
        target_tier="mac",
        messages=[{"role": "user", "content": "hi"}],
    )


class _Invoker:
    def __init__(self, *, delay: float = 0.0, policy_version: str | None = None,
                 fail: bool = False) -> None:
        self.delay = delay
        self.policy_version = policy_version
        self.fail = fail

    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("provider unavailable")
        return ProviderInvocationResult(
            content="provider answer",
            provider_ref="provider-ref-1",
            decision_ref="telos-decision-1",
            policy_version=self.policy_version,
        )


@pytest.mark.asyncio
async def test_successful_dispatch_persists_one_ledger_entry() -> None:
    ledger = InMemoryOutboundLedger()
    invoker = _Invoker(policy_version="telos-v1")
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=invoker,
        outbound_ledger=ledger,
    )

    result = await graph.ainvoke(_state("session-1"))

    assert result.metadata["provider_ref"] == "provider-ref-1"
    assert result.metadata["provider_policy_version"] == "telos-v1"
    entries = ledger.entries()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.run_id == "session-1"
    assert entry.backend_name == "ollama-local"
    assert entry.model == result.metadata["routed_model"]
    assert entry.outcome == "success"
    assert entry.decision_ref == "telos-decision-1"
    assert entry.provider_ref == "provider-ref-1"
    assert entry.policy_version == "telos-v1"
    assert entry.reason is None
    assert entry.recorded_at


@pytest.mark.asyncio
async def test_failed_dispatch_records_outcome_without_leaking_exception_text() -> None:
    ledger = InMemoryOutboundLedger()
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_Invoker(fail=True),
        outbound_ledger=ledger,
    )

    result = await graph.ainvoke(_state("session-fail"))

    assert result.error is not None
    assert "provider unavailable" in result.error  # graph delta keeps detail
    entries = ledger.entries()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.outcome == "failed"
    # Audit records carry the exception *type name* only; never str(exc).
    assert entry.reason == "RuntimeError"


@pytest.mark.asyncio
async def test_hung_invocation_is_contained_by_the_dispatch_deadline() -> None:
    ledger = InMemoryOutboundLedger()

    class _HungInvoker:
        async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
            await asyncio.sleep(30)

    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_HungInvoker(),
        outbound_ledger=ledger,
        invocation_timeout_seconds=0.05,
    )

    result = await graph.ainvoke(_state("session-timeout"))

    assert result.error is not None
    assert "timed out" in result.error
    assert result.metadata["provider_outcome"] == "timeout"
    entries = ledger.entries()
    assert len(entries) == 1
    assert entries[0].outcome == "timeout"
    assert entries[0].decision_ref is None  # nothing dialed, nothing authorized


@pytest.mark.asyncio
async def test_dispatch_settles_on_deadline_even_when_invoker_suppresses_cancellation() -> None:
    """CodeRabbit finding df4ea0a759661a4e56e2cddf: asyncio.wait_for() waits
    for a cancelled task's own cancellation to finish, so an invoker that
    catches CancelledError and keeps doing I/O can extend the wait well past
    invocation_timeout_seconds. Proves the actual wall-clock deadline holds
    even against an invoker deliberately built to ignore cancellation."""
    ledger = InMemoryOutboundLedger()

    class _CancellationSuppressingInvoker:
        """Swallows cancellation exactly twice before finally respecting it.

        Bounded deliberately: an invoker that swallows cancellation forever
        would still prove the dispatch-level assertion below, but it would
        also leave an immortal background task that this test's own event
        loop teardown has to wait out -- an artifact of the test process,
        not of the dispatch code under test. A few bounded swallows are
        enough to prove asyncio.wait() (not asyncio.wait_for()) is what lets
        dispatch_node return at the deadline regardless.
        """

        def __init__(self) -> None:
            self.cancelled_count = 0

        async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
            for _ in range(2):
                try:
                    await asyncio.sleep(1)
                except asyncio.CancelledError:
                    self.cancelled_count += 1
                    continue  # swallow cancellation and keep "working" briefly
            return ProviderInvocationResult(
                content="should never be reached",
                provider_ref="provider-ref-1",
                decision_ref="telos-decision-1",
            )

    invoker = _CancellationSuppressingInvoker()
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=invoker,
        outbound_ledger=ledger,
        invocation_timeout_seconds=0.05,
    )

    started = asyncio.get_event_loop().time()
    result = await asyncio.wait_for(graph.ainvoke(_state("session-suppressed")), timeout=2.0)
    elapsed = asyncio.get_event_loop().time() - started

    assert result.error is not None
    assert "timed out" in result.error
    assert result.metadata["provider_outcome"] == "timeout"
    # The real assertion: dispatch itself settled near the 0.05s deadline,
    # not near the invoker's ~20s of suppressed-cancellation sleeping. The
    # 2.0s outer wait_for is only a test-safety net against a genuine hang;
    # it is not the behavior under test.
    assert elapsed < 1.0
    entries = ledger.entries()
    assert len(entries) == 1
    assert entries[0].outcome == "timeout"


@pytest.mark.asyncio
async def test_dispatch_calls_abort_on_abortable_invoker_after_timeout() -> None:
    """Part 1 of the Phase-3 hard-termination design: an invoker that
    implements the optional AbortableProviderInvoker capability gets a
    second, independent chance to force resource release (e.g. closing
    its own transport) beyond plain .cancel(), which only requests
    cooperative cancellation."""
    ledger = InMemoryOutboundLedger()
    abort_calls: list[ProviderInvocationRequest] = []

    class _AbortableHangingInvoker:
        async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
            await asyncio.sleep(30)
            raise AssertionError("must never complete")

        async def abort(self, request: ProviderInvocationRequest) -> None:
            abort_calls.append(request)

    invoker = _AbortableHangingInvoker()
    assert isinstance(invoker, AbortableProviderInvoker)
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=invoker,
        outbound_ledger=ledger,
        invocation_timeout_seconds=0.05,
    )

    result = await asyncio.wait_for(graph.ainvoke(_state("session-abort")), timeout=2.0)

    assert result.error is not None
    assert "timed out" in result.error
    # abort() runs as a fire-and-forget background task alongside the
    # cancelled invoke() task; give the event loop one more tick so its
    # (synchronous, no-await-inside) body has actually run.
    await asyncio.sleep(0)
    assert len(abort_calls) == 1
    assert abort_calls[0].run_id == "session-abort"


@pytest.mark.asyncio
async def test_dispatch_refuses_new_invocations_once_abandoned_cap_exceeded() -> None:
    """Part 2 of the Phase-3 hard-termination design: bounding
    "accumulate tasks... without a bound" (CodeRabbit PR#7 review
    5184132490) does not require invoker cooperation to be SAFE, only to
    recover quickly. Once max_abandoned_invocations abandoned tasks are
    outstanding, a NEW dispatch must fail closed immediately rather than
    pile more uncooperative background work on top."""
    ledger = InMemoryOutboundLedger()

    class _BoundedSuppressingInvoker:
        """Swallows cancellation twice (~0.2s total) then finishes -- long
        enough to still be 'abandoned' when the second dispatch runs,
        short enough not to outlive this test."""

        async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
            for _ in range(2):
                try:
                    await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    continue
            return ProviderInvocationResult(
                content="unused", provider_ref="p", decision_ref="d",
            )

    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_BoundedSuppressingInvoker(),
        outbound_ledger=ledger,
        invocation_timeout_seconds=0.02,
        max_abandoned_invocations=1,
    )

    first = await asyncio.wait_for(graph.ainvoke(_state("session-first")), timeout=1.0)
    assert first.metadata["provider_outcome"] == "timeout"

    # The first dispatch's invoker task is still abandoned (its own 0.2s
    # of bounded suppression hasn't elapsed yet) -- the cap (1) is already
    # met, so this second dispatch must be refused before ever calling
    # invoke() again, not time out a second time.
    second = await asyncio.wait_for(graph.ainvoke(_state("session-second")), timeout=1.0)
    assert second.metadata["provider_outcome"] == "circuit_open"
    assert "abandoned" in (second.error or "")

    entries = ledger.entries()
    assert [e.outcome for e in entries] == ["timeout", "failed"]
    assert entries[1].reason == "TooManyAbandonedInvocations"


@pytest.mark.asyncio
async def test_dispatch_recovers_once_abandoned_task_finishes() -> None:
    """Complementary case to the cap test above: once the abandoned task
    actually finishes on its own, the registry empties and a subsequent
    dispatch on the SAME graph is accepted (times out on its own new
    grounds) rather than refused outright by the still-open circuit."""
    ledger = InMemoryOutboundLedger()

    class _BoundedSuppressingInvoker:
        async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
            for _ in range(2):
                try:
                    await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    continue
            return ProviderInvocationResult(
                content="unused", provider_ref="p", decision_ref="d",
            )

    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_BoundedSuppressingInvoker(),
        outbound_ledger=ledger,
        invocation_timeout_seconds=0.02,
        max_abandoned_invocations=1,
    )

    first = await asyncio.wait_for(graph.ainvoke(_state("session-first")), timeout=1.0)
    assert first.metadata["provider_outcome"] == "timeout"

    # Give the first dispatch's abandoned task its own ~0.2s of bounded
    # suppression time to actually finish and clear itself from the
    # registry via its done-callback.
    await asyncio.sleep(0.5)

    # Same graph, same invoker (always overshoots the 0.02s deadline) --
    # if the registry had NOT drained, this would be refused outright
    # with provider_outcome=circuit_open instead of being accepted and
    # timing out on its own.
    third = await asyncio.wait_for(graph.ainvoke(_state("session-recovered")), timeout=1.0)
    assert third.metadata["provider_outcome"] == "timeout"


@pytest.mark.asyncio
async def test_concurrent_dispatches_interleave_without_crosstalk() -> None:
    ledger = InMemoryOutboundLedger()
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_Invoker(delay=0.05),
        outbound_ledger=ledger,
    )
    graph_fast = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_Invoker(),
        outbound_ledger=ledger,
    )

    await asyncio.gather(
        graph.ainvoke(_state("session-slow")),
        graph_fast.ainvoke(_state("session-fast")),
    )

    entries = ledger.entries()
    assert {entry.run_id for entry in entries} == {"session-slow", "session-fast"}
    assert len(entries) == 2
    assert all(entry.outcome == "success" for entry in entries)
    assert all(entry.recorded_at for entry in entries)


def test_ledger_is_append_only() -> None:
    ledger = InMemoryOutboundLedger()
    ledger.record(
        OutboundLedgerEntry(
            run_id="run-1",
            backend_name="b",
            model="m",
            outcome="success",
            decision_ref="d",
            provider_ref="p",
        )
    )
    first = ledger.entries()
    ledger.record(
        OutboundLedgerEntry(
            run_id="run-2",
            backend_name="b",
            model="m",
            outcome="failed",
            reason="RuntimeError",
        )
    )
    second = ledger.entries()

    assert len(second) == len(first) + 1
    assert second[: len(first)] == first  # history never rewritten
    assert all(entry.recorded_at for entry in second)
    # UTC evidence per program control.
    assert second[0].recorded_at.endswith("+00:00") or second[0].recorded_at.endswith("Z")
