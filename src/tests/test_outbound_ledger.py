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
    assert entry.model == "qwen-test"
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
