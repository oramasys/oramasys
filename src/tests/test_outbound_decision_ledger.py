"""Outbound decision ledger + seam contract tests.

Follow-up lane for the 2026-09-11 outbound-ledger coverage review
(references/2026-09-11-oramasys-consumer-pin-and-outbound-ledger-review.md,
Finding 2, gaps 1-4):

1. an append-only per-run dispatch record (run_id, decision_ref, provider_ref,
   outcome, timestamp) persists at the dispatch boundary;
2. a bounded invocation timeout, when configured, is contained as a normal
   graph error delta — never leaked;
3. concurrent run_ids through the dispatch boundary each leave exactly one
   ledger record, without interleaving corruption;
4. the Telos health-probe policy version, when the invoker supplies it, is
   carried in provider results and recorded.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from perpetua_core.discovery import Backend, BackendHealth, BackendKind
from perpetua_core.graph.plugins.interrupts import Interrupt
from perpetua_core.state import PerpetuaState

from orama.graph.perpetua_graph import build_graph
from orama.providers import (
    ProviderInvocationRequest,
    ProviderInvocationResult,
    ProviderMessage,
)
from orama.providers.outbound_ledger import OutboundDispatchRecord, OutboundLedger


class _Registry:
    def __init__(self, backend: Backend) -> None:
        self._backend = backend

    def online(self) -> list[Backend]:
        return [self._backend]


class _FakeInvoker:
    def __init__(self, *, policy_version: str | None = None, delay: float = 0.0) -> None:
        self.policy_version = policy_version
        self.delay = delay

    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        if self.delay:
            await asyncio.sleep(self.delay)
        return ProviderInvocationResult(
            content="provider answer",
            provider_ref="provider-ref-1",
            decision_ref="telos-decision-1",
            telos_policy_version=self.policy_version,
        )


class _FailingInvoker:
    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        raise RuntimeError("provider unavailable at https://secret.example/v1?token=redact")


class _InterruptingInvoker:
    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        raise Interrupt(prompt="approve?")


def _backend() -> Backend:
    return Backend(
        name="ollama-local",
        base_url="http://localhost:11434/v1",
        kind=BackendKind.OLLAMA,
        models=("qwen-test",),
        health=BackendHealth.ONLINE,
        last_seen=datetime.now(UTC),
    )


def _state(run_id: str) -> PerpetuaState:
    return PerpetuaState(
        session_id=f"session-{run_id}",
        task_type="reasoning",
        target_tier="mac",
        messages=[{"role": "user", "content": "hello"}],
        metadata={"run_id": run_id},
    )


def test_ledger_record_defaults_to_utc_timestamp() -> None:
    record = OutboundDispatchRecord(run_id="run-1", outcome="succeeded")

    parsed = datetime.fromisoformat(record.recorded_at)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == datetime.now(UTC).utcoffset()


def test_ledger_appends_and_reads_back_in_order(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")
    first = OutboundDispatchRecord(
        run_id="run-1", outcome="succeeded",
        decision_ref="dec-1", provider_ref="prov-1",
    )
    second = OutboundDispatchRecord(run_id="run-2", outcome="failed", error="boom")

    asyncio.run(ledger.record(first))
    asyncio.run(ledger.record(second))

    lines = (tmp_path / "outbound.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["run_id"] for line in lines] == ["run-1", "run-2"]
    assert ledger.read_all() == [first, second]


def test_ledger_rejects_a_malformed_existing_line(tmp_path: Path) -> None:
    path = tmp_path / "outbound.jsonl"
    path.write_text('{"run_id": "run-1", "outcome": "succeeded", "recorded_at": "2026-09-11T00:00:00+00:00"}\nnot json\n', encoding="utf-8")
    ledger = OutboundLedger(path)

    with pytest.raises(ValueError, match="malformed"):
        ledger.read_all()


@pytest.mark.asyncio
async def test_ledger_writes_are_serialized_under_concurrency(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")

    await asyncio.gather(
        *(
            ledger.record(OutboundDispatchRecord(run_id=f"run-{i}", outcome="succeeded"))
            for i in range(16)
        )
    )

    lines = (tmp_path / "outbound.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 16
    run_ids = {json.loads(line)["run_id"] for line in lines}
    assert run_ids == {f"run-{i}" for i in range(16)}


@pytest.mark.asyncio
async def test_successful_dispatch_records_outbound_decision(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_FakeInvoker(policy_version="telos-policy-7"),
        outbound_ledger=ledger,
    )

    result = await graph.ainvoke(_state("run-42"))

    assert result.error is None
    assert result.metadata["telos_policy_version"] == "telos-policy-7"
    (record,) = ledger.read_all()
    assert record.run_id == "run-42"
    assert record.outcome == "succeeded"
    assert record.decision_ref == "telos-decision-1"
    assert record.provider_ref == "provider-ref-1"
    assert record.telos_policy_version == "telos-policy-7"


@pytest.mark.asyncio
async def test_failed_dispatch_records_outcome_and_error(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_FailingInvoker(),
        outbound_ledger=ledger,
    )

    result = await graph.ainvoke(_state("run-43"))

    assert "provider invocation failed" in (result.error or "")
    (record,) = ledger.read_all()
    assert record.run_id == "run-43"
    assert record.outcome == "failed"
    assert record.error == "RuntimeError"
    assert "secret.example" not in (record.error or "")
    assert "token" not in (record.error or "")
    assert record.decision_ref == ""
    assert record.provider_ref == ""


@pytest.mark.asyncio
async def test_bounded_timeout_is_contained_and_recorded(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_FakeInvoker(delay=30.0),
        outbound_ledger=ledger,
        invocation_timeout_seconds=0.05,
    )

    result = await asyncio.wait_for(graph.ainvoke(_state("run-44")), timeout=5.0)

    assert "timed out" in (result.error or "")
    (record,) = ledger.read_all()
    assert record.run_id == "run-44"
    assert record.outcome == "failed"
    assert record.error == "RuntimeError"


@pytest.mark.asyncio
async def test_interrupt_is_not_recorded_as_a_failure(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_InterruptingInvoker(),
        outbound_ledger=ledger,
    )

    result = await graph.ainvoke(_state("run-45"))

    # MiniGraph owns its structural HITL protocol: the interrupt becomes an
    # interrupted state, not a raised exception. Either way it is a
    # control-flow signal, not a dispatch outcome, so no ledger record.
    assert result.status == "interrupted"
    assert ledger.read_all() == []


@pytest.mark.asyncio
async def test_concurrent_run_ids_each_leave_exactly_one_record(tmp_path: Path) -> None:
    ledger = OutboundLedger(tmp_path / "outbound.jsonl")
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_FakeInvoker(),
        outbound_ledger=ledger,
    )

    results = await asyncio.gather(
        *(graph.ainvoke(_state(f"run-{i}")) for i in range(2))
    )

    assert all(result.error is None for result in results)
    records = ledger.read_all()
    assert sorted(record.run_id for record in records) == ["run-0", "run-1"]
    assert all(record.outcome == "succeeded" for record in records)


@pytest.mark.asyncio
async def test_no_ledger_and_no_timeout_preserves_existing_behavior(tmp_path: Path) -> None:
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_FakeInvoker(),
    )

    result = await graph.ainvoke(_state("run-46"))

    assert result.error is None
    assert "telos_policy_version" not in result.metadata
    assert not (tmp_path / "outbound.jsonl").exists()
