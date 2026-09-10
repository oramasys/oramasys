from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from perpetua_core.discovery import Backend, BackendHealth, BackendKind
from perpetua_core.state import PerpetuaState

from orama.graph.perpetua_graph import build_graph
from orama.providers import (
    ProviderInvocationRequest,
    ProviderInvocationResult,
    ProviderMessage,
)


class _Registry:
    def __init__(self, backend: Backend) -> None:
        self._backend = backend

    def online(self) -> list[Backend]:
        return [self._backend]


class _FakeInvoker:
    def __init__(self) -> None:
        self.requests: list[ProviderInvocationRequest] = []

    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        self.requests.append(request)
        return ProviderInvocationResult(
            content="provider answer",
            provider_ref="provider-ref-1",
            decision_ref="telos-decision-1",
        )


def _backend() -> Backend:
    return Backend(
        name="ollama-local",
        base_url="http://localhost:11434/v1",
        kind=BackendKind.OLLAMA,
        models=("qwen-test",),
        health=BackendHealth.ONLINE,
        last_seen=datetime.now(UTC),
    )


def test_provider_request_is_immutable() -> None:
    request = ProviderInvocationRequest(
        backend=_backend(),
        model="qwen-test",
        messages=(ProviderMessage(role="user", content="hi"),),
        run_id="run-1",
    )

    with pytest.raises(FrozenInstanceError):
        request.model = "other"  # type: ignore[misc]


def test_provider_request_requires_model_and_run_id() -> None:
    with pytest.raises(ValueError, match="model is required"):
        ProviderInvocationRequest(
            backend=_backend(),
            model="",
            messages=(),
            run_id="run-1",
        )

    with pytest.raises(ValueError, match="run_id is required"):
        ProviderInvocationRequest(
            backend=_backend(),
            model="qwen-test",
            messages=(),
            run_id="",
        )


@pytest.mark.asyncio
async def test_no_invoker_preserves_phase2_no_network_behavior() -> None:
    graph = build_graph(registry=_Registry(_backend()))
    state = PerpetuaState(
        session_id="session-1",
        task_type="reasoning",
        target_tier="mac",
    )

    result = await graph.ainvoke(state)

    assert result.metadata["resolved_backend"] == "ollama-local"
    assert "provider_ref" not in result.metadata
    assert result.messages[-1]["content"] == "dispatched to ollama-local"


@pytest.mark.asyncio
async def test_explicit_invoker_receives_resolved_backend_and_telos_evidence() -> None:
    invoker = _FakeInvoker()
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=invoker,
    )
    state = PerpetuaState(
        session_id="session-1",
        task_type="reasoning",
        target_tier="mac",
        messages=[{"role": "user", "content": "hello"}],
        metadata={"run_id": "run-42"},
    )

    result = await graph.ainvoke(state)

    assert len(invoker.requests) == 1
    request = invoker.requests[0]
    assert request.backend.name == "ollama-local"
    assert request.model == "qwen-test"
    assert request.messages == (ProviderMessage(role="user", content="hello"),)
    assert request.run_id == "run-42"
    assert result.metadata["provider_ref"] == "provider-ref-1"
    assert result.metadata["decision_ref"] == "telos-decision-1"
    assert result.messages[-1]["content"] == "provider answer"


@pytest.mark.asyncio
async def test_explicit_invoker_fails_closed_when_backend_has_no_model() -> None:
    backend = Backend(
        name="ollama-local",
        base_url="http://localhost:11434/v1",
        kind=BackendKind.OLLAMA,
        models=(),
        health=BackendHealth.ONLINE,
    )
    invoker = _FakeInvoker()
    graph = build_graph(
        registry=_Registry(backend),
        provider_invoker=invoker,
    )
    state = PerpetuaState(
        session_id="session-1",
        task_type="reasoning",
        target_tier="mac",
    )

    result = await graph.ainvoke(state)

    assert result.error == "backend 'ollama-local' has no model available for invocation"
    assert invoker.requests == []
