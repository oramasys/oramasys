from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

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


class _FailingInvoker:
    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        raise RuntimeError("provider unavailable")


class _InvalidResultInvoker:
    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        return None  # type: ignore[return-value]


class _ContentInvoker:
    def __init__(self, content: object) -> None:
        self.content = content

    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        return ProviderInvocationResult(
            content=self.content,  # type: ignore[arg-type]
            provider_ref="provider-ref-1",
            decision_ref="telos-decision-1",
        )


class _InterruptingInvoker:
    def __init__(self, interrupt: type[BaseException]) -> None:
        self.interrupt = interrupt

    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        raise self.interrupt()


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


def test_provider_request_coerces_a_caller_supplied_list_to_a_real_tuple() -> None:
    """A mutable caller collection must not remain aliased by a frozen request."""
    mutable_messages = [ProviderMessage(role="user", content="hi")]
    request = ProviderInvocationRequest(
        backend=_backend(),
        model="qwen-test",
        messages=mutable_messages,  # type: ignore[arg-type]
        run_id="run-1",
    )

    mutable_messages.append(ProviderMessage(role="system", content="injected"))

    assert isinstance(request.messages, tuple)
    assert len(request.messages) == 1


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


@pytest.mark.asyncio
async def test_provider_invocation_failure_is_contained_in_state_error() -> None:
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_FailingInvoker(),
    )
    state = PerpetuaState(
        session_id="session-1",
        task_type="reasoning",
        target_tier="mac",
        metadata={"run_id": "run-42", "existing": "kept"},
    )

    result = await graph.ainvoke(state)

    assert result.error == "provider invocation failed: provider unavailable"
    assert result.metadata["resolved_backend"] == "ollama-local"
    assert result.metadata["resolved_url"] == "http://localhost:11434/v1"
    assert result.metadata["existing"] == "kept"
    assert "provider_ref" not in result.metadata


@pytest.mark.asyncio
async def test_invalid_provider_result_is_contained_in_state_error() -> None:
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_InvalidResultInvoker(),
    )
    state = PerpetuaState(
        session_id="session-1",
        task_type="reasoning",
        target_tier="mac",
    )

    result = await graph.ainvoke(state)

    assert result.error.startswith("provider invocation failed:")
    assert result.metadata["resolved_backend"] == "ollama-local"
    assert "provider_ref" not in result.metadata


@pytest.mark.asyncio
async def test_invalid_provider_request_is_contained_before_invocation() -> None:
    invoker = _FakeInvoker()
    graph = build_graph(registry=_Registry(_backend()), provider_invoker=invoker)
    state = PerpetuaState(
        session_id="session-1",
        task_type="reasoning",
        target_tier="mac",
        metadata={"run_id": " \t ", "existing": "kept"},
    )

    result = await graph.ainvoke(state)

    assert result.error == "provider invocation failed: run_id is required"
    assert result.metadata["resolved_backend"] == "ollama-local"
    assert result.metadata["existing"] == "kept"
    assert "provider_ref" not in result.metadata
    assert invoker.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [None, 0, {}])
async def test_non_string_provider_content_returns_error_state(content: object) -> None:
    graph = build_graph(
        registry=_Registry(_backend()), provider_invoker=_ContentInvoker(content)
    )
    state = PerpetuaState(session_id="session-1", target_tier="mac")

    result = await graph.ainvoke(state)

    assert result.error == "provider invocation failed: provider content must be a string"
    assert result.metadata["resolved_backend"] == "ollama-local"
    assert "provider_content" not in result.metadata
    assert "provider_ref" not in result.metadata
    assert result.messages == []


@pytest.mark.asyncio
async def test_empty_string_provider_content_remains_a_valid_response() -> None:
    graph = build_graph(
        registry=_Registry(_backend()), provider_invoker=_ContentInvoker("")
    )

    result = await graph.ainvoke(PerpetuaState(session_id="session-1", target_tier="mac"))

    assert result.error is None
    assert result.messages[-1]["content"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupt", [asyncio.CancelledError, KeyboardInterrupt, SystemExit])
async def test_provider_control_flow_interrupts_propagate(interrupt: type[BaseException]) -> None:
    graph = build_graph(
        registry=_Registry(_backend()), provider_invoker=_InterruptingInvoker(interrupt)
    )

    with pytest.raises(interrupt):
        await graph.ainvoke(PerpetuaState(session_id="session-1", target_tier="mac"))


@pytest.mark.asyncio
async def test_provider_graph_interrupt_reaches_minigraph() -> None:
    interrupt = Interrupt(prompt="operator approval required", payload={"action": "invoke"})
    graph = build_graph(
        registry=_Registry(_backend()),
        provider_invoker=_InterruptingInvoker(lambda: interrupt),
    )

    result = await graph.ainvoke(PerpetuaState(session_id="session-1", target_tier="mac"))

    assert result.status == "interrupted"
    assert result.error is None
    assert result.metadata["interrupt_node"] == "dispatch"
    assert result.metadata["interrupt_prompt"] == "operator approval required"
    assert result.metadata["interrupt_payload"] == {"action": "invoke"}
    assert "respond" not in result.nodes_visited
