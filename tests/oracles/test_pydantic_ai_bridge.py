"""Real pinned framework; offline models and socket guard, never importorskip."""
from __future__ import annotations

import asyncio
import socket

import pytest
from pydantic import BaseModel
from pydantic_ai import Agent, DeferredToolRequests, models
from pydantic_ai.models.test import TestModel
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.usage import UsageLimits
from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.compat.pydantic_ai_bridge import as_node
from orama.compat.pydantic_ai_bridge import BridgeRefused


@pytest.fixture(autouse=True)
def offline_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any socket attempt and disable model requests for the entire oracle."""
    monkeypatch.setattr(models, "ALLOW_MODEL_REQUESTS", False)
    def blocked(*args: object, **kwargs: object) -> None:
        """Count attempted network effects by failing at the socket boundary."""
        pytest.fail("offline oracle attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def run(agent: Agent, usage_limits: UsageLimits | None = None) -> PerpetuaState:
    """Execute the real agent through Core's one scheduler."""
    node = as_node(agent, prompt_from=lambda state: "prompt", deps_from=lambda state: None,
                   output_key="answer", offline_test=True, usage_limits=usage_limits)
    graph = MiniGraph().add_node("agent", node).add_edge(START, "agent").add_edge("agent", END)
    return asyncio.run(graph.ainvoke(PerpetuaState(session_id="oracle")))


def test_text_output_and_usage() -> None:
    """Real Agent output and token/request counters become a delta without messages."""
    state = run(Agent(TestModel(custom_output_text="offline answer")))
    assert state.scratchpad["answer"] == "offline answer"
    assert state.metadata["agent_usage"]["requests"] == 1
    assert "messages" not in state.metadata


def test_structured_output() -> None:
    """Store a JSON-mode dump, not an opaque Pydantic object."""
    class Output(BaseModel):
        """Structured oracle payload."""
        value: int
    state = run(Agent(TestModel(custom_output_args={"value": 7}), output_type=Output))
    assert state.scratchpad["answer"] == {"value": 7}


def test_real_tool_runs_offline() -> None:
    """The test model exercises a real registered function tool."""
    calls: list[str] = []
    agent = Agent(TestModel(call_tools=["echo"], custom_output_text="done"))
    @agent.tool_plain
    def echo() -> str:
        """Record a local deterministic tool call."""
        calls.append("echo")
        return "echo"
    assert run(agent).scratchpad["answer"] == "done"
    assert calls == ["echo"]


def test_budget_exhausted_is_wrapper_termination() -> None:
    """A request ceiling stops the whole run without changing Core's terminal taxonomy."""
    downstream: list[str] = []
    node = as_node(Agent(TestModel()), prompt_from=lambda state: "prompt",
                   deps_from=lambda state: None, output_key="answer", offline_test=True,
                   usage_limits=UsageLimits(request_limit=0))
    graph = (MiniGraph().add_node("agent", node)
             .add_node("after", lambda state: downstream.append("after") or {})
             .add_edge(START, "agent").add_edge("agent", "after").add_edge("after", END))
    state = asyncio.run(graph.ainvoke(PerpetuaState(session_id="oracle")))
    assert state.status == "interrupted"
    assert state.metadata["interrupt_payload"]["compat_terminal_reason"] == "budget_exhausted"
    assert state.metadata["interrupt_payload"]["resumable"] is False
    assert downstream == []
    assert "answer" not in state.scratchpad


def test_deferred_approval_never_executes() -> None:
    """Deferred request becomes a structural interrupt and the tool stays unexecuted."""
    calls: list[str] = []
    agent = Agent(TestModel(call_tools=["dangerous"]), output_type=[str, DeferredToolRequests])
    @agent.tool_plain(requires_approval=True)
    def dangerous() -> str:
        """An approval-gated effect whose execution is forbidden in Phase 1."""
        calls.append("called")
        return "forbidden"
    state = run(agent)
    assert calls == []
    assert state.status == "interrupted"


def test_function_model_is_a_real_offline_target() -> None:
    """A caller-supplied real FunctionModel runs without any provider client."""
    def respond(messages, info):
        """Return one deterministic model response."""
        return ModelResponse(parts=[TextPart(content="function answer")])
    assert run(Agent(FunctionModel(respond))).scratchpad["answer"] == "function answer"


def test_changed_model_and_enabled_requests_are_refused(monkeypatch) -> None:
    """Revalidate mutable model selection and the global provider-request guard."""
    agent = Agent(TestModel())
    node = as_node(agent, prompt_from=lambda state: "prompt", deps_from=lambda state: None,
                   output_key="answer", offline_test=True)
    agent.model = object()
    with pytest.raises(BridgeRefused):
        asyncio.run(node(PerpetuaState(session_id="oracle")))
    agent.model = TestModel()
    monkeypatch.setattr(models, "ALLOW_MODEL_REQUESTS", True)
    with pytest.raises(BridgeRefused):
        asyncio.run(node(PerpetuaState(session_id="oracle")))
