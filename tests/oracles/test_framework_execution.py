"""Pinned real LC/LG topology and graph-tool integration, with no network."""
from __future__ import annotations

import asyncio
import socket

import pytest
from langchain_core.runnables import RunnableLambda
from langgraph.graph import END as LG_END
from pydantic import BaseModel
from pydantic_ai import Agent, models
from pydantic_ai.models.test import TestModel
from perpetua_core import END, START, MiniGraph, PerpetuaState
from perpetua_core.graph.adapters.langgraph_adapter import LangGraphExporter
from perpetua_core.graph.engine import ConditionalEdge
from orama.compat.graph_tool import graph_tool


@pytest.fixture(autouse=True)
def offline_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disallow network effects throughout real framework execution."""
    monkeypatch.setattr(models, "ALLOW_MODEL_REQUESTS", False)
    def blocked(*args: object, **kwargs: object) -> None:
        """Fail a socket dial instead of accidentally using a real provider."""
        pytest.fail("offline oracle attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


class Input(BaseModel):
    """Explicitly typed input for an external tool schema."""
    value: int


def tool(calls=None):
    """Expose one real Core graph as a framework-free callable."""
    def double(state):
        """Observe the actual graph node, without replacing the tool signature."""
        if calls is not None:
            calls.append(state.scratchpad["value"])
        return {"scratchpad": {"answer": state.scratchpad["value"] * 2}}
    graph = MiniGraph().add_node("double", double).add_edge(START, "double").add_edge("double", END)
    return graph_tool("double_graph", graph, input_model=Input, output_key="answer",
                      state_from=lambda payload: PerpetuaState(
                          session_id="oracle", scratchpad={"value": payload.value}))


def test_real_langchain_runnable_pipe() -> None:
    """Explicit RunnableLambda wrapping composes with real upstream LCEL."""
    pipeline = RunnableLambda(tool()) | RunnableLambda(lambda result: result + 1)
    assert asyncio.run(pipeline.ainvoke(Input(value=3))) == 7


def test_real_langgraph_declared_paths_and_execution() -> None:
    """Declared targets survive export; execution uses upstream's scheduler."""
    graph = MiniGraph().add_node("choose", lambda s: {}).add_node(
        "answer", lambda s: {"scratchpad": {"answer": 42}})
    graph.add_edge(START, "choose")
    graph.add_edge("choose", ConditionalEdge(
        lambda s: END if s.metadata.get("stop") else "answer",
        declared_targets=("answer", END)))
    graph.add_edge("answer", END)
    exported = LangGraphExporter.to_langgraph(graph, PerpetuaState)
    edges = {(edge.source, edge.target) for edge in exported.get_graph().edges}
    assert ("choose", "answer") in edges and ("choose", LG_END) in edges
    result = asyncio.run(exported.ainvoke(PerpetuaState(session_id="oracle")))
    assert result["scratchpad"]["answer"] == 42
    stopped = asyncio.run(exported.ainvoke(PerpetuaState(session_id="oracle", metadata={"stop": True})))
    assert "answer" not in stopped["scratchpad"]


def test_real_agent_registers_graph_tool_schema_and_executes() -> None:
    """Real Pydantic AI derives a schema and calls the import-free graph tool."""
    calls = []
    wrapped = tool(calls)
    agent = Agent(TestModel(call_tools=["double_graph"], custom_output_text="done"), tools=[wrapped])
    result = asyncio.run(agent.run("offline"))
    assert result.output == "done"
    assert len(calls) == 1
