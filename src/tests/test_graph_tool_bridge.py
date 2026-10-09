"""Graph-as-tool needs no third-party framework or second scheduler."""
from __future__ import annotations

import asyncio
import inspect
import ast
from pathlib import Path
import pytest

from pydantic import BaseModel
from perpetua_core import END, START, MiniGraph, PerpetuaState
from orama.compat.graph_tool import graph_tool


class Input(BaseModel):
    """Typed input that a caller-installed framework can derive a tool schema from."""
    text: str


def test_graph_tool_signature_and_execution() -> None:
    """Run the real graph while preserving a schema-readable signature."""
    graph = MiniGraph().add_node("a", lambda state: {"scratchpad": {"output": state.messages[0]["content"]}})
    graph.add_edge(START, "a").add_edge("a", END)
    tool = graph_tool("echo_graph", graph.compile(), input_model=Input,
        state_from=lambda value: PerpetuaState(session_id="tool", messages=[{"role": "user", "content": value.text}]),
        output_key="output", description="Echo through the native graph.")
    assert tool.__name__ == "echo_graph"
    assert inspect.signature(tool).parameters["request"].annotation is Input
    assert "native graph" in tool.__doc__
    assert asyncio.run(tool(Input(text="hello"))) == "hello"


def test_graph_tool_module_imports_nothing() -> None:
    """Keep the exact import-free bridge contract executable."""
    import orama.compat.graph_tool as module
    tree = ast.parse(Path(module.__file__).read_text())
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree))


@pytest.mark.parametrize("status,error", [("interrupted", None), ("done", "denied")])
def test_graph_tool_does_not_report_stale_output_after_refusal(status, error) -> None:
    """An interrupted/failed run must not return an earlier scratchpad answer."""
    class Graph:
        """Model a native terminal refusal carrying a stale prior output."""
        async def ainvoke(self, state):
            """Return refused state without executing an effect."""
            return PerpetuaState(session_id="test", status=status, error=error,
                                 scratchpad={"output": "stale"})
    tool = graph_tool("refused_graph", Graph(), input_model=Input,
                      state_from=lambda payload: None, output_key="output")
    with pytest.raises(RuntimeError, match="did not complete"):
        asyncio.run(tool(Input(text="hello")))
