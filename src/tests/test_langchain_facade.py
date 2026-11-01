"""Duck-typed LangChain/LangGraph façade: strict config, admission-gated, framework-free."""
from __future__ import annotations

import ast
import asyncio
import inspect

import pytest
from perpetua_core import END, START, MiniGraph, PerpetuaState
from pydantic import BaseModel

from orama.compat import langchain_facade
from orama.compat.graph_tool import graph_tool
from orama.compat.langchain_facade import (
    FacadeRefused,
    check_config,
    graph_runnable,
    langgraph_node,
    tool_facade,
)


class Input(BaseModel):
    """Typed input."""
    text: str


class Runner:
    """Admission runner double that records every call."""

    def __init__(self) -> None:
        """Start with no calls."""
        self.calls = 0
        self.live = 0
        self.peak = 0

    async def invoke(self, graph, state):
        """Count the call, track concurrency, and run the graph."""
        self.calls += 1
        self.live += 1
        self.peak = max(self.peak, self.live)
        await asyncio.sleep(0.01)
        try:
            return await graph.ainvoke(state)
        finally:
            self.live -= 1


def echo_graph():
    """Return a compiled graph copying the first message into the scratchpad."""
    graph = MiniGraph().add_node("a", lambda s: {"scratchpad": {"output": s.messages[0]["content"], "n": 1}})
    graph.add_edge(START, "a").add_edge("a", END)
    return graph.compile()


def make_state(value):
    """Map an input to native state."""
    text = value.text if isinstance(value, Input) else value["text"]
    return PerpetuaState(session_id="s", messages=[{"role": "user", "content": text}])


def test_facade_modules_import_no_third_party_framework() -> None:
    """The façade is stdlib only, so the framework import contract holds."""
    tree = ast.parse(inspect.getsource(langchain_facade))
    roots = {
        (n.module or "").split(".")[0] if isinstance(n, ast.ImportFrom) else a.name.split(".")[0]
        for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert roots <= {"__future__", "asyncio", "collections", "typing"}


def test_tool_facade_is_structured_tool_shaped_and_validates_input() -> None:
    """name/description/args_schema exist; mapping input validates; wrong types are refused."""
    runner = Runner()
    tool = graph_tool("echo", echo_graph(), input_model=Input, state_from=make_state,
                      output_key="output", runner=runner, description="Echo.")
    facade = tool_facade(tool, input_model=Input)
    assert (facade.name, facade.description, facade.args_schema, facade.return_direct) == ("echo", "Echo.", Input, False)
    assert facade.get_input_jsonschema()["properties"]["text"]["type"] == "string"
    assert facade.invoke({"text": "hi"}) == "hi" and facade.invoke(Input(text="yo")) == "yo"
    assert facade.effect_kind == "untrusted"
    with pytest.raises(FacadeRefused) as bad:
        asyncio.run(facade.ainvoke(42))
    assert bad.value.code == "facade.bad_input"
    with pytest.raises(ValueError):
        asyncio.run(facade.ainvoke({"wrong": 1}))
    assert runner.calls == 2


def test_every_call_goes_through_the_admission_runner() -> None:
    """Runnable, tool and node each invoke the runner exactly once per call."""
    runner = Runner()
    runnable = graph_runnable("echo_run", echo_graph(), runner=runner, state_from=make_state,
                              output_key="output", input_model=Input)
    assert runnable.invoke({"text": "a"}) == "a"
    node = langgraph_node("echo_node", echo_graph(), runner=runner, state_from=make_state,
                          output_map={"output": "answer", "n": "count"})
    assert asyncio.run(node({"text": "b"})) == {"answer": "b", "count": 1}
    assert runner.calls == 2 and node.effect_kind == "untrusted" and node.__name__ == "echo_node"


@pytest.mark.parametrize("config,code", [
    ({"callbacks": [object()]}, "facade.callbacks_unsupported"),
    ({"configurable": {"x": 1}}, "facade.config_unsupported"),
    ({"recursion_limit": 5}, "facade.config_unsupported"),
    ({"unknown": "x"}, "facade.config_unsupported"),
    ("not a mapping", "facade.config_unsupported"),
])
def test_unsupported_config_is_refused(config, code) -> None:
    """Callbacks and every other unadmitted config key are refused when non-empty."""
    with pytest.raises(FacadeRefused) as caught:
        check_config(config)
    assert caught.value.code == code


def test_empty_framework_defaults_and_honoured_keys_pass() -> None:
    """LangChain's empty defaults are accepted and the honoured keys are returned."""
    assert check_config(None) == {}
    assert check_config({"callbacks": [], "configurable": {}, "recursion_limit": 0, "tags": ["t"],
                         "max_concurrency": 2}) == {"tags": ["t"], "max_concurrency": 2}


def test_batch_order_and_bounded_concurrency() -> None:
    """Results keep input order; concurrency defaults to 1 and never exceeds the ceiling."""
    runner = Runner()
    runnable = graph_runnable("echo_run", echo_graph(), runner=runner, state_from=make_state,
                              output_key="output", input_model=Input)
    inputs = [{"text": str(i)} for i in range(6)]
    assert asyncio.run(runnable.abatch(inputs)) == ["0", "1", "2", "3", "4", "5"] and runner.peak == 1
    runner.peak = 0
    asyncio.run(runnable.abatch(inputs, {"max_concurrency": 3}))
    assert runner.peak == 3
    for bad in (0, 9, True, "2"):
        with pytest.raises(FacadeRefused) as caught:
            asyncio.run(runnable.abatch(inputs, {"max_concurrency": bad}))
        assert caught.value.code == "facade.bad_concurrency"
    assert runnable.batch(inputs[:2]) == ["0", "1"]


def test_abatch_can_return_exceptions_without_losing_order() -> None:
    """return_exceptions keeps a failed item in place."""
    runner = Runner()
    runnable = graph_runnable("echo_run", echo_graph(), runner=runner, state_from=make_state,
                              output_key="output", input_model=Input)
    out = asyncio.run(runnable.abatch([{"text": "a"}, {"bad": 1}, {"text": "c"}], return_exceptions=True))
    assert out[0] == "a" and isinstance(out[1], ValueError) and out[2] == "c"


def test_sync_entry_points_refuse_inside_a_running_loop() -> None:
    """invoke/batch never nest an event loop."""
    runnable = graph_runnable("echo_run", echo_graph(), runner=Runner(), state_from=make_state,
                              output_key="output", input_model=Input)

    async def inside() -> None:
        for call in (lambda: runnable.invoke({"text": "a"}), lambda: runnable.batch([{"text": "a"}])):
            with pytest.raises(FacadeRefused) as caught:
                call()
            assert caught.value.code == "facade.sync_in_running_loop"

    asyncio.run(inside())


def test_streaming_is_exactly_one_final_chunk() -> None:
    """astream and stream yield one chunk; there is no incremental streaming."""
    runnable = graph_runnable("echo_run", echo_graph(), runner=Runner(), state_from=make_state,
                              output_key="output", input_model=Input)

    async def collect():
        return [chunk async for chunk in runnable.astream({"text": "z"})]

    assert asyncio.run(collect()) == ["z"] and list(runnable.stream({"text": "y"})) == ["y"]


def test_unfinished_or_missing_output_never_returns_stale_data() -> None:
    """Refused runs and absent output keys raise instead of returning a partial update."""
    class Refusing:
        async def ainvoke(self, state):
            return PerpetuaState(session_id="s", status="interrupted", scratchpad={"output": "stale"})

    runner = Runner()
    runnable = graph_runnable("r", Refusing(), runner=runner, state_from=make_state, output_key="output")
    with pytest.raises(RuntimeError, match="did not complete"):
        runnable.invoke({"text": "a"})
    node = langgraph_node("n", echo_graph(), runner=runner, state_from=make_state,
                          output_map={"missing": "x"})
    with pytest.raises(RuntimeError, match="without output keys"):
        asyncio.run(node({"text": "a"}))
    with pytest.raises(FacadeRefused):
        asyncio.run(node("not a mapping"))


def test_constructors_and_schema_guards() -> None:
    """Bad names, missing runners and schema-less models are explicit errors."""
    with pytest.raises(ValueError):
        graph_runnable("bad name", echo_graph(), runner=Runner(), state_from=make_state, output_key="o")
    with pytest.raises(ValueError):
        graph_runnable("ok", echo_graph(), runner=object(), state_from=make_state, output_key="o")
    with pytest.raises(ValueError):
        langgraph_node("n", echo_graph(), runner=Runner(), state_from=make_state, output_map={})
    bare = graph_runnable("ok", echo_graph(), runner=Runner(), state_from=make_state, output_key="output")
    with pytest.raises(FacadeRefused) as schema:
        bare.get_input_jsonschema()
    assert schema.value.code == "facade.schema_unavailable"
    with pytest.raises(FacadeRefused):
        asyncio.run(bare.ainvoke({"text": "a"}, extra=1))
    with pytest.raises(ValueError):
        FacadeRefused("facade.invented")


def test_runnable_protocol_with_the_real_framework_when_installed() -> None:
    """If langchain_core is present, the façade composes inside a real RunnableLambda chain."""
    core = pytest.importorskip("langchain_core.runnables")
    runnable = graph_runnable("echo_run", echo_graph(), runner=Runner(), state_from=make_state,
                              output_key="output", input_model=Input)
    chain = core.RunnableLambda(lambda text: {"text": text}) | core.RunnableLambda(runnable.invoke)
    assert chain.invoke("hello") == "hello"
