"""Duck-typed LangChain / LangGraph façade over the native admission-gated graph.

This module imports no third-party framework (the framework import contract holds). It produces
objects *shaped* like a LangChain ``Runnable`` / ``StructuredTool`` and a LangGraph node so a caller
that owns the framework can register them; it never schedules work itself. Every call goes through
the caller-supplied admission ``runner``, so nothing here widens what the graph may do. Contract:
``docs/langchain-langgraph-facade.md``.

Closed and refused rather than emulated, because each would be an unadmitted execution path:

* ``configurable`` and any unknown config key are refused when non-empty. ``callbacks``,
  ``recursion_limit`` and ``run_id`` are tolerated but *never acted on* (real LangChain propagates
  them into every nested call); no callback is ever invoked, so there is no tracing. Only ``tags``,
  ``metadata``, ``run_name`` and ``max_concurrency`` are honoured.
* ``astream`` yields exactly one final chunk; there is no incremental or token streaming.
* ``invoke`` (sync) refuses inside a running event loop instead of nesting one.
* Every facade carries ``effect_kind = "untrusted"``; production foreign effects stay refused.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from typing import Any, Final

HONOURED_CONFIG_KEYS: Final = frozenset({"tags", "metadata", "run_name", "max_concurrency"})
MAX_CONCURRENCY_CEILING: Final = 8
IGNORED_CONFIG_KEYS: Final = frozenset({"callbacks", "recursion_limit", "run_id"})
FACADE_REFUSAL_CODES: Final = frozenset({
    "facade.config_unsupported", "facade.sync_in_running_loop",
    "facade.schema_unavailable", "facade.bad_input", "facade.bad_concurrency",
})


class FacadeRefused(PermissionError):
    """A closed-vocabulary façade refusal carrying a stable ``code``."""

    def __init__(self, code: str) -> None:
        """Record the code, which must belong to the façade vocabulary."""
        if code not in FACADE_REFUSAL_CODES:
            raise ValueError(f"unknown facade refusal code: {code}")
        super().__init__(code)
        self.code = code


def check_config(config: object) -> dict[str, Any]:
    """Return the honoured subset of a LangChain-style config, refusing anything else non-empty."""
    if config is None:
        return {}
    if not isinstance(config, Mapping):
        raise FacadeRefused("facade.config_unsupported")
    for key, value in config.items():
        if key in HONOURED_CONFIG_KEYS or key in IGNORED_CONFIG_KEYS or not value:
            continue
        raise FacadeRefused("facade.config_unsupported")
    return {key: config[key] for key in HONOURED_CONFIG_KEYS if key in config}


def _concurrency(config: Mapping[str, Any]) -> int:
    """Return the validated batch concurrency, defaulting to strictly sequential."""
    value = config.get("max_concurrency", 1)
    value = 1 if value is None else value
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_CONCURRENCY_CEILING:
        raise FacadeRefused("facade.bad_concurrency")
    return value


class FacadeRunnable:
    """``Runnable``-shaped wrapper over one coroutine that already runs through admission."""

    effect_kind = "untrusted"

    def __init__(
        self, name: str, call: Callable[[Any], Any], *, coerce: Callable[[Any], Any],
        schema: Callable[[], dict[str, Any]] | None = None, description: str = "",
    ) -> None:
        """Bind the awaited callable, the explicit input coercion and an optional schema source."""
        if not isinstance(name, str) or not name.isidentifier():
            raise ValueError("facade name must be an identifier")
        self.name, self.description = name, description
        self._call, self._coerce, self._schema = call, coerce, schema

    def get_input_jsonschema(self, config: object = None) -> dict[str, Any]:
        """Return the input JSON schema, or refuse when the input model cannot supply one."""
        check_config(config)
        if self._schema is None:
            raise FacadeRefused("facade.schema_unavailable")
        return self._schema()

    async def ainvoke(self, input: Any, config: object = None, **kwargs: Any) -> Any:
        """Run once through the admission runner; extra keyword arguments are refused."""
        if kwargs:
            raise FacadeRefused("facade.config_unsupported")
        check_config(config)
        return await self._call(self._coerce(input))

    def invoke(self, input: Any, config: object = None, **kwargs: Any) -> Any:
        """Synchronous entry point; refuses inside a running loop rather than nesting one."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.ainvoke(input, config, **kwargs))
        raise FacadeRefused("facade.sync_in_running_loop")

    def batch(
        self, inputs: Sequence[Any], config: object = None, *, return_exceptions: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        """Run inputs in order; concurrency is whatever ``max_concurrency`` allows (default 1)."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.abatch(inputs, config, return_exceptions=return_exceptions, **kwargs))
        raise FacadeRefused("facade.sync_in_running_loop")

    async def abatch(
        self, inputs: Sequence[Any], config: object = None, *, return_exceptions: bool = False,
        **kwargs: Any,
    ) -> list[Any]:
        """Run inputs with at most ``max_concurrency`` in flight; results keep input order."""
        if kwargs:
            raise FacadeRefused("facade.config_unsupported")
        honoured = check_config(config)
        gate = asyncio.Semaphore(_concurrency(honoured))

        async def one(value: Any) -> Any:
            """Run one input under the concurrency gate."""
            async with gate:
                return await self._call(self._coerce(value))

        return list(await asyncio.gather(*(one(v) for v in inputs), return_exceptions=return_exceptions))

    async def astream(self, input: Any, config: object = None, **kwargs: Any) -> AsyncIterator[Any]:
        """Yield exactly one final chunk; incremental streaming is deliberately unsupported."""
        yield await self.ainvoke(input, config, **kwargs)

    def stream(self, input: Any, config: object = None, **kwargs: Any) -> Any:
        """Synchronous single-chunk stream."""
        yield self.invoke(input, config, **kwargs)


def tool_facade(tool: Callable[..., Any], *, input_model: type, description: str | None = None) -> FacadeRunnable:
    """Wrap a ``graph_tool`` result as a StructuredTool-shaped object with validated input.

    ``tool`` MUST be the callable returned by ``orama.compat.graph_tool.graph_tool``: that function
    refuses to build without an admission runner, and every call it makes goes through that runner.
    This facade does not add admission of its own, so an arbitrary callable would run unadmitted.
    """
    if not callable(tool) or not getattr(tool, "__name__", ""):
        raise ValueError("tool must be a named graph_tool result")
    name = tool.__name__

    def coerce(value: object) -> object:
        """Accept the typed model or a mapping that validates into it; refuse anything else."""
        if isinstance(value, input_model):
            return value
        if isinstance(value, Mapping):
            return input_model(**value)
        raise FacadeRefused("facade.bad_input")

    schema = getattr(input_model, "model_json_schema", None)
    facade = FacadeRunnable(
        name, tool, coerce=coerce, schema=schema if callable(schema) else None,
        description=description if description is not None else (tool.__doc__ or ""),
    )
    facade.args_schema = input_model  # type: ignore[attr-defined]
    facade.return_direct = False  # type: ignore[attr-defined]
    return facade


def graph_runnable(
    name: str, graph: object, *, runner: object, state_from: Callable[[Any], Any], output_key: str,
    input_model: type | None = None, description: str = "Run the native compiled graph.",
) -> FacadeRunnable:
    """Expose a compiled native graph as a Runnable whose every call goes through the runner."""
    if (
        not callable(getattr(graph, "ainvoke", None)) or not callable(getattr(runner, "invoke", None))
        or not callable(state_from) or not isinstance(output_key, str) or not output_key.strip()
    ):
        raise ValueError("graph, admission runner, state mapper and output key must be explicit")

    async def call(value: Any) -> Any:
        """Run through admission and return the named output, never a stale or partial one."""
        result = await runner.invoke(graph, state_from(value))  # type: ignore[attr-defined]
        if result.status != "done" or result.error is not None:
            raise RuntimeError("graph did not complete successfully")
        if output_key not in result.scratchpad:
            raise RuntimeError(f"graph completed without output key {output_key!r}")
        return result.scratchpad[output_key]

    def coerce(value: object) -> object:
        """Validate against the optional input model; otherwise pass the value through."""
        if input_model is None or isinstance(value, input_model):
            return value
        if isinstance(value, Mapping):
            return input_model(**value)
        raise FacadeRefused("facade.bad_input")

    schema = getattr(input_model, "model_json_schema", None) if input_model is not None else None
    return FacadeRunnable(
        name, call, coerce=coerce, schema=schema if callable(schema) else None, description=description)


def langgraph_node(
    name: str, graph: object, *, runner: object, state_from: Callable[[Mapping[str, Any]], Any],
    output_map: Mapping[str, str],
) -> Callable[..., Any]:
    """Return an async LangGraph-style node: ``(state_dict, config=None) -> partial_state_dict``.

    ``output_map`` maps native scratchpad keys to the LangGraph state keys they update. A missing
    native key, a non-``done`` run or an error raises instead of returning a partial update.
    """
    if (
        not isinstance(name, str) or not name.isidentifier() or not output_map
        or not callable(getattr(graph, "ainvoke", None)) or not callable(getattr(runner, "invoke", None))
        or not callable(state_from)
        or any(not isinstance(k, str) or not isinstance(v, str) or not k or not v for k, v in output_map.items())
        or len(set(output_map.values())) != len(output_map)
    ):
        raise ValueError("node name, graph, admission runner, state mapper and output map must be explicit")
    mapping = dict(output_map)

    async def node(state: Mapping[str, Any], config: object = None) -> dict[str, Any]:
        """Run the graph under admission and return only the mapped keys."""
        check_config(config)
        if not isinstance(state, Mapping):
            raise FacadeRefused("facade.bad_input")
        result = await runner.invoke(graph, state_from(state))  # type: ignore[attr-defined]
        if result.status != "done" or result.error is not None:
            raise RuntimeError("graph did not complete successfully")
        missing = [key for key in mapping if key not in result.scratchpad]
        if missing:
            raise RuntimeError(f"graph completed without output keys {missing!r}")
        return {target: result.scratchpad[source] for source, target in mapping.items()}

    node.__name__ = name
    node.effect_kind = "untrusted"  # type: ignore[attr-defined]
    return node
