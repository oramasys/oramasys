# LangChain / LangGraph façade contract

`orama.compat.langchain_facade` exposes native admission-gated graphs in the *shape* of a LangChain
`Runnable` / `StructuredTool` and a LangGraph node. It imports no third-party framework.

## What it provides
- `graph_runnable(...)`: `invoke/ainvoke/batch/abatch/stream/astream`, `get_input_jsonschema`.
- `tool_facade(tool, input_model=...)`: `name`, `description`, `args_schema`, validated input.
- `langgraph_node(...)`: async `(state, config) -> partial state`, with an explicit native→state key map.

## Invariants (each enforced by `test_langchain_facade.py`)
1. Every call goes through the caller-supplied admission runner exactly once.
2. Config is closed: only `tags`, `metadata`, `run_name`, `max_concurrency` are honoured. `callbacks`,
   `recursion_limit` and `run_id` are tolerated because real LangChain propagates them into every nested
   call, but they are never invoked or acted on (no tracing). Non-empty `configurable` or unknown keys are
   refused. A real `langchain_core` chain test found the original stricter rule broke composition.
3. `max_concurrency` defaults to 1. Values above 8, zero, booleans and non-integers are refused with
   `facade.bad_concurrency` (never silently reduced).
4. A run that is not `done`, has an error, or lacks the named output key raises; stale data is never returned.
5. Streaming is one final chunk. Sync entry points refuse inside a running event loop.
6. `effect_kind = "untrusted"`; no new effect capability is introduced and effects remain refused.
7. Stdlib-only imports (AST-checked); a conformance test runs only if `langchain_core` is installed.

## Not provided
Token/incremental streaming, callbacks/tracing, checkpointers, `configurable` fields and arbitrary
LangGraph graph compilation. Each would be an unadmitted execution path and needs its own review.
