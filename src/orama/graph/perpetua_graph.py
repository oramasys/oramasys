"""
Default oramasys graph — 3-node example: route → dispatch → respond.

- route_node:    hardware affinity gate (HardwarePolicyResolver, optional)
- dispatch_node: consults a BackendRegistry via select_backend() and records
                 resolved_backend / resolved_url in state.metadata.
                 (Actual LLMClient invocation is Phase 3 — out of scope.)
- respond_node:  appends an assistant message announcing the resolved backend.
"""
from __future__ import annotations
from pathlib import Path

from perpetua_core import MiniGraph, PerpetuaState, START, END
from perpetua_core.policy import HardwarePolicyResolver
from perpetua_core.discovery import BackendRegistry, select_backend
from perpetua_core.discovery.errors import NoBackendAvailableError

_POLICY_PATH = Path(__file__).parent.parent.parent / "config" / "model_hardware_policy.yml"


def build_graph(*, registry: BackendRegistry | None = None) -> MiniGraph:
    """Build the default 3-node graph.

    Args:
        registry: optional BackendRegistry. If None, an empty registry is used
                  (dispatch will then record an error rather than resolving).
    """
    reg = registry if registry is not None else BackendRegistry()

    async def route_node(state: PerpetuaState) -> dict:
        """Hardware affinity gate — raises HardwareAffinityError on NEVER verdict."""
        meta_extra: dict = {"routed_at": "route_node"}
        if _POLICY_PATH.exists():
            resolver = HardwarePolicyResolver.from_file(_POLICY_PATH)
            decision = resolver.resolve(
                task_type=state.task_type,
                optimize_for=state.optimize_for,
                model_hint=state.model_hint,
            )
            meta_extra["routed_model"] = decision.model
            meta_extra["routed_tier"] = decision.hardware_tier
        return {"metadata": {**state.metadata, **meta_extra}}

    async def dispatch_node(state: PerpetuaState) -> dict:
        """Consult the discovery registry; record the resolved backend.

        Placeholder for the actual LLMClient call (Phase 3). Graceful on empty
        registries: NoBackendAvailableError lands in state.error rather than
        propagating, so the graph still terminates cleanly.
        """
        try:
            backend = select_backend(
                reg,
                model_hint=state.model_hint,
                task_type=state.task_type,
                target_tier=state.target_tier,
            )
        except NoBackendAvailableError as exc:
            return {
                "error": str(exc),
                "metadata": {**state.metadata, "resolved_backend": None},
            }
        return {
            "metadata": {
                **state.metadata,
                "resolved_backend": backend.name,
                "resolved_url": backend.base_url,
            }
        }

    async def respond_node(state: PerpetuaState) -> dict:
        resolved = state.metadata.get("resolved_backend") or "unresolved"
        return {
            "messages": [
                *state.messages,
                {"role": "assistant", "content": f"dispatched to {resolved}"},
            ]
        }

    g = MiniGraph()
    g.add_node("route", route_node)
    g.add_node("dispatch", dispatch_node)
    g.add_node("respond", respond_node)
    g.add_edge(START, "route")
    g.add_edge("route", "dispatch")
    g.add_edge("dispatch", "respond")
    g.add_edge("respond", END)
    return g


graph = build_graph()
