"""
Default oramasys graph — 3-node example: route → dispatch → respond.

Replace or extend with your domain-specific MiniGraph nodes.
Hardware affinity check happens at the 'route' node before any LLM call.
"""
from __future__ import annotations
from pathlib import Path
from perpetua_core import MiniGraph, PerpetuaState, START, END
from perpetua_core.policy import HardwarePolicyResolver

_POLICY_PATH = Path(__file__).parent.parent.parent / "config" / "model_hardware_policy.yml"


async def route_node(state: PerpetuaState) -> dict:
    """Hardware affinity gate — raises HardwareAffinityError on NEVER verdict."""
    if _POLICY_PATH.exists():
        resolver = HardwarePolicyResolver.from_file(_POLICY_PATH)
        decision = resolver.resolve(
            task_type=state.task_type,
            optimize_for=state.optimize_for,
            model_hint=state.model_hint,
        )
        return {
            "metadata": {
                **state.metadata,
                "routed_model": decision.model,
                "routed_tier": decision.hardware_tier,
            }
        }
    return {}


async def dispatch_node(state: PerpetuaState) -> dict:
    """Placeholder — replace with actual LLMClient call."""
    model = state.metadata.get("routed_model", "unknown")
    return {
        "messages": [
            *state.messages,
            {"role": "assistant", "content": f"[{model}] Echo: {state.messages[0]['content']}"},
        ]
    }


def build_graph() -> MiniGraph:
    g = MiniGraph()
    g.add_node("route", route_node)
    g.add_node("dispatch", dispatch_node)
    g.add_edge(START, "route")
    g.add_edge("route", "dispatch")
    g.add_edge("dispatch", END)
    return g


graph = build_graph()
