"""
Default oramasys graph — route → dispatch → respond.

- route_node: hardware affinity gate (HardwarePolicyResolver, optional)
- dispatch_node: consults BackendRegistry/select_backend and records routing
  metadata; when an explicit ProviderInvoker is injected, it performs the
  application-level invocation through that contract.
- respond_node: emits provider content when present, otherwise preserves the
  Phase-2 compatibility response announcing the resolved backend.

No production network client belongs in this module. Real provider transport
must remain behind a Telos-backed ProviderInvoker implementation.
"""
from __future__ import annotations

from pathlib import Path

from perpetua_core import END, START, MiniGraph, PerpetuaState
from perpetua_core.discovery import BackendRegistry, select_backend
from perpetua_core.discovery.errors import NoBackendAvailableError
from perpetua_core.policy import HardwarePolicyResolver

from orama.providers import (
    ProviderInvocationRequest,
    ProviderInvoker,
    ProviderMessage,
)

_POLICY_PATH = Path(__file__).parent.parent.parent / "config" / "model_hardware_policy.yml"


def _provider_messages(state: PerpetuaState) -> tuple[ProviderMessage, ...]:
    messages: list[ProviderMessage] = []
    for item in state.messages:
        role = item.get("role") if isinstance(item, dict) else None
        content = item.get("content") if isinstance(item, dict) else None
        if isinstance(role, str) and isinstance(content, str):
            messages.append(ProviderMessage(role=role, content=content))
    return tuple(messages)


def build_graph(
    *,
    registry: BackendRegistry | None = None,
    provider_invoker: ProviderInvoker | None = None,
) -> MiniGraph:
    """Build the default graph.

    ``provider_invoker`` is an explicit Phase-3 seam. Omitting it preserves the
    existing Phase-2 behavior and performs no provider network invocation.
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
        """Resolve a backend and optionally invoke it through the provider port."""
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

        metadata = {
            **state.metadata,
            "resolved_backend": backend.name,
            "resolved_url": backend.base_url,
        }

        if provider_invoker is None:
            return {"metadata": metadata}

        model = state.model_hint or (backend.models[0] if backend.models else "")
        if not model:
            return {
                "error": f"backend {backend.name!r} has no model available for invocation",
                "metadata": metadata,
            }

        result = await provider_invoker.invoke(
            ProviderInvocationRequest(
                backend=backend,
                model=model,
                messages=_provider_messages(state),
                run_id=str(state.metadata.get("run_id") or state.session_id),
            )
        )
        return {
            "metadata": {
                **metadata,
                "provider_ref": result.provider_ref,
                "decision_ref": result.decision_ref,
                "provider_content": result.content,
            }
        }

    async def respond_node(state: PerpetuaState) -> dict:
        provider_content = state.metadata.get("provider_content")
        if isinstance(provider_content, str):
            content = provider_content
        else:
            resolved = state.metadata.get("resolved_backend") or "unresolved"
            content = f"dispatched to {resolved}"
        return {
            "messages": [
                *state.messages,
                {"role": "assistant", "content": content},
            ]
        }

    graph_builder = MiniGraph()
    graph_builder.add_node("route", route_node)
    graph_builder.add_node("dispatch", dispatch_node)
    graph_builder.add_node("respond", respond_node)
    graph_builder.add_edge(START, "route")
    graph_builder.add_edge("route", "dispatch")
    graph_builder.add_edge("dispatch", "respond")
    graph_builder.add_edge("respond", END)
    return graph_builder


graph = build_graph()
