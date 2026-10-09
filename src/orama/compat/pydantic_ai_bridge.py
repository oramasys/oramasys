"""Explicit Phase-1 bridge. Only deterministic offline tests may execute today."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from perpetua_core.graph.plugins.interrupts import Interrupt
from perpetua_core.state import PerpetuaState


class BridgeRefused(PermissionError):
    """Production foreign effects remain refused until enforceable admission exists."""


def as_node(agent: object, *, prompt_from: Callable[[PerpetuaState], str],
            deps_from: Callable[[PerpetuaState], Any], output_key: str,
            offline_test: bool = False, usage_limits: object = None) -> Callable[..., Any]:
    """Wrap a caller agent; offline_test is test scope, never an egress authorization.

    A trusted test harness must also install a socket guard. Real providers,
    deferred approvals, automatic resume, and streaming are deliberately gated.
    Import and dependency failures propagate without a silent alternate path.
    """
    if not offline_test:
        raise BridgeRefused("production agent effects require durable admission and Telos transport")
    if not callable(prompt_from) or not callable(deps_from):
        raise TypeError("explicit prompt and dependency mappers required")
    from pydantic_ai import Agent, DeferredToolRequests, models
    from pydantic_ai.exceptions import UsageLimitExceeded
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.models.test import TestModel

    if not isinstance(agent, Agent) or not isinstance(output_key, str) or not output_key.strip():
        raise TypeError("explicit Agent and output key required")

    def check_offline() -> None:
        """Recheck after construction so changed providers cannot evade the offline gate."""
        if models.ALLOW_MODEL_REQUESTS or type(agent.model) not in (TestModel, FunctionModel):
            raise BridgeRefused("offline test model and ALLOW_MODEL_REQUESTS=False required")

    check_offline()

    async def node(state: PerpetuaState) -> dict[str, Any]:
        """Return a state delta with usage metadata only; never export message bodies."""
        check_offline()
        try:
            result = await agent.run(prompt_from(state), deps=deps_from(state), usage_limits=usage_limits)
        except UsageLimitExceeded:
            return {"error": "agent budget exhausted", "metadata": {
                **state.metadata, "compat_terminal_reason": "budget_exhausted"}}
        output = result.output
        if isinstance(output, DeferredToolRequests):
            raise Interrupt("agent tool approval pending", payload={
                "reason": "durable_approval_unavailable",
                "pending_count": len(output.approvals) + len(output.calls),
            })
        dump = getattr(output, "model_dump", None)
        stored = dump(mode="json") if callable(dump) else output
        usage = result.usage()
        return {"scratchpad": {**state.scratchpad, output_key: stored}, "metadata": {
            **state.metadata, "agent_usage": {"requests": usage.requests,
                "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens}}}

    node.effect_kind = "untrusted"
    return node
