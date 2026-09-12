"""
Default oramasys graph — route → dispatch → respond.

- route_node: hardware affinity gate, backed by agate (oramasys/agate), the
  canonical v2 hardware authority -- never orama-system's legacy dynamic PT
  import and never a locally-embedded duplicate resolver.
- dispatch_node: consults BackendRegistry/select_backend and records routing
  metadata; when an explicit ProviderInvoker is injected, it performs the
  application-level invocation through that contract.
- respond_node: emits provider content when present, otherwise preserves the
  Phase-2 compatibility response announcing the resolved backend.

No production network client belongs in this module. Real provider transport
must remain behind a Telos-backed ProviderInvoker implementation.
"""
from __future__ import annotations

import asyncio

from agate import HardwareAffinityError, load_policy_cached
from perpetua_core import END, START, MiniGraph, PerpetuaState
from perpetua_core.discovery import BackendRegistry, select_backend
from perpetua_core.discovery.errors import NoBackendAvailableError
from perpetua_core.graph.plugins.interrupts import Interrupt
from perpetua_core.graph.spec import EdgeSpec, GraphSpec, NodeSpec, stable_callable_ref

from orama.providers import (
    AbortableProviderInvoker,
    OutboundLedger,
    OutboundLedgerEntry,
    ProviderInvocationRequest,
    ProviderInvoker,
    ProviderMessage,
)

_TIER_TO_REPRESENTATIVE_PROFILE = {
    "mac": "mac-studio",
    "windows": "win-rtx3080",
    "shared": "mac-studio",
}


def _representative_profile_id(target_tier: str) -> str:
    try:
        return _TIER_TO_REPRESENTATIVE_PROFILE[target_tier]
    except KeyError:
        raise ValueError(f"unknown target_tier: {target_tier!r}") from None


_DEFAULT_MAX_ABANDONED_INVOCATIONS = 8


def _track_abandoned(task: asyncio.Task, registry: set[asyncio.Task]) -> None:
    """Track a fire-and-forget task so its resource footprint is bounded
    and observable instead of vanishing into the event loop untracked."""
    registry.add(task)

    def _on_done(finished: asyncio.Task) -> None:
        registry.discard(finished)
        if not finished.cancelled() and finished.exception() is not None:
            # Abandoned background work failing is expected -- that's
            # exactly why it was abandoned. The ledger already recorded
            # the timeout that caused this; swallow here so it doesn't
            # also surface as an "exception was never retrieved" warning
            # at garbage-collection time.
            pass

    task.add_done_callback(_on_done)


def _provider_messages(state: PerpetuaState) -> tuple[ProviderMessage, ...]:
    """Convert valid state messages into immutable provider messages."""
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
    outbound_ledger: OutboundLedger | None = None,
    invocation_timeout_seconds: float | None = None,
    max_abandoned_invocations: int = _DEFAULT_MAX_ABANDONED_INVOCATIONS,
) -> MiniGraph:
    """Build the default graph.

    ``provider_invoker`` is an explicit Phase-3 seam. Omitting it preserves the
    existing Phase-2 behavior and performs no provider network invocation.

    ``outbound_ledger`` records one append-only entry per outbound dispatch
    attempt (success, contained failure, or timeout) for audit correlation.
    When omitted, dispatch behavior is unchanged and nothing is recorded.

    ``invocation_timeout_seconds`` bounds a hung provider invocation; on
    expiry the dispatch fails closed with a timeout error delta instead of
    hanging the graph. Uses ``asyncio.wait`` rather than ``asyncio.wait_for``
    so an invoker that catches ``CancelledError`` and continues I/O cannot
    extend the dispatch past this deadline — the timeout branch returns
    immediately and lets the abandoned task finish (or not) in the
    background, it never awaits that task's own completion.

    Hard termination against an invoker that ignores cancellation is a
    two-part mitigation, both scoped to this one ``build_graph()`` call
    (each graph instance owns its own abandoned-task registry):

    1. If ``provider_invoker`` also implements ``AbortableProviderInvoker``
       (an optional capability, checked structurally), its ``abort()`` is
       fired alongside ``.cancel()`` on timeout -- a second, independent
       chance to force resource release (e.g. closing an underlying
       transport) that does not depend on the invoker's own coroutine ever
       noticing cancellation.
    2. Every abandoned task (the cancelled ``invoke()`` and, when present,
       the ``abort()`` call) is tracked in a bounded registry. Once
       ``max_abandoned_invocations`` abandoned tasks are outstanding, a new
       dispatch fails closed immediately (``provider_outcome: circuit_open``)
       instead of piling more uncooperative background work on top --
       bounding "accumulate without a bound" even when neither invoker
       cooperation nor ``abort()`` actually stops anything. Only meaningful
       when ``invocation_timeout_seconds`` is set; otherwise no task is ever
       abandoned in the first place.
    """

    reg = registry if registry is not None else BackendRegistry()
    abandoned_tasks: set[asyncio.Task] = set()

    async def route_node(state: PerpetuaState) -> dict:
        """Apply the hardware-affinity routing policy via agate, the
        canonical v2 hardware authority -- never orama-system's legacy
        dynamic PT import (v1, frozen) and never perpetua-core's own
        now-superseded duplicate resolver."""
        meta_extra: dict = {"routed_at": "route_node"}
        profile_id = _representative_profile_id(state.target_tier)
        store = load_policy_cached()

        if state.model_hint:
            try:
                verdict = store.decide(state.model_hint, profile_id)
            except HardwareAffinityError as exc:
                return {
                    "error": str(exc),
                    "metadata": {**state.metadata, **meta_extra, "routed_tier": state.target_tier},
                }
            meta_extra["routed_model"] = state.model_hint
            meta_extra["routed_tier"] = state.target_tier
            meta_extra["routed_verdict"] = verdict
        else:
            preferred = store.preferred_model(profile_id, task_key=state.task_type)
            if preferred is not None:
                meta_extra["routed_model"] = preferred
                meta_extra["routed_tier"] = state.target_tier

        return {"metadata": {**state.metadata, **meta_extra}}

    async def dispatch_node(state: PerpetuaState) -> dict:
        """Resolve a backend and contain provider failures at the dispatch boundary."""
        if state.error is not None:
            # A prior node (route_node's hardware-affinity gate) already
            # failed closed. Attempting dispatch anyway would silently
            # overwrite that error with an unrelated "no backend" failure,
            # discarding the actual reason for the rejection.
            return {}
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

        try:
            request = ProviderInvocationRequest(
                backend=backend,
                model=model,
                messages=_provider_messages(state),
                run_id=str(state.metadata.get("run_id") or state.session_id),
            )
            run_id = request.run_id
        except Exception as exc:
            if isinstance(exc, Interrupt):
                raise
            return {
                "error": f"provider invocation failed: {exc}",
                "metadata": metadata,
            }

        def _record(outcome: str, *, decision_ref: str | None = None,
                    provider_ref: str | None = None,
                    policy_version: str | None = None,
                    reason: str | None = None) -> None:
            if outbound_ledger is None:
                return
            outbound_ledger.record(
                OutboundLedgerEntry(
                    run_id=run_id,
                    backend_name=backend.name,
                    model=model,
                    outcome=outcome,
                    decision_ref=decision_ref,
                    provider_ref=provider_ref,
                    policy_version=policy_version,
                    reason=reason,
                )
            )

        if invocation_timeout_seconds is not None and len(abandoned_tasks) >= max_abandoned_invocations:
            # Circuit breaker: refuse to start a NEW invocation while too
            # many prior ones remain abandoned (cancelled but not
            # confirmed finished). This bounds resource accumulation
            # regardless of whether the invoker ever cooperates with
            # cancellation or implements AbortableProviderInvoker below --
            # it does not need either to be SAFE, only to recover quickly
            # once abandoned tasks actually finish and clear themselves.
            _record("failed", reason="TooManyAbandonedInvocations")
            return {
                "error": (
                    f"refusing dispatch: {len(abandoned_tasks)} abandoned "
                    f"provider invocations have not yet released their "
                    f"resources"
                ),
                "metadata": {**metadata, "provider_outcome": "circuit_open"},
            }

        try:
            if invocation_timeout_seconds is not None:
                # Only wrapped in a real Task on the timeout path -- an
                # asyncio Task re-raises KeyboardInterrupt/SystemExit out of
                # its own step method into the event loop directly, bypassing
                # the normal await/.result() exception propagation a bare
                # `await coro` gives those same BaseException types. Wrapping
                # unconditionally would silently change that control-flow
                # semantics for every dispatch, not just the timed-out ones.
                invoke_task = asyncio.ensure_future(provider_invoker.invoke(request))
                done, pending = await asyncio.wait(
                    {invoke_task}, timeout=invocation_timeout_seconds
                )
                if invoke_task in pending:
                    # Deliberately NOT asyncio.wait_for: that primitive awaits
                    # the task's own cancellation to finish, so an invoker
                    # that catches CancelledError and keeps doing I/O extends
                    # the wait past invocation_timeout_seconds regardless.
                    # asyncio.wait already returned at the deadline; cancel
                    # and move on without waiting further -- the task may
                    # still be running, abandoned, but the dispatch settles.
                    #
                    # .cancel() only requests cooperative cancellation, which
                    # an invoker that catches CancelledError and keeps
                    # running (proven by test_dispatch_settles_on_deadline_
                    # even_when_invoker_suppresses_cancellation) does not
                    # honor. Two mitigations, neither requiring the other:
                    # (1) if the invoker also implements
                    # AbortableProviderInvoker, fire its abort() too -- an
                    # independent chance to force resource release (e.g.
                    # closing a transport) that does not depend on invoke()
                    # ever noticing cancellation; (2) track both the
                    # cancelled task and any abort() call in a bounded
                    # registry so repeated timeouts trip the circuit
                    # breaker above instead of accumulating without limit.
                    invoke_task.cancel()
                    _track_abandoned(invoke_task, abandoned_tasks)
                    if isinstance(provider_invoker, AbortableProviderInvoker):
                        abort_task = asyncio.ensure_future(provider_invoker.abort(request))
                        _track_abandoned(abort_task, abandoned_tasks)
                    _record("timeout", reason="invocation exceeded dispatch deadline")
                    return {
                        "error": (
                            f"provider invocation timed out after "
                            f"{invocation_timeout_seconds}s"
                        ),
                        "metadata": {**metadata, "provider_outcome": "timeout"},
                    }
                result = invoke_task.result()
            else:
                result = await provider_invoker.invoke(request)
            provider_ref = result.provider_ref
            decision_ref = result.decision_ref
            provider_content = result.content
            policy_version = getattr(result, "policy_version", None)
            # ProviderInvoker is a Protocol: a structurally-compatible but
            # non-ProviderInvocationResult object bypasses that dataclass's
            # own __post_init__ validation entirely. Validate the identity
            # references at this boundary too, not just provider_content.
            if not isinstance(provider_ref, str) or not provider_ref.strip():
                raise TypeError("provider_ref must be a non-empty string")
            if not isinstance(decision_ref, str) or not decision_ref.strip():
                raise TypeError("decision_ref must be a non-empty string")
            if not isinstance(provider_content, str):
                raise TypeError("provider content must be a string")
        except Exception as exc:
            if isinstance(exc, Interrupt):
                # MiniGraph owns its structural HITL protocol. Re-raise its
                # interrupt so the scheduler can emit the interrupted state.
                raise
            # asyncio.CancelledError/SystemExit/KeyboardInterrupt inherit from
            # BaseException and therefore retain their control-flow semantics.
            # Provider/runtime/data-shape failures become a normal graph delta.
            # The ledger records the exception *type name* only; str(exc) can
            # carry endpoint URLs or provider payloads and must not enter
            # audit records.
            _record("failed", reason=type(exc).__name__)
            return {
                "error": f"provider invocation failed: {exc}",
                "metadata": metadata,
            }

        _record(
            "success",
            decision_ref=decision_ref,
            provider_ref=provider_ref,
            policy_version=policy_version,
        )

        return {
            "metadata": {
                **metadata,
                "provider_ref": provider_ref,
                "decision_ref": decision_ref,
                "provider_content": provider_content,
                **({"provider_policy_version": policy_version} if policy_version else {}),
            }
        }

    async def respond_node(state: PerpetuaState) -> dict:
        """Append provider content or the Phase-2 dispatch compatibility response."""
        if state.error is not None:
            # MiniGraph can continue after an error delta. Do not append a
            # success-like compatibility response after a failed dispatch.
            return {}
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


def build_graph_spec() -> GraphSpec:
    """Describe the immutable topology of :func:`build_graph` without running it.

    The runtime graph deliberately keeps injected registry and provider seams out
    of this data-only contract. ``GraphSpec`` therefore records stable topology
    and provenance, not executable closures or endpoint data.
    """
    return GraphSpec.create(
        max_steps=3,
        nodes=(
            NodeSpec("route", metadata={"responsibility": "hardware-policy"}),
            NodeSpec("dispatch", metadata={"responsibility": "backend-selection"}),
            NodeSpec("respond", metadata={"responsibility": "response-formatting"}),
        ),
        edges=(
            EdgeSpec(source=START, kind="static", target="route"),
            EdgeSpec(source="route", kind="static", target="dispatch"),
            EdgeSpec(source="dispatch", kind="static", target="respond"),
            EdgeSpec(source="respond", kind="static", target=END),
        ),
        metadata={
            "runtime_builder": stable_callable_ref(build_graph),
            "runtime_engine": "perpetua_core.graph:MiniGraph",
        },
    )


graph = build_graph()
