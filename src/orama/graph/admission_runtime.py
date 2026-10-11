"""T1 invocation composition for the single Core scheduler.

This module owns the application-side transition from a trusted deployment
configuration to one invocation-specific :class:`AdmissionGate`.  It never
chooses an owner, invents a binding, or falls back to direct scheduling:
callers provide every authority-bearing input explicitly.  An unconfigured
deployment receives ``UnconfiguredGraphRunner``, which refuses before Core can
dispatch a node.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol, runtime_checkable
from uuid import uuid4

from orama.graph.admission import (
    AdmissionContext,
    AdmissionProviders,
    AdmissionRefused,
    AdmissionRequirements,
    ArtifactBinding,
    Clock,
    admit_artifact,
)
from orama.graph.execution_guard import AdmissionGate, DeliveryHealth, NoDeliverySinks, StepLedger, StopSignal


class GraphRunner(Protocol):
    """Application-owned invocation boundary used by every public graph caller."""

    async def invoke(self, graph: object, state: object) -> object:
        """Run one graph invocation or refuse it before scheduling."""


@runtime_checkable
class AuthenticatedGraphRunnerFactory(Protocol):
    """Bind a graph runner to verified transport authority for one request."""

    def for_authenticated_principal(self, principal_id: str) -> GraphRunner:
        """Return a runner that owns run identity and principal for one request."""


@runtime_checkable
class _GateCapableGraph(Protocol):
    """The narrow Core surface required by the admission runner."""

    async def ainvoke(self, state: object, *, gate: object) -> object:
        """Run through Core's existing scheduler with its neutral gate."""


@dataclass(frozen=True, slots=True)
class UnconfiguredGraphRunner:
    """Fail closed when trusted deployment admission configuration is absent."""

    async def invoke(self, graph: object, state: object) -> object:
        """Refuse before touching the supplied graph or state."""
        raise AdmissionRefused("admission.enforcement_unavailable")


@dataclass(slots=True)
class AdmissionGraphRunner:
    """Build and apply exactly one admission gate for each Core invocation.

    ``context_from_state`` may derive requested model/effect attributes, but a
    transport-bound runner always replaces its principal and run identity.
    Calling this factory directly refuses rather than accepting authority from
    request state.
    """

    binding: ArtifactBinding
    providers: AdmissionProviders
    ledger: StepLedger
    context_from_state: Callable[[object], AdmissionContext]
    max_steps: int
    requirements: AdmissionRequirements
    clock: Clock
    stop_factory: Callable[[], StopSignal] = StopSignal
    delivery_factory: Callable[[], DeliveryHealth] = NoDeliverySinks

    def for_authenticated_principal(self, principal_id: str) -> GraphRunner:
        """Bind one verified control-plane capability to future invocations."""
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise AdmissionRefused("admission.authenticated_principal_missing")
        return _BoundAdmissionGraphRunner(self, principal_id)

    async def invoke(self, graph: object, state: object) -> object:
        """Refuse unbound invocation so request state cannot self-authorize."""
        raise AdmissionRefused("admission.authenticated_context_required")

    async def _invoke_bound(
        self,
        graph: object,
        state: object,
        *,
        principal_id: str,
        run_id: str,
    ) -> object:
        """Admit, fence, and pass one transport-bound gate to Core."""
        if not isinstance(graph, _GateCapableGraph):
            raise AdmissionRefused("admission.graph_gate_unsupported")

        context = replace(
            self.context_from_state(state),
            run_id=run_id,
            principal_id=principal_id,
        )

        decision = admit_artifact(
            self.binding,
            context,
            self.providers,
            clock=self.clock,
            max_steps=self.max_steps,
            requirements=self.requirements,
        )
        if decision.outcome != "allow":
            raise AdmissionRefused(f"admission.{decision.outcome}:{decision.reason_code}")

        epoch = self.ledger.open_lease(run_id, max_steps=decision.max_steps)
        gate = AdmissionGate(
            decision=decision,
            binding=self.binding,
            providers=self.providers,
            ledger=self.ledger,
            run_id=run_id,
            lease_epoch=epoch,
            stop=self.stop_factory(),
            clock=self.clock,
            delivery=self.delivery_factory(),
        )
        return await graph.ainvoke(state, gate=gate)


@dataclass(frozen=True, slots=True)
class _BoundAdmissionGraphRunner:
    """One request-scoped admission runner with server-owned authority."""

    factory: AdmissionGraphRunner
    principal_id: str

    async def invoke(self, graph: object, state: object) -> object:
        """Mint a fresh opaque run identity before Core receives the gate."""
        return await self.factory._invoke_bound(
            graph,
            state,
            principal_id=self.principal_id,
            run_id=str(uuid4()),
        )
