"""T1 invocation composition for the single Core scheduler.

This module owns the application-side transition from a trusted deployment
configuration to one invocation-specific :class:`AdmissionGate`.  It never
chooses an owner, invents a binding, or falls back to direct scheduling:
callers provide every authority-bearing input explicitly.  An unconfigured
deployment receives ``UnconfiguredGraphRunner``, which refuses before Core can
dispatch a node.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

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


def _state_run_id(state: object) -> str:
    """Extract the already-established run identity without accepting a new one."""
    metadata = getattr(state, "metadata", None)
    run_id = metadata.get("run_id") if isinstance(metadata, Mapping) else None
    if run_id is None:
        run_id = getattr(state, "session_id", None)
    if not isinstance(run_id, str) or not run_id.strip():
        raise AdmissionRefused("admission.run_id_missing")
    return run_id


@dataclass(slots=True)
class AdmissionGraphRunner:
    """Build and apply exactly one admission gate for each Core invocation.

    ``context_from_state`` is a trusted application boundary.  It must derive
    the authenticated principal and declared effects from already-authenticated
    request/lifecycle state; request payloads do not construct it directly.
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

    async def invoke(self, graph: object, state: object) -> object:
        """Admit, fence, and pass one gate to Core's existing scheduler."""
        if not isinstance(graph, _GateCapableGraph):
            raise AdmissionRefused("admission.graph_gate_unsupported")

        run_id = _state_run_id(state)
        context = self.context_from_state(state)
        if context.run_id != run_id:
            raise AdmissionRefused("admission.run_id_mismatch")

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
