"""T1 invocation composition for the single Core scheduler.

This module owns the application-side transition from a trusted deployment
configuration to one invocation-specific :class:`AdmissionGate`.  It never
chooses an owner, invents a binding, or falls back to direct scheduling:
callers provide every authority-bearing input explicitly.  An unconfigured
deployment receives ``UnconfiguredGraphRunner``, which refuses before Core can
dispatch a node.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from functools import partial
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
from orama.graph.execution_guard import (
    CORE_GATE_AVAILABLE,
    AdmissionGate,
    DeliveryHealth,
    DurableStopRequested,
    NoDeliverySinks,
    StepLedger,
)
from orama.graph.run_control import RunControl, TerminalOutcome

if CORE_GATE_AVAILABLE:
    from perpetua_core.graph.gate import GateRefused
else:  # pre-T1 Core pin: keep the module importable so the API can refuse safely

    class GateRefused(Exception):  # type: ignore[no-redef]
        """Placeholder that is never raised when Core has no gate seam."""


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


def _observation_runner() -> Callable[..., Awaitable[object]]:
    """Resolve Core's plugin runner, refusing as an admission decision if it is absent.

    Resolved during preflight, before any owner or lease record exists. Importing it
    lazily after the lease would turn "this Core cannot drain observations" into an
    ``unknown`` runtime terminal for a run that never started, which is the wrong
    evidence. A Core pin without the plugin runner refuses here instead.
    """
    try:
        from perpetua_core.graph.plugins.observer import run_with_plugins
    except ImportError as error:
        raise AdmissionRefused("admission.delivery_core_unsupported") from error
    return run_with_plugins


async def _drain(
    graph: object,
    state: object,
    gate: object,
    delivery: object,
    *,
    runner: Callable[..., Awaitable[object]] | None,
) -> object:
    """Run one graph, draining Core's observations through ``delivery`` when it observes.

    Why: the admitted path used to call ``graph.ainvoke(state, gate=gate)``, so the
    gate saw delivery *health* but nothing ever fed Core's observation stream to the
    delivery. Bounded delivery existed but was not live in a normal run.

    How: Core already owns the delivery transport. ``run_with_plugins`` drains the
    canonical observation stream, hands the listener a detached copy (a listener
    cannot mutate the scheduler's live state), fails closed, and closes the iterator
    deterministically so cleanup failure is not lost. Reusing it keeps one seam
    instead of a second, weaker one on ``ainvoke``, and needs no Core release or pin
    bump: it is present at the production pin and at Core #12 and #13. ``runner`` is
    resolved in preflight by ``_observation_runner``; ``None`` means no sink observes
    and the plain gated ``ainvoke`` is used, exactly as before.
    """
    if runner is None:
        return await graph.ainvoke(state, gate=gate)  # type: ignore[attr-defined]
    return await runner(graph, state, delivery=delivery, gate=gate)


async def _quiesce(delivery: object, *, suppress: bool) -> None:
    """Shut an observing delivery down so its workers and callbacks are released.

    A per-run delivery owns background tasks (non-critical queue workers, in-flight
    callbacks, off-loop sink closes). Nothing else ever stops them, so without this
    each run would leak them and late authority could act after the terminal was
    recorded. Shutdown is idempotent, so the failure handlers call it again safely.
    On an error path ``suppress`` keeps a failing close from replacing the original
    failure; cancellation is never suppressed.
    """
    shutdown = getattr(delivery, "shutdown", None)
    if not callable(shutdown):
        return
    try:
        outcome = shutdown()
        if inspect.isawaitable(outcome):
            await outcome
    except Exception:  # noqa: BLE001 - see docstring; CancelledError still propagates
        if not suppress:
            raise


class DeliveryDrainIncomplete(RuntimeError):
    """A run finished but its delivery could not be shown to be fully drained.

    Shutdown can return normally with the circuit tripped: an off-loop callback is a
    thread and cannot be cancelled, so one that outlives the grace period is reported
    (``stop_timeout``) rather than raised. The run's own result is then uncertain
    delivery state and is recorded as ``unknown``, never ``completed``.
    """

    reason = "delivery.shutdown_incomplete"

    def __init__(self) -> None:
        """Carry the stable reason string as the message."""
        super().__init__(self.reason)


def _require_drained(delivery: object) -> None:
    """Refuse to call a run complete while its delivery reports itself unhealthy."""
    healthy = getattr(delivery, "healthy", None)
    if callable(healthy) and not healthy():
        raise DeliveryDrainIncomplete


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

    Delivery: ``run_delivery_factory(run_id)`` builds one delivery per run from the
    server-minted run id (``delivery_factory()`` takes no argument, so it cannot
    name the run; ``BoundedObserver`` refuses sinks without one). A delivery that
    has ``on_observation`` is drained through Core; one that also has
    ``bind_authority`` is bound to this run's ledger so a critical failure names
    only started, unsettled attempts. The default is still no sinks and a plain
    ``ainvoke``.
    """

    binding: ArtifactBinding
    providers: AdmissionProviders
    ledger: StepLedger
    run_control: RunControl
    context_from_state: Callable[[object], AdmissionContext]
    max_steps: int
    requirements: AdmissionRequirements
    clock: Clock
    delivery_factory: Callable[[], DeliveryHealth] = NoDeliverySinks
    run_delivery_factory: Callable[[str], DeliveryHealth] | None = None

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

        state = self._bind_run_identity(state, run_id)
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
            raise AdmissionRefused(
                f"admission.{decision.outcome}:{decision.reason_code}"
            )

        delivery = (
            self.run_delivery_factory(run_id)
            if self.run_delivery_factory is not None
            else self.delivery_factory()
        )
        # A delivery that observes must never be silently skipped: refuse before any
        # lease or owner record exists if this graph or Core cannot be drained.
        observing = callable(getattr(delivery, "on_observation", None))
        if observing and not callable(getattr(graph, "aobserve", None)):
            raise AdmissionRefused("admission.graph_observation_unsupported")
        runner = _observation_runner() if observing else None

        self._register_store_and_owner(run_id, principal_id)
        epoch = self.ledger.open_lease(run_id, max_steps=decision.max_steps)
        gate = AdmissionGate(
            decision=decision,
            binding=self.binding,
            providers=self.providers,
            ledger=self.ledger,
            run_id=run_id,
            lease_epoch=epoch,
            stop=self.run_control.durable_signal(run_id=run_id, principal=principal_id),
            clock=self.clock,
            delivery=delivery,
        )
        bind = getattr(delivery, "bind_authority", None)
        try:
            if observing and callable(bind):
                # Inside the guarded lifecycle: the owner and lease already exist, so a
                # refused binding must still reach a terminal receipt, not strand the run.
                # Identity comes from the ledger at trip time, bound to this run only.
                bind(
                    identity_source=partial(self.ledger.started_unsettled_attempts, run_id),
                    on_unknown=partial(self.ledger.mark_unknown, run_id),
                    stop_signal=gate.stop,
                )
            result = await _drain(graph, state, gate, delivery, runner=runner)
            if getattr(result, "status", None) == "done":
                # Inside the try so a stop or failure during trailing
                # settlement still reaches the terminal-receipt handlers.
                await gate.finish_run()
            if observing:
                await _quiesce(delivery, suppress=False)
                _require_drained(delivery)
        except DurableStopRequested as error:
            if observing:
                await _quiesce(delivery, suppress=True)
            self._record_terminal_after_boundary_failure(
                run_id=run_id,
                epoch=epoch,
                outcome="cancelled",
                reason=error.reason,
                cause=error,
            )
            raise AdmissionRefused("admission.stop_requested") from error
        except GateRefused as error:
            if observing:
                await _quiesce(delivery, suppress=True)
            stopped = error.decision.verdict == "stop"
            outcome = "cancelled" if stopped else "refused"
            self._record_terminal_after_boundary_failure(
                run_id=run_id,
                epoch=epoch,
                outcome=outcome,
                reason=error.decision.reason,
                cause=error,
            )
            code = (
                "admission.stop_requested" if stopped else "admission.boundary_refused"
            )
            raise AdmissionRefused(code) from error
        except BaseException as error:
            if observing:
                await _quiesce(delivery, suppress=True)
            outcome = (
                "interrupted" if type(error).__name__ == "CancelledError" else "unknown"
            )
            if outcome == "interrupted":
                reason = "run.interrupted"
            elif isinstance(error, DeliveryDrainIncomplete):
                reason = error.reason
            elif observing and not delivery.healthy():
                reason = "delivery.critical_failure"
            else:
                reason = "run.execution_error"
            try:
                self.run_control.record_runtime_terminal(
                    run_id=run_id, epoch=epoch, outcome=outcome, reason=reason
                )
            except BaseException as receipt_error:
                raise BaseExceptionGroup(
                    "graph execution and terminal evidence both failed",
                    [error, receipt_error],
                )
            raise
        status = getattr(result, "status", None)
        stop_reason = self.run_control.stop_for(run_id)
        outcome = {
            "done": "completed",
            "interrupted": "interrupted",
            "stopped": "cancelled",
        }.get(status, "unknown")
        reason = (
            stop_reason.reason
            if outcome == "cancelled" and stop_reason is not None
            else f"run.{outcome}"
        )
        self.run_control.record_runtime_terminal(
            run_id=run_id, epoch=epoch, outcome=outcome, reason=reason
        )
        return result

    @staticmethod
    def _bind_run_identity(state: object, run_id: str) -> object:
        """Overwrite any client-supplied run identity with the server-minted one.

        Admission, accounting and provider/outbound records must all describe
        the invocation under the same trusted ``run_id``.
        """
        metadata = getattr(state, "metadata", None)
        merge = getattr(state, "merge", None)
        if not isinstance(metadata, dict) or not callable(merge):
            raise AdmissionRefused("admission.state_identity_unbindable")
        return merge({"metadata": {**metadata, "run_id": run_id}})

    def _record_terminal_after_boundary_failure(
        self,
        *,
        run_id: str,
        epoch: int,
        outcome: TerminalOutcome,
        reason: str,
        cause: BaseException,
    ) -> None:
        """Persist a boundary stop/refusal without masking receipt-write failure."""
        try:
            self.run_control.record_runtime_terminal(
                run_id=run_id,
                epoch=epoch,
                outcome=outcome,
                reason=reason,
            )
        except BaseException as receipt_error:
            raise BaseExceptionGroup(
                "graph boundary and terminal evidence both failed",
                [cause, receipt_error],
            )

    def _register_store_and_owner(self, run_id: str, principal_id: str) -> None:
        """Require one SQLite authority and persist ownership before lease use."""
        if (
            not self.ledger.database_path
            or self.ledger.database_path != self.run_control.database_path
        ):
            raise AdmissionRefused("admission.run_control_store_mismatch")
        self.run_control.register_run(run_id=run_id, owner_principal=principal_id)


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
