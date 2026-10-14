"""Explicit, fenced takeover of a run whose process was lost.

Why this exists: only a running ``AdmissionGraphRunner`` writes a terminal receipt, and nothing in
production calls ``StepLedger.recover_accounting``. A process that dies mid-run (SIGKILL, power loss)
therefore leaves a run with held or started attempts and no terminal receipt, indistinguishable to a
reader from a run that is still going.

What it does: one operator-invoked, idempotent operation that

1. refuses unless the caller is the run's registered owner (the same rule as stopping a run),
2. returns an existing terminal receipt unchanged, so a finished run is never touched,
3. refuses a run that has no lease, so it can never fabricate one (``open_lease`` creates a lease
   for any id it is given),
4. takes the lease over, which fences the old holder even if it is merely slow,
5. lets accounting recovery classify holds (unstarted holds are released, started holds stay charged
   as unknown), and
6. records a terminal receipt with outcome ``unknown`` and reason ``run.process_lost``.

This is a FORCE takeover. It fences the current holder whether or not that process is actually dead, so a
slow-but-alive holder loses its lease and its later commits and terminal write fail. It is not proof of
process death, and it must be invoked by someone entitled to make that call.

What it deliberately does NOT do: it never invokes a node, callable or effect, never replays a start,
and is not a daemon or an automatic trigger. The outcome is always ``unknown``: the run never reached a
terminal state, so ``completed`` or ``interrupted`` would over-claim, even when no hold is unresolved.
"""

from __future__ import annotations

from orama.graph.execution_guard import LeaseFenced, StepLedger
from orama.graph.run_control import RunControl, TerminalReceipt

LOST_RUN_REASON = "run.process_lost"


class LostRunRefused(Exception):
    """Takeover was refused before any state changed; ``code`` names why."""

    def __init__(self, code: str, run_id: str) -> None:
        """Carry a stable machine-readable code and the run it concerned."""
        super().__init__(f"{code}: {run_id}")
        self.code = code
        self.run_id = run_id


def _require_text(value: object, name: str) -> str:
    """Return ``value`` when it is a non-blank string, else raise ValueError."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def recover_lost_run(
    *,
    ledger: StepLedger,
    run_control: RunControl,
    run_id: str,
    principal: str,
) -> TerminalReceipt:
    """Fence a lost run's old holder and record its conservative terminal receipt.

    ``ledger`` and ``run_control`` must resolve to the same SQLite store; this is checked before any
    state is read or changed. Safe to call repeatedly and from competing processes: exactly one terminal
    receipt is ever written, and every caller that returns normally returns that receipt. The takeover
    is a compare-and-set on the lease epoch, so concurrent recoverers cannot fence one another: a loser
    that finds no receipt yet gets ``LeaseFenced``, which is the documented retryable outcome.

    A retry after a recoverer died between steps advances the epoch once more. That is safe: each
    advance only fences a dead or obsolete recoverer, accounting recovery is idempotent per epoch and
    monotone (unstarted holds release, started holds stay unknown), and the terminal is written once.
    """
    _require_text(run_id, "run_id")
    _require_text(principal, "principal")
    if ledger.database_path != run_control.database_path:
        raise LostRunRefused("run.store_mismatch", run_id)
    owner = run_control.owner_principal(run_id)
    if owner is None:
        raise LostRunRefused("run.unknown", run_id)
    if owner != principal:
        raise LostRunRefused("run.not_owner", run_id)
    existing = run_control.terminal_receipt(run_id)
    if existing is not None:
        return existing
    lease = ledger.lease_snapshot(run_id)
    if lease is None:
        raise LostRunRefused("run.no_lease", run_id)
    current_epoch, max_steps = lease
    try:
        epoch = ledger.open_lease(run_id, max_steps=max_steps, expected_epoch=current_epoch)
        ledger.recover_accounting(run_id, epoch)
        return run_control.record_runtime_terminal(
            run_id=run_id, epoch=epoch, outcome="unknown", reason=LOST_RUN_REASON
        )
    except (LeaseFenced, ValueError):
        # Another recoverer, or the original holder finishing, may have written the terminal first.
        # Whatever raised, an existing terminal IS the run's canonical receipt, so return it; with no
        # terminal the error is real and propagates (a LeaseFenced loser may simply retry).
        winner = run_control.terminal_receipt(run_id)
        if winner is not None:
            return winner
        raise
