"""Deterministic process-crash coverage for durable accounting recovery."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "crash-recovery-run"
ATTEMPT_ID = "crash-attempt"
LEGACY_ATTEMPT_ID = "legacy-uncertain"
RESULT_DIGEST = "result-digest"

CRASH_SCRIPT = textwrap.dedent(
    f"""
    import signal
    import sys

    from orama.graph.accounting_types import ChargeUnits
    from orama.graph.execution_guard import StepLedger

    database, phase = sys.argv[1:]
    run_id = {RUN_ID!r}
    attempt_id = {ATTEMPT_ID!r}
    limits = ChargeUnits(
        steps=10,
        elapsed_ms=1000,
        cost_microunits=10000,
        effect_attempts=10,
        cost_basis="test-unit",
    )
    charge = ChargeUnits(
        steps=2,
        elapsed_ms=20,
        cost_microunits=200,
        effect_attempts=1,
        cost_basis="test-unit",
    )

    def checkpoint(name):
        print(name, flush=True)
        signal.pause()

    ledger = StepLedger(database)
    epoch = ledger.open_lease(run_id, max_steps=limits.steps)
    with ledger._tx() as database_handle:
        database_handle.execute(
            "INSERT INTO attempt_holds "
            "(run_id, attempt_id, hold_id, epoch, units, state) "
            "VALUES (?, ?, ?, ?, ?, 'held')",
            (
                run_id,
                {LEGACY_ATTEMPT_ID!r},
                "hold:pre-migration-legacy-uncertain",
                epoch,
                1,
            ),
        )
        database_handle.execute(
            "UPDATE leases SET used = used + 1 WHERE run_id = ?",
            (run_id,),
        )
    ledger.configure_limits(run_id, epoch, limits)

    if phase == "before-reserve":
        checkpoint(phase)
    else:
        hold = ledger.reserve_charge(run_id, epoch, attempt_id, charge)
        if phase == "after-hold-before-start":
            checkpoint(phase)
        else:
            ledger.mark_started(run_id, attempt_id, epoch)
            if phase == "after-start-before-outcome":
                checkpoint(phase)
            else:
                ledger.record_outcome(
                    run_id, attempt_id, epoch, {RESULT_DIGEST!r}
                )
                if phase == "after-outcome-before-intent":
                    checkpoint(phase)
                else:
                    ledger.prepare_commit(
                        run_id,
                        attempt_id,
                        hold.hold_id,
                        epoch,
                        {RESULT_DIGEST!r},
                    )
                    if phase == "after-intent-before-settlement":
                        checkpoint(phase)
                    else:
                        raise AssertionError(f"unknown phase: {{phase}}")
    """
)

RECOVER_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys

    from orama.graph.execution_guard import StepLedger

    database = sys.argv[1]
    run_id = {RUN_ID!r}
    ledger = StepLedger(database)
    epoch = ledger.open_lease(run_id, max_steps=10)
    recovery = ledger.recover_accounting(run_id, epoch)
    has_intent = ledger._db.execute(
        "SELECT 1 FROM commit_intents WHERE run_id = ? AND attempt_id = ?",
        (run_id, {ATTEMPT_ID!r}),
    ).fetchone() is not None
    print(json.dumps({{
        "epoch": epoch,
        "released": list(recovery.released),
        "unknown": list(recovery.unknown),
        "preserved_unknown": list(recovery.preserved_unknown),
        "crash_state": ledger.hold_state(run_id, {ATTEMPT_ID!r}),
        "legacy_state": ledger.hold_state(run_id, {LEGACY_ATTEMPT_ID!r}),
        "usage": ledger.usage(run_id).to_dict(),
        "events": [event.event_type for event in ledger.events(run_id)],
        "has_intent": has_intent,
    }}, sort_keys=True), flush=True)
    """
)


def _subprocess_env() -> dict[str, str]:
    """Import this worktree's sources in every fresh interpreter."""
    env = os.environ.copy()
    current = env.get("PYTHONPATH")
    paths = [str(ROOT / "src")]
    if current:
        paths.append(current)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def _crash_at_marker(database: Path, phase: str) -> None:
    """Kill the writer immediately after its flushed durable phase marker."""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", CRASH_SCRIPT, str(database), phase],
        cwd=ROOT,
        env=_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        if process.poll() is None:
            os.kill(process.pid, signal.SIGKILL)
        _, stderr = process.communicate(timeout=5)
        pytest.fail(
            f"crash worker timed out before {phase!r}; "
            f"returncode={process.returncode}, stderr={stderr!r}"
        )
    marker = process.stdout.readline().strip()
    if marker != phase:
        if process.poll() is None:
            os.kill(process.pid, signal.SIGKILL)
        _, stderr = process.communicate(timeout=5)
        pytest.fail(
            f"crash worker did not reach {phase!r}; "
            f"marker={marker!r}, returncode={process.returncode}, stderr={stderr!r}"
        )

    os.kill(process.pid, signal.SIGKILL)
    _, stderr = process.communicate(timeout=5)
    assert process.returncode == -signal.SIGKILL, stderr


def _recover_in_fresh_process(database: Path) -> dict[str, object]:
    """Take over the lease, recover, and inspect without replaying any work."""
    completed = subprocess.run(
        [sys.executable, "-u", "-c", RECOVER_SCRIPT, str(database)],
        cwd=ROOT,
        env=_subprocess_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.mark.parametrize(
    (
        "phase",
        "released",
        "unknown",
        "crash_state",
        "usage",
        "events",
        "has_intent",
    ),
    [
        (
            "before-reserve",
            [],
            [LEGACY_ATTEMPT_ID],
            None,
            (1, 0, 0, 0),
            ["limits_configured", "accounting_recovered"],
            False,
        ),
        (
            "after-hold-before-start",
            [ATTEMPT_ID],
            [LEGACY_ATTEMPT_ID],
            "released",
            (1, 0, 0, 0),
            [
                "limits_configured",
                "reservation_tracked",
                "accounting_recovered",
            ],
            False,
        ),
        (
            "after-start-before-outcome",
            [],
            [ATTEMPT_ID, LEGACY_ATTEMPT_ID],
            "unknown",
            (3, 20, 200, 1),
            [
                "limits_configured",
                "reservation_tracked",
                "attempt_started",
                "accounting_recovered",
            ],
            False,
        ),
        (
            "after-outcome-before-intent",
            [],
            [ATTEMPT_ID, LEGACY_ATTEMPT_ID],
            "unknown",
            (3, 20, 200, 1),
            [
                "limits_configured",
                "reservation_tracked",
                "attempt_started",
                "outcome_recorded",
                "accounting_recovered",
            ],
            False,
        ),
        (
            "after-intent-before-settlement",
            [],
            [ATTEMPT_ID, LEGACY_ATTEMPT_ID],
            "unknown",
            (3, 20, 200, 1),
            [
                "limits_configured",
                "reservation_tracked",
                "attempt_started",
                "outcome_recorded",
                "accounting_recovered",
            ],
            True,
        ),
    ],
)
def test_sigkill_recovery_is_conservative_without_replay(
    tmp_path: Path,
    phase: str,
    released: list[str],
    unknown: list[str],
    crash_state: str | None,
    usage: tuple[int, int, int, int],
    events: list[str],
    has_intent: bool,
) -> None:
    """A fresh holder recovers each crash window from durable evidence alone."""
    database = tmp_path / "ledger.sqlite3"
    assert "perpetua_core.graph" not in CRASH_SCRIPT
    assert "perpetua_core.graph" not in RECOVER_SCRIPT
    assert "MiniGraph" not in CRASH_SCRIPT + RECOVER_SCRIPT

    _crash_at_marker(database, phase)
    recovered = _recover_in_fresh_process(database)

    assert recovered["epoch"] == 2
    assert recovered["released"] == released
    assert recovered["unknown"] == unknown
    assert recovered["preserved_unknown"] == []
    assert recovered["crash_state"] == crash_state
    assert recovered["legacy_state"] == "unknown"
    assert recovered["events"] == events
    assert recovered["has_intent"] is has_intent
    assert recovered["usage"] == {
        "steps": usage[0],
        "elapsed_ms": usage[1],
        "cost_microunits": usage[2],
        "effect_attempts": usage[3],
        "cost_basis": "test-unit",
    }
