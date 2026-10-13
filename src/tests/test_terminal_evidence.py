"""TDD: Durable Stop and Truthful Terminal Evidence (REV3 Task 5).

Required acceptance tests per HANDOFF-PLAN-T2-TO-M1-2026-10-11.md §6 Task 5:
- test_stop_persists_before_notification (already verified in test_run_control.py)
- test_restart_preserves_stop (already verified in test_run_control.py)
- test_stop_before_dispatch
- test_stop_between_result_and_commit
- test_partial_fanout_stop_preserves_charges
- test_uncooperative_task_remains_unknown
- test_terminal_receipt_taxonomy
- test_conflicting_terminal_retries_rejected
"""

from __future__ import annotations

import json
import os
import select
import subprocess
from collections.abc import Mapping
import sys
from pathlib import Path
from typing import Any

import pytest

from orama.graph.run_control import (
    RunControl,
    StopRequest,
    TerminalReceipt,
    TerminalOutcome,
)
from orama.graph.execution_guard import DurableStopRequested, LeaseFenced, StepLedger


_TERMINAL_WRITER = r"""
import json
import sys

from orama.graph.run_control import RunControl, TerminalReceipt

store_path = sys.argv[1]
payload = json.loads(sys.argv[2])
control = RunControl(store_path=store_path)
try:
    print(json.dumps({"state": "ready"}), flush=True)
    if sys.stdin.readline() != "go\n":
        raise RuntimeError("parent did not release terminal writer")
    receipt = TerminalReceipt(
        run_id=payload["run_id"],
        epoch=payload["epoch"],
        outcome=payload["outcome"],
        reason=payload["reason"],
        unresolved_attempts=tuple(payload["unresolved_attempts"]),
        schema_version=payload["schema_version"],
    )
    try:
        stored = control.record_terminal_receipt(receipt)
    except Exception as error:
        result = {
            "state": "error",
            "type": type(error).__name__,
            "message": str(error),
        }
    else:
        result = {
            "state": "ok",
            "receipt": {
                "epoch": stored.epoch,
                "outcome": stored.outcome,
                "reason": stored.reason,
                "unresolved_attempts": list(stored.unresolved_attempts),
                "schema_version": stored.schema_version,
            },
        }
    print(json.dumps(result, sort_keys=True), flush=True)
finally:
    control.close()
"""


def _receipt_payload(receipt: TerminalReceipt) -> str:
    """Serialize one receipt without requiring the child to import this test module."""
    return json.dumps(
        {
            "run_id": receipt.run_id,
            "epoch": receipt.epoch,
            "outcome": receipt.outcome,
            "reason": receipt.reason,
            "unresolved_attempts": list(receipt.unresolved_attempts),
            "schema_version": receipt.schema_version,
        },
        sort_keys=True,
    )


def _read_child_message(
    process: subprocess.Popen[str], timeout: float = 10
) -> dict[str, Any]:
    """Read one JSON line without permitting an unbounded child wait."""
    assert process.stdout is not None
    readable, _, _ = select.select([process.stdout], [], [], timeout)
    if not readable:
        raise AssertionError("terminal writer timed out")
    line = process.stdout.readline()
    if not line:
        stderr = ""
        if process.poll() is not None and process.stderr is not None:
            stderr = process.stderr.read()
        raise AssertionError(f"terminal writer exited before its message: {stderr}")
    message = json.loads(line)
    assert isinstance(message, dict)
    return message


_SOURCE_ROOT = Path(__file__).resolve().parents[1]


def _child_launch(
    isolated_import_ok: bool,
    base_env: Mapping[str, str],
    *,
    source_root: Path = _SOURCE_ROOT,
) -> tuple[dict[str, str], list[str]]:
    """Return the environment and interpreter flags for a cross-process writer.

    These tests prove behaviour of the *installed* package across real processes,
    so the preferred child is isolated (``-I``) with no ambient ``PYTHONPATH``.
    When the package is not installed (a source checkout), the child cannot use
    ``-I`` (it ignores ``PYTHONPATH``) and must be told where ``orama`` lives.
    The earlier fallback dropped ``PYTHONPATH`` and never added the source root,
    so it failed exactly in the case it existed for, and CI (which always
    installs the package) never took that branch to notice. The source root goes
    first and the caller's own paths, such as a specific Core revision, follow.
    """
    env = dict(base_env)
    if isolated_import_ok:
        env.pop("PYTHONPATH", None)
        return env, ["-I"]
    inherited = [entry for entry in env.get("PYTHONPATH", "").split(os.pathsep) if entry]
    env["PYTHONPATH"] = os.pathsep.join([str(source_root), *inherited])
    return env, []


def _race_terminal_receipts(
    store_path: Path,
    receipts: tuple[TerminalReceipt, ...],
) -> list[tuple[Any, ...]]:
    """Race isolated installed-package writers through a bounded JSON handshake."""
    initializer = RunControl(store_path=store_path)
    initializer.close()
    probe_env, _ = _child_launch(True, os.environ)
    isolated_probe = subprocess.run(
        [sys.executable, "-I", "-c", "import orama.graph.run_control"],
        cwd=store_path.parent,
        env=probe_env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    env, isolation_flag = _child_launch(isolated_probe.returncode == 0, os.environ)
    processes: list[subprocess.Popen[str]] = []
    try:
        for receipt in receipts:
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        *isolation_flag,
                        "-c",
                        _TERMINAL_WRITER,
                        str(store_path),
                        _receipt_payload(receipt),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    cwd=store_path.parent,
                    env=env,
                )
            )
        for process in processes:
            assert _read_child_message(process) == {"state": "ready"}
        for process in processes:
            assert process.stdin is not None
            process.stdin.write("go\n")
            process.stdin.flush()

        messages = [_read_child_message(process) for process in processes]
        recorded = []
        for message in messages:
            if message["state"] == "ok":
                stored = message["receipt"]
                recorded.append(
                    (
                        "ok",
                        stored["epoch"],
                        stored["outcome"],
                        stored["reason"],
                        tuple(stored["unresolved_attempts"]),
                        stored["schema_version"],
                    )
                )
            else:
                recorded.append(("error", message["type"], message["message"]))
        for process in processes:
            assert process.wait(timeout=10) == 0
        return recorded
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def test_terminal_receipt_taxonomy() -> None:
    """TerminalReceipt strictly enforces schema version 1 and valid outcomes."""
    valid_outcomes: list[TerminalOutcome] = [
        "completed",
        "interrupted",
        "cancelled",
        "refused",
        "budget",
        "unknown",
    ]
    for outcome in valid_outcomes:
        receipt = TerminalReceipt(
            run_id="run-1",
            epoch=1,
            outcome=outcome,
            reason="test.outcome",
        )
        assert receipt.outcome == outcome
        assert receipt.schema_version == 2

    with pytest.raises(ValueError, match="outcome"):
        TerminalReceipt(
            run_id="run-1",
            epoch=1,
            outcome="invalid_outcome",  # type: ignore[arg-type]
            reason="test",
        )


@pytest.mark.parametrize("epoch", [True, False, 1.0, 0, -1])
def test_terminal_receipt_rejects_invalid_epoch(epoch: object) -> None:
    """Epoch is a strict positive integer, never a boolean or float."""
    with pytest.raises(ValueError, match="epoch"):
        TerminalReceipt(
            run_id="run-1",
            epoch=epoch,  # type: ignore[arg-type]
            outcome="completed",
            reason="success",
        )


@pytest.mark.parametrize("schema_version", [True, False, 1.0, 0, 3])
def test_terminal_receipt_rejects_invalid_schema_version(
    schema_version: object,
) -> None:
    """Schema version is the strict integer value two."""
    with pytest.raises(ValueError, match="schema_version"):
        TerminalReceipt(
            run_id="run-1",
            epoch=1,
            outcome="completed",
            reason="success",
            schema_version=schema_version,  # type: ignore[arg-type]
        )


def test_terminal_receipt_preserves_legacy_schema_one_rows(tmp_path: Path) -> None:
    """Schema-v1 records remain readable without inventing v2 evidence."""
    import sqlite3

    store_path = tmp_path / "legacy.sqlite3"
    db = sqlite3.connect(store_path)
    db.execute(
        "CREATE TABLE terminal_receipts ("
        "run_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, outcome TEXT NOT NULL, "
        "reason TEXT NOT NULL, unresolved_attempts TEXT NOT NULL, schema_version INTEGER NOT NULL)"
    )
    db.execute(
        "INSERT INTO terminal_receipts VALUES (?, ?, ?, ?, ?, ?)",
        ("old-run", 1, "completed", "legacy.success", "[]", 1),
    )
    db.commit()
    db.close()
    os.chmod(store_path, 0o600)

    control = RunControl(store_path=store_path)
    receipt = control.terminal_receipt("old-run")
    assert receipt == TerminalReceipt(
        run_id="old-run",
        epoch=1,
        outcome="completed",
        reason="legacy.success",
        schema_version=1,
    )
    control.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [("run_id", ""), ("run_id", "   "), ("reason", ""), ("reason", "\t")],
)
def test_terminal_receipt_rejects_blank_strings(field: str, value: str) -> None:
    """Identity and reason strings must contain non-whitespace content."""
    values = {
        "run_id": "run-1",
        "epoch": 1,
        "outcome": "completed",
        "reason": "success",
    }
    values[field] = value
    with pytest.raises(ValueError, match=field):
        TerminalReceipt(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "unresolved_attempts",
    [
        ["attempt-1"],
        ("",),
        ("   ",),
        (1,),
        ("attempt-1", "attempt-1"),
    ],
)
def test_terminal_receipt_rejects_invalid_unresolved_attempts(
    unresolved_attempts: object,
) -> None:
    """Unresolved references are an immutable tuple of unique non-empty strings."""
    with pytest.raises(ValueError, match="unresolved_attempts"):
        TerminalReceipt(
            run_id="run-1",
            epoch=1,
            outcome="unknown",
            reason="execution_unresolved",
            unresolved_attempts=unresolved_attempts,  # type: ignore[arg-type]
        )


def test_unresolved_attempts_require_unknown_outcome() -> None:
    """Only an unknown terminal state may carry unresolved attempt references."""
    with pytest.raises(ValueError, match="unknown outcome"):
        TerminalReceipt(
            run_id="run-1",
            epoch=1,
            outcome="cancelled",
            reason="cancelled",
            unresolved_attempts=("attempt-1",),
        )


def test_conflicting_terminal_retries_rejected(tmp_path: Path) -> None:
    """A run with a recorded terminal receipt rejects conflicting terminal states."""
    control = RunControl(store_path=tmp_path / "stop.sqlite3")
    control.register_run(run_id="run-term", owner_principal="owner")

    first = TerminalReceipt(
        run_id="run-term",
        epoch=1,
        outcome="completed",
        reason="success",
    )
    control.record_terminal_receipt(first)

    # Identical retry is idempotent
    assert control.record_terminal_receipt(first) == first

    # Conflicting retry raises ValueError
    conflicting = TerminalReceipt(
        run_id="run-term",
        epoch=1,
        outcome="cancelled",
        reason="conflicting",
    )
    with pytest.raises(ValueError, match="conflicting terminal receipt"):
        control.record_terminal_receipt(conflicting)

    assert control.record_terminal_receipt(first) == first
    other = TerminalReceipt(
        run_id="run-other",
        epoch=1,
        outcome="completed",
        reason="success",
    )
    assert control.record_terminal_receipt(other) == other


def test_runtime_terminal_retry_is_idempotent_but_rejects_conflicts(
    tmp_path: Path,
) -> None:
    """The runtime path returns its first receipt and rejects a contradictory retry."""
    store_path = tmp_path / "shared.sqlite3"
    control = RunControl(store_path=store_path)
    ledger = StepLedger(store_path)
    control.register_run(run_id="runtime-retry", owner_principal="owner")
    epoch = ledger.open_lease("runtime-retry", max_steps=1)

    first = control.record_runtime_terminal(
        run_id="runtime-retry", epoch=epoch, outcome="completed", reason="run.done"
    )
    assert control.record_runtime_terminal(
        run_id="runtime-retry", epoch=epoch, outcome="completed", reason="run.done"
    ) == first
    with pytest.raises(ValueError, match="conflicting runtime terminal retry"):
        control.record_runtime_terminal(
            run_id="runtime-retry", epoch=epoch, outcome="cancelled", reason="operator.stop"
        )
    ledger.close()
    control.close()


def test_identical_terminal_receipts_are_idempotent_across_processes(
    tmp_path: Path,
) -> None:
    """Concurrent identical writers all observe the same canonical receipt."""
    store_path = tmp_path / "stop.sqlite3"
    receipt = TerminalReceipt(
        run_id="run-identical-race",
        epoch=3,
        outcome="unknown",
        reason="settlement_unresolved",
        unresolved_attempts=("attempt-1",),
    )

    results = _race_terminal_receipts(store_path, (receipt, receipt, receipt, receipt))

    assert (
        results
        == [("ok", 3, "unknown", "settlement_unresolved", ("attempt-1",), 2)] * 4
    )
    reopened = RunControl(store_path=store_path)
    assert reopened.record_terminal_receipt(receipt) == receipt
    reopened.close()


def test_conflicting_terminal_receipts_have_one_canonical_winner_across_processes(
    tmp_path: Path,
) -> None:
    """Concurrent changed payloads produce one winner and one canonical conflict."""
    store_path = tmp_path / "stop.sqlite3"
    completed = TerminalReceipt(
        run_id="run-conflict-race",
        epoch=4,
        outcome="completed",
        reason="success",
    )
    unknown = TerminalReceipt(
        run_id="run-conflict-race",
        epoch=4,
        outcome="unknown",
        reason="settlement_unresolved",
        unresolved_attempts=("attempt-2",),
    )

    results = _race_terminal_receipts(store_path, (completed, unknown))

    successes = [result for result in results if result[0] == "ok"]
    failures = [result for result in results if result[0] == "error"]
    assert len(successes) == 1
    assert failures == [
        (
            "error",
            "ValueError",
            "conflicting terminal receipt for run run-conflict-race",
        )
    ]

    winner = completed if successes[0][2] == "completed" else unknown
    loser = unknown if winner is completed else completed
    reopened = RunControl(store_path=store_path)
    assert reopened.record_terminal_receipt(winner) == winner
    with pytest.raises(ValueError, match="conflicting terminal receipt"):
        reopened.record_terminal_receipt(loser)
    reopened.close()


def test_uncooperative_task_remains_unknown(tmp_path: Path) -> None:
    """An unresolved started attempt is never represented as clean cancellation."""
    store_path = tmp_path / "shared.sqlite3"
    control = RunControl(store_path=store_path)
    ledger = StepLedger(store_path)
    control.register_run(run_id="run-uncoop", owner_principal="owner")
    epoch = ledger.open_lease("run-uncoop", max_steps=2)
    ledger.reserve_attempt(
        "run-uncoop", epoch, "attempt-1", units=1, requires_start_marker=True
    )
    ledger.mark_started("run-uncoop", "attempt-1", epoch)

    receipt = control.record_runtime_terminal(
        run_id="run-uncoop",
        epoch=epoch,
        outcome="interrupted",
        reason="operator.cancel",
    )
    assert receipt.outcome == "unknown"
    assert receipt.reason == "operator.cancel"
    assert receipt.unresolved_attempts == ("attempt-1",)
    assert receipt.charge_summary == (
        ("steps", 1),
        ("elapsed_ms", 0),
        ("cost_microunits", 0),
        ("effect_attempts", 0),
    )
    assert control.record_runtime_terminal(
        run_id="run-uncoop", epoch=epoch, outcome="completed", reason="operator.cancel"
    ) == receipt
    ledger.close()
    control.close()


def test_terminal_receipt_fences_late_ledger_mutations(tmp_path: Path) -> None:
    """A terminal receipt closes the run against stale gates and lease takeovers."""
    store_path = tmp_path / "shared.sqlite3"
    control = RunControl(store_path=store_path)
    ledger = StepLedger(store_path)
    run_id = "run-terminal-fence"
    control.register_run(run_id=run_id, owner_principal="owner")
    epoch = ledger.open_lease(run_id, max_steps=2)
    ledger.reserve_attempt(run_id, epoch, "attempt-1", units=1)

    control.record_runtime_terminal(
        run_id=run_id,
        epoch=epoch,
        outcome="completed",
        reason="run.completed",
    )

    with pytest.raises(LeaseFenced):
        ledger.open_lease(run_id, max_steps=2)
    with pytest.raises(LeaseFenced):
        ledger.reserve_attempt(run_id, epoch, "attempt-2", units=1)
    with pytest.raises(LeaseFenced):
        ledger.prepare_commit(run_id, "attempt-1", "hold", epoch, "digest")
    with pytest.raises(LeaseFenced):
        ledger.check(run_id, epoch)

    assert ledger.used(run_id) == 1
    assert ledger.hold_state(run_id, "attempt-2") is None
    ledger.close()
    control.close()


def test_stop_before_dispatch_preserves_unsettled_fanout_charges(
    tmp_path: Path,
) -> None:
    """A durable stop fences commit while preserving every reserved fan-out hold."""
    store_path = tmp_path / "shared.sqlite3"
    control = RunControl(store_path=store_path)
    ledger = StepLedger(store_path)
    run_id = "run-predispatch"
    control.register_run(run_id=run_id, owner_principal="owner")
    epoch = ledger.open_lease(run_id, max_steps=3)
    ledger.reserve_batch(
        run_id,
        epoch,
        "batch-1",
        (("batch-1:a", 1), ("batch-1:b", 1)),
        requires_start_marker=True,
    )
    control.request_stop(
        StopRequest(run_id=run_id, principal="owner", reason="operator_cancel")
    )

    with pytest.raises(DurableStopRequested, match="operator_cancel"):
        ledger.mark_started(run_id, "batch-1:a", epoch)
    with pytest.raises(DurableStopRequested, match="operator_cancel"):
        ledger.prepare_batch_commit(
            run_id, "batch-1", ("batch-1:a", "batch-1:b"), epoch, "digest"
        )

    assert ledger.batch_hold_states(run_id, "batch-1") == {
        "batch-1:a": "held",
        "batch-1:b": "held",
    }
    receipt = control.record_runtime_terminal(
        run_id=run_id, epoch=epoch, outcome="cancelled", reason="operator_cancel"
    )
    assert receipt.outcome == "unknown"
    assert receipt.unresolved_attempts == ("batch-1:a", "batch-1:b")
    assert ledger.used(run_id) == 2
    ledger.close()
    control.close()


def test_stop_wins_commit_race_and_runtime_receipt_is_conservative(
    tmp_path: Path,
) -> None:
    """A stop that commits first prevents a later intent and retains its hold."""
    store_path = tmp_path / "shared.sqlite3"
    control = RunControl(store_path=store_path)
    ledger = StepLedger(store_path)
    run_id = "run-commit-race"
    control.register_run(run_id=run_id, owner_principal="owner")
    epoch = ledger.open_lease(run_id, max_steps=2)
    hold = ledger.reserve_attempt(
        run_id, epoch, "attempt-1", units=1, requires_start_marker=True
    )
    ledger.mark_started(run_id, "attempt-1", epoch)
    ledger.record_outcome(run_id, "attempt-1", epoch, "result-digest")
    control.request_stop(
        StopRequest(run_id=run_id, principal="owner", reason="stop.race")
    )

    with pytest.raises(DurableStopRequested, match="stop.race"):
        ledger.prepare_commit(run_id, "attempt-1", hold.hold_id, epoch, "result-digest")

    receipt = control.record_runtime_terminal(
        run_id=run_id, epoch=epoch, outcome="cancelled", reason="stop.race"
    )
    assert receipt.outcome == "unknown"
    assert receipt.unresolved_attempts == ("attempt-1",)
    assert ledger.hold_state(run_id, "attempt-1") == "held"
    ledger.close()
    control.close()


def test_installed_package_children_run_isolated_without_ambient_paths() -> None:
    """With the package installed, children use it alone: no PYTHONPATH, -I isolation."""
    env, flags = _child_launch(True, {"PYTHONPATH": "/somewhere", "KEEP": "1"})

    assert flags == ["-I"]
    assert "PYTHONPATH" not in env
    assert env["KEEP"] == "1"


def test_source_checkout_children_get_the_source_tree_and_the_callers_paths() -> None:
    """Without an installed package the child must still be able to import ``orama``.

    ``-I`` would ignore PYTHONPATH, so it is not used here. The checkout's source
    root comes first, and any path the caller deliberately set (for example a
    specific Core revision) is preserved behind it rather than dropped.
    """
    root = Path("/repo/src")
    env, flags = _child_launch(False, {"PYTHONPATH": "/core/src"}, source_root=root)

    assert flags == []
    assert env["PYTHONPATH"].split(os.pathsep) == ["/repo/src", "/core/src"]


def test_source_checkout_children_work_when_no_pythonpath_was_set() -> None:
    """An empty or absent PYTHONPATH yields exactly the source root, no blank entry."""
    env, _ = _child_launch(False, {}, source_root=Path("/repo/src"))

    assert env["PYTHONPATH"] == "/repo/src"
