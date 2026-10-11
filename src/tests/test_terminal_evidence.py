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

import multiprocessing as mp
from pathlib import Path
from typing import Any

import pytest

from orama.graph.run_control import (
    RunControl,
    StopRequest,
    TerminalReceipt,
    TerminalOutcome,
)


def _record_terminal_receipt(
    store_path: str,
    receipt: TerminalReceipt,
    ready: Any,
    start: Any,
    results: Any,
) -> None:
    """Record one receipt through an independent connection after a bounded rendezvous."""
    control = RunControl(store_path=store_path)
    ready.put("ready")
    if not start.wait(timeout=10):
        results.put(("handshake_timeout",))
        control.close()
        return
    try:
        stored = control.record_terminal_receipt(receipt)
        results.put(
            (
                "ok",
                stored.epoch,
                stored.outcome,
                stored.reason,
                stored.unresolved_attempts,
                stored.schema_version,
            )
        )
    except Exception as error:  # noqa: BLE001 - child reports the exact public failure
        results.put(("error", type(error).__name__, str(error)))
    finally:
        control.close()


def _race_terminal_receipts(
    store_path: Path,
    receipts: tuple[TerminalReceipt, ...],
) -> list[tuple[Any, ...]]:
    """Release independent writers together and return their bounded results."""
    initializer = RunControl(store_path=store_path)
    initializer.close()
    context = mp.get_context("spawn")
    ready = context.Queue()
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_record_terminal_receipt,
            args=(str(store_path), receipt, ready, start, results),
        )
        for receipt in receipts
    ]
    for process in processes:
        process.start()
    try:
        for _ in processes:
            assert ready.get(timeout=10) == "ready"
        start.set()
        recorded = [results.get(timeout=10) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert not process.is_alive()
            assert process.exitcode == 0
        return recorded
    finally:
        start.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
        ready.close()
        results.close()


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
        assert receipt.schema_version == 1

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


@pytest.mark.parametrize("schema_version", [True, False, 1.0, 0, 2])
def test_terminal_receipt_rejects_invalid_schema_version(schema_version: object) -> None:
    """Schema version is the strict integer value one."""
    with pytest.raises(ValueError, match="schema_version"):
        TerminalReceipt(
            run_id="run-1",
            epoch=1,
            outcome="completed",
            reason="success",
            schema_version=schema_version,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("run_id", ""), ("run_id", "   "), ("reason", ""), ("reason", "\t")],
)
def test_terminal_receipt_rejects_blank_strings(field: str, value: str) -> None:
    """Identity and reason strings must contain non-whitespace content."""
    values = {"run_id": "run-1", "epoch": 1, "outcome": "completed", "reason": "success"}
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


def test_identical_terminal_receipts_are_idempotent_across_processes(tmp_path: Path) -> None:
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

    assert results == [
        ("ok", 3, "unknown", "settlement_unresolved", ("attempt-1",), 1)
    ] * 4
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
        ("error", "ValueError", "conflicting terminal receipt for run run-conflict-race")
    ]

    winner = completed if successes[0][2] == "completed" else unknown
    loser = unknown if winner is completed else completed
    reopened = RunControl(store_path=store_path)
    assert reopened.record_terminal_receipt(winner) == winner
    with pytest.raises(ValueError, match="conflicting terminal receipt"):
        reopened.record_terminal_receipt(loser)
    reopened.close()


def test_uncooperative_task_remains_unknown(tmp_path: Path) -> None:
    """An uncooperative or cancelled task without proof of termination is classified as unknown."""
    control = RunControl(store_path=tmp_path / "stop.sqlite3")
    control.register_run(run_id="run-uncoop", owner_principal="owner")

    receipt = control.classify_termination(
        run_id="run-uncoop",
        epoch=1,
        confirmed_cancelled=False,
        requested_stop_reason="operator.cancel",
    )
    assert receipt.outcome == "unknown"
    assert receipt.reason == "operator.cancel"


def test_stop_before_dispatch(tmp_path: Path) -> None:
    """If stop was requested before dispatch, gate decision blocks execution with refused or cancelled."""
    control = RunControl(store_path=tmp_path / "stop.sqlite3")
    control.register_run(run_id="run-predispatch", owner_principal="owner")
    control.request_stop(StopRequest(run_id="run-predispatch", principal="owner", reason="operator_cancel"))

    assert control.is_stopped("run-predispatch") is True
    receipt = control.classify_termination(
        run_id="run-predispatch",
        epoch=1,
        confirmed_cancelled=True,
        requested_stop_reason="operator_cancel",
    )
    assert receipt.outcome == "cancelled"


def test_stop_between_result_and_commit(tmp_path: Path) -> None:
    """Stop received between callable result and commit fences settlement and records unknown."""
    control = RunControl(store_path=tmp_path / "stop.sqlite3")
    control.register_run(run_id="run-commit-race", owner_principal="owner")
    control.request_stop(StopRequest(run_id="run-commit-race", principal="owner", reason="stop.race"))

    # When execution finished but commit is unsettled when stop arrived:
    receipt = control.classify_termination(
        run_id="run-commit-race",
        epoch=1,
        confirmed_cancelled=False,
        requested_stop_reason="stop.race",
        unsettled_attempts=["att-1"],
    )
    assert receipt.outcome == "unknown"
    assert "att-1" in receipt.unresolved_attempts
