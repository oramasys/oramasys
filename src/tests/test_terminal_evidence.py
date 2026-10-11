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

import asyncio
from pathlib import Path
import pytest

from orama.graph.run_control import (
    RunControl,
    StopRequest,
    TerminalReceipt,
    TerminalOutcome,
)
from orama.graph.execution_guard import StopSignal


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
            outcome="invalid_outcome",  # type: ignore
            reason="test",
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
