"""REV3 T2-A durable accounting records and conservative recovery."""
from __future__ import annotations

import pytest

from orama.graph.execution_guard import AttemptHold, StepLedger, UnknownDisposition


def test_commit_intent_is_idempotent_and_settlement_is_bound_to_its_hold(tmp_path) -> None:
    """A prepared commit settles exactly its durable hold and exact result digest."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=3)
    hold = ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)

    assert hold == AttemptHold("run-1", "attempt-1", hold.hold_id, epoch, 1)
    assert ledger.prepare_commit("run-1", "attempt-1", hold.hold_id, epoch, "digest-a") is True
    assert ledger.prepare_commit("run-1", "attempt-1", hold.hold_id, epoch, "digest-a") is False
    with pytest.raises(ValueError, match="digest"):
        ledger.prepare_commit("run-1", "attempt-1", hold.hold_id, epoch, "digest-b")

    assert ledger.settle_commit("run-1", "attempt-1", "digest-a") is True
    assert ledger.settle_commit("run-1", "attempt-1", "digest-a") is False
    assert ledger.hold_state("run-1", "attempt-1") == "settled"


def test_unknown_hold_is_not_released_without_an_explicit_adjustment(tmp_path) -> None:
    """Crash uncertainty remains durable and cannot become free budget implicitly."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=2)
    hold = ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)
    unknown = UnknownDisposition(
        attempt_id="attempt-1",
        hold_id=hold.hold_id,
        fence_epoch=epoch,
        cause="crash_before_settle",
        stop_state="none",
        settlement_state="unsettled",
    )

    ledger.mark_unknown("run-1", unknown)

    assert ledger.hold_state("run-1", "attempt-1") == "unknown"
    assert ledger.used("run-1") == 1
    with pytest.raises(ValueError, match="unknown"):
        ledger.release_attempt("run-1", "attempt-1", epoch)


def test_unknown_disposition_rejects_unversioned_or_invalid_vocabulary() -> None:
    """The cross-stream terminal record rejects ambiguous reason shapes at its boundary."""
    with pytest.raises(ValueError, match="unknown disposition"):
        UnknownDisposition(
            attempt_id="attempt-1",
            hold_id="hold-1",
            fence_epoch=1,
            cause="timeout",  # type: ignore[arg-type]
            stop_state="none",
            settlement_state="unsettled",
        )


def test_batch_reservation_is_all_or_nothing_and_idempotent(tmp_path) -> None:
    """A batch either reserves every branch or charges no branch at all."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=2)

    holds = ledger.reserve_batch(
        "run-1", epoch, "batch-1", (("branch-a", 1), ("branch-b", 1))
    )
    assert [hold.attempt_id for hold in holds] == ["branch-a", "branch-b"]
    assert ledger.used("run-1") == 2
    assert ledger.reserve_batch(
        "run-1", epoch, "batch-1", (("branch-a", 1), ("branch-b", 1))
    ) == holds
    with pytest.raises(ValueError, match="payload"):
        ledger.reserve_batch("run-1", epoch, "batch-1", (("branch-a", 2),))

    # A database written before the membership index existed recovers it only
    # from a replay whose payload digest still proves identical membership.
    ledger._db.execute("DELETE FROM batch_attempts WHERE run_id = ?", ("run-1",))
    assert ledger.reserve_batch(
        "run-1", epoch, "batch-1", (("branch-a", 1), ("branch-b", 1))
    ) == holds
    assert set(ledger.batch_hold_states("run-1", "batch-1")) == {"branch-a", "branch-b"}

    other = StepLedger(tmp_path / "other.sqlite3")
    other_epoch = other.open_lease("run-2", max_steps=1)
    with pytest.raises(ValueError, match="budget"):
        other.reserve_batch("run-2", other_epoch, "batch-2", (("a", 1), ("b", 1)))
    assert other.used("run-2") == 0


def test_batch_commit_intents_settle_only_the_admitted_attempts(tmp_path) -> None:
    """A region publication settles exactly the branch holds it admits."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=3)
    ledger.reserve_batch(
        "run-1",
        epoch,
        "batch-1",
        (("batch-1:a", 1), ("batch-1:b", 1), ("batch-1:c", 1)),
    )

    assert ledger.prepare_batch_commit(
        "run-1", "batch-1", ("batch-1:a", "batch-1:b"), epoch, "digest-a"
    ) is True
    assert ledger.prepare_batch_commit(
        "run-1", "batch-1", ("batch-1:a", "batch-1:b"), epoch, "digest-a"
    ) is False
    assert ledger.settle_batch_commit(
        "run-1", "batch-1", ("batch-1:a", "batch-1:b"), "digest-a"
    ) is True
    assert ledger.settle_batch_commit(
        "run-1", "batch-1", ("batch-1:a", "batch-1:b"), "digest-a"
    ) is False
    assert ledger.hold_state("run-1", "batch-1:a") == "settled"
    assert ledger.hold_state("run-1", "batch-1:b") == "settled"
    assert ledger.hold_state("run-1", "batch-1:c") == "held"
