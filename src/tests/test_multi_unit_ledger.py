"""T2-B multi-unit accounting on the existing fenced StepLedger."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from orama.graph.accounting_types import ChargeUnits
from orama.graph.execution_guard import (
    AccountingEvent,
    AccountingRecovery,
    LeaseFenced,
    StepLedger,
    UnknownDisposition,
)


BASIS = "usd_microunits"
SQLITE_MAX_INT = 2**63 - 1


def units(
    steps: int = 0,
    elapsed_ms: int = 0,
    cost_microunits: int = 0,
    effect_attempts: int = 0,
) -> ChargeUnits:
    """Build strict units in the test cost basis."""
    return ChargeUnits(
        steps,
        elapsed_ms,
        cost_microunits,
        effect_attempts,
        cost_basis=BASIS,
    )


def projection(ledger: StepLedger, run_id: str) -> tuple[int, int, int]:
    """Read the non-step durable projection directly for transaction assertions."""
    row = ledger._db.execute(  # noqa: SLF001 - verifies the durable projection directly
        "SELECT elapsed_ms, cost_microunits, effect_attempts "
        "FROM charge_projection WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert row is not None
    return tuple(int(value) for value in row)


def configured_ledger(
    tmp_path: Path, *, maximum: ChargeUnits | None = None
) -> tuple[StepLedger, int]:
    """Open one lease and opt it into multi-unit accounting limits."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    maximum = maximum or units(10, 1000, 10_000, 10)
    epoch = ledger.open_lease("run-1", max_steps=maximum.steps)
    assert ledger.configure_limits("run-1", epoch, maximum) is True
    return ledger, epoch


def test_multi_unit_reservation_is_atomic_and_replay_stable(tmp_path: Path) -> None:
    """One reservation charges every dimension atomically and retries identically."""
    ledger, epoch = configured_ledger(tmp_path, maximum=units(3, 100, 1000, 2))
    charge = units(2, 40, 300, 1)

    hold = ledger.reserve_charge("run-1", epoch, "attempt-1", charge)

    assert ledger.used("run-1") == 2
    assert projection(ledger, "run-1") == (40, 300, 1)
    assert ledger.usage("run-1") == charge
    assert [event.event_type for event in ledger.events("run-1")] == [
        "limits_configured",
        "reservation_tracked",
    ]
    assert all(isinstance(event, AccountingEvent) for event in ledger.events("run-1"))
    assert ledger.reserve_charge("run-1", epoch, "attempt-1", charge) == hold
    assert ledger.used("run-1") == 2
    with pytest.raises(ValueError, match="conflict"):
        ledger.reserve_charge("run-1", epoch, "attempt-1", units(2, 41, 300, 1))
    with pytest.raises(ValueError, match="budget"):
        ledger.reserve_charge("run-1", epoch, "attempt-2", units(1, 61, 1, 0))
    assert ledger.used("run-1") == 2
    assert projection(ledger, "run-1") == (40, 300, 1)


def test_failed_charge_batch_never_charges_other_branches(tmp_path: Path) -> None:
    """A batch that exceeds any dimension leaves every projection unchanged."""
    ledger, epoch = configured_ledger(tmp_path, maximum=units(4, 100, 1000, 3))
    attempts = (("a", units(2, 50, 400, 1)), ("b", units(2, 51, 400, 1)))

    with pytest.raises(ValueError, match="budget"):
        ledger.reserve_charge_batch("run-1", epoch, "batch-1", attempts)

    assert ledger.used("run-1") == 0
    assert projection(ledger, "run-1") == (0, 0, 0)
    assert ledger.hold_state("run-1", "a") is None
    assert ledger.hold_state("run-1", "b") is None

    accepted = (("a", units(2, 40, 400, 1)), ("b", units(2, 50, 400, 1)))
    holds = ledger.reserve_charge_batch("run-1", epoch, "batch-1", accepted)
    assert ledger.reserve_charge_batch("run-1", epoch, "batch-1", accepted) == holds
    with pytest.raises(ValueError, match="payload"):
        ledger.reserve_charge_batch("run-1", epoch, "batch-1", accepted[:1])
    assert ledger.used("run-1") == 4
    assert projection(ledger, "run-1") == (90, 800, 2)


def test_limits_are_immutable_same_payload_idempotent_and_epoch_fenced(
    tmp_path: Path,
) -> None:
    """Limits are immutable, retry-stable, and bound to the current lease."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=3)
    limit = units(3, 100, 1000, 2)

    assert ledger.configure_limits("run-1", epoch, limit) is True
    assert ledger.configure_limits("run-1", epoch, limit) is False
    with pytest.raises(ValueError, match="conflict"):
        ledger.configure_limits("run-1", epoch, units(3, 101, 1000, 2))
    with pytest.raises(ValueError, match="step"):
        ledger.configure_limits("run-1", epoch, units(2, 100, 1000, 2))
    with pytest.raises(ValueError, match="immutable"):
        ledger.open_lease("run-1", max_steps=4)

    new_epoch = ledger.open_lease("run-1", max_steps=3)
    with pytest.raises(LeaseFenced):
        ledger.configure_limits("run-1", epoch, limit)
    assert ledger.configure_limits("run-1", new_epoch, limit) is False


def test_post_v2_legacy_holds_are_tracked_without_opt_in_limits(tmp_path: Path) -> None:
    """Legacy holds record whether the caller actually implements start markers."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=3)

    hold = ledger.reserve_attempt("run-1", epoch, "legacy-new", units=1)
    assert ledger.reserve_attempt("run-1", epoch, "legacy-new", units=1) == hold
    assert ledger.usage("run-1") == ChargeUnits(steps=1, cost_basis="legacy_step_only")
    assert [event.event_type for event in ledger.events("run-1")] == ["reservation_tracked"]
    with pytest.raises(ValueError, match="reservation evidence"):
        ledger.mark_started("run-1", "legacy-new", epoch)
    with pytest.raises(ValueError, match="conflict"):
        ledger.reserve_attempt(
            "run-1", epoch, "legacy-new", units=1, requires_start_marker=True
        )

    ledger.reserve_attempt(
        "run-1", epoch, "marker-aware", units=1, requires_start_marker=True
    )
    assert ledger.mark_started("run-1", "marker-aware", epoch) is True
    assert ledger.record_outcome("run-1", "marker-aware", epoch, "node-result") is True


def test_configured_limits_cannot_be_bypassed_by_legacy_reservation(
    tmp_path: Path,
) -> None:
    """Configured runs must use the multi-unit reservation path."""
    ledger, epoch = configured_ledger(tmp_path)

    with pytest.raises(ValueError, match="reserve_charge"):
        ledger.reserve("run-1", epoch, 1)
    with pytest.raises(ValueError, match="reserve_charge"):
        ledger.reserve_attempt("run-1", epoch, "legacy", units=1)
    with pytest.raises(ValueError, match="reserve_charge_batch"):
        ledger.reserve_batch("run-1", epoch, "legacy-batch", (("legacy", 1),))


def test_recovery_without_any_holds_is_an_empty_idempotent_result(tmp_path: Path) -> None:
    """A run with no unresolved work recovers to an empty result without takeover."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=2)

    empty = AccountingRecovery(released=(), unknown=(), preserved_unknown=())
    assert ledger.recover_accounting("run-1", epoch) == empty
    assert ledger.recover_accounting("run-1", epoch) == empty


def test_start_and_outcome_are_immutable_and_ordered(tmp_path: Path) -> None:
    """Starts precede outcomes and both records reject changed retries."""
    ledger, epoch = configured_ledger(tmp_path)
    ledger.reserve_charge("run-1", epoch, "attempt-1", units(1, 10, 20, 1))

    assert ledger.mark_started("run-1", "attempt-1", epoch) is True
    assert ledger.mark_started("run-1", "attempt-1", epoch) is False
    assert ledger.record_outcome("run-1", "attempt-1", epoch, "digest-a") is True
    assert ledger.record_outcome("run-1", "attempt-1", epoch, "digest-a") is False
    with pytest.raises(ValueError, match="conflict"):
        ledger.record_outcome("run-1", "attempt-1", epoch, "digest-b")

    ledger.reserve_charge("run-1", epoch, "attempt-2", units(1))
    with pytest.raises(ValueError, match="start"):
        ledger.record_outcome("run-1", "attempt-2", epoch, "digest")


def test_verified_usage_refunds_only_with_start_and_outcome_evidence(
    tmp_path: Path,
) -> None:
    """Verified usage refunds only the evidenced difference from its hold."""
    ledger, epoch = configured_ledger(tmp_path)
    held = units(3, 100, 1000, 2)
    actual = units(1, 60, 700, 1)
    hold = ledger.reserve_charge("run-1", epoch, "attempt-1", held)
    ledger.mark_started("run-1", "attempt-1", epoch)

    with pytest.raises(ValueError, match="outcome"):
        ledger.settle_usage("run-1", "attempt-1", epoch, "receipt-1", actual)

    ledger.record_outcome("run-1", "attempt-1", epoch, "result-a")
    assert ledger.settle_usage("run-1", "attempt-1", epoch, "receipt-1", actual) is True
    assert ledger.settle_usage("run-1", "attempt-1", epoch, "receipt-1", actual) is False
    assert ledger.used("run-1") == 1
    assert projection(ledger, "run-1") == (60, 700, 1)
    assert ledger.hold_state("run-1", "attempt-1") == "settled"
    receipt = ledger._db.execute(  # noqa: SLF001 - prove the canonical receipt is unchanged
        "SELECT receipt_id, usage_known, steps, elapsed_ms, cost_microunits, effect_attempts "
        "FROM usage_receipts WHERE run_id = ? AND attempt_id = ?",
        ("run-1", "attempt-1"),
    ).fetchone()
    with pytest.raises(ValueError, match="known usage receipt"):
        ledger.mark_unknown(
            "run-1",
            UnknownDisposition(
                attempt_id="attempt-1",
                hold_id=hold.hold_id,
                fence_epoch=epoch,
                cause="crash_before_settle",
                stop_state="none",
                settlement_state="unsettled",
            ),
        )
    assert ledger.hold_state("run-1", "attempt-1") == "settled"
    assert ledger.usage("run-1") == actual
    assert ledger._db.execute(  # noqa: SLF001 - compare the durable receipt byte-for-byte
        "SELECT receipt_id, usage_known, steps, elapsed_ms, cost_microunits, effect_attempts "
        "FROM usage_receipts WHERE run_id = ? AND attempt_id = ?",
        ("run-1", "attempt-1"),
    ).fetchone() == receipt

    with pytest.raises(ValueError, match="receipt"):
        ledger.settle_usage("run-1", "attempt-1", epoch, "receipt-2", actual)
    with pytest.raises(ValueError, match="conflict"):
        ledger.settle_usage("run-1", "attempt-1", epoch, "receipt-1", units(1, 61, 700, 1))


def test_unknown_usage_consumes_the_full_hold_without_release(tmp_path: Path) -> None:
    """Missing usage remains unknown and conservatively consumes the full hold."""
    ledger, epoch = configured_ledger(tmp_path)
    held = units(2, 100, 1000, 1)
    ledger.reserve_charge("run-1", epoch, "attempt-1", held)
    ledger.mark_started("run-1", "attempt-1", epoch)
    ledger.record_outcome("run-1", "attempt-1", epoch, "result-without-intent")

    assert ledger.settle_usage("run-1", "attempt-1", epoch, "receipt-unknown", None) is True
    assert ledger.used("run-1") == held.steps
    assert projection(ledger, "run-1") == (100, 1000, 1)
    assert ledger.hold_state("run-1", "attempt-1") == "unknown"
    assert ledger._db.execute(  # noqa: SLF001 - outcome alone is not commit intent
        "SELECT cause FROM unknown_dispositions WHERE run_id = ? AND attempt_id = ?",
        ("run-1", "attempt-1"),
    ).fetchone() == ("crash_before_intent",)
    with pytest.raises(ValueError, match="unknown"):
        ledger.release_attempt("run-1", "attempt-1", epoch)


def test_usage_must_fit_hold_and_match_basis(tmp_path: Path) -> None:
    """Receipts cannot exceed their hold or cross accounting bases."""
    ledger, epoch = configured_ledger(tmp_path)
    ledger.reserve_charge("run-1", epoch, "attempt-1", units(1, 10, 100, 1))
    ledger.mark_started("run-1", "attempt-1", epoch)
    ledger.record_outcome("run-1", "attempt-1", epoch, "result")

    with pytest.raises(ValueError, match="steps"):
        ledger.settle_usage("run-1", "attempt-1", epoch, "zero-steps", units(0, 1, 1, 0))
    assert ledger.used("run-1") == 1
    with pytest.raises(ValueError, match="hold"):
        ledger.settle_usage("run-1", "attempt-1", epoch, "too-large", units(1, 11, 100, 1))
    with pytest.raises(ValueError, match="cost_basis"):
        ledger.settle_usage(
            "run-1",
            "attempt-1",
            epoch,
            "wrong-basis",
            ChargeUnits(1, 10, 100, 1, cost_basis="tokens"),
        )


def test_recovery_classifies_uncertainty_from_commit_intent_not_outcome(
    tmp_path: Path,
) -> None:
    """Commit intent, not outcome observation, selects the frozen v1 cause."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    old_epoch = ledger.open_lease("run-1", max_steps=4)
    legacy = ledger.reserve_attempt("run-1", old_epoch, "legacy-intent", units=1)
    ledger.prepare_commit(
        "run-1", "legacy-intent", legacy.hold_id, old_epoch, "legacy-result"
    )
    ledger.configure_limits("run-1", old_epoch, units(4, 100, 1000, 4))
    ledger.reserve_charge("run-1", old_epoch, "outcome-only", units(1, 10, 100, 1))
    ledger.mark_started("run-1", "outcome-only", old_epoch)
    ledger.record_outcome("run-1", "outcome-only", old_epoch, "observed-result")

    new_epoch = ledger.open_lease("run-1", max_steps=4)
    recovery = ledger.recover_accounting("run-1", new_epoch)

    assert recovery.unknown == ("legacy-intent", "outcome-only")
    causes = dict(
        ledger._db.execute(  # noqa: SLF001 - verify frozen schema-v1 classifications
            "SELECT attempt_id, cause FROM unknown_dispositions WHERE run_id = ?",
            ("run-1",),
        ).fetchall()
    )
    assert causes == {
        "legacy-intent": "crash_before_settle",
        "outcome-only": "crash_before_intent",
    }
    recovery_event = next(
        event for event in ledger.events("run-1") if event.event_type == "accounting_recovered"
    )
    evidence = json.loads(recovery_event.payload_json)["evidence"]
    assert evidence["legacy-intent"] == {
        "start": False,
        "outcome": False,
        "intent": True,
    }
    assert evidence["outcome-only"] == {
        "start": True,
        "outcome": True,
        "intent": False,
    }


def test_recovery_requires_takeover_releases_only_proven_unstarted_new_holds(
    tmp_path: Path,
) -> None:
    """Takeover releases only marker-aware unstarted holds and never replays work."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    old_epoch = ledger.open_lease("run-1", max_steps=10)
    ledger.reserve_attempt(
        "run-1", old_epoch, "tracked-step-hold", units=1, requires_start_marker=True
    )
    ledger.reserve_attempt("run-1", old_epoch, "legacy-unmarked", units=1)
    ledger.configure_limits("run-1", old_epoch, units(10, 1000, 10_000, 10))
    ledger.reserve_charge("run-1", old_epoch, "new-unstarted", units(2, 20, 200, 0))
    ledger.reserve_charge("run-1", old_epoch, "new-started", units(2, 30, 300, 1))
    ledger.mark_started("run-1", "new-started", old_epoch)
    ledger.reserve_charge("run-1", old_epoch, "already-unknown", units(1, 40, 400, 1))
    ledger.mark_started("run-1", "already-unknown", old_epoch)
    ledger.settle_usage("run-1", "already-unknown", old_epoch, "unknown-r", None)
    with ledger._tx() as db:  # noqa: SLF001 - simulate a pre-v2 hold with no tracking event
        db.execute(
            "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) "
            "VALUES (?, ?, ?, ?, ?, 'held')",
            ("run-1", "pre-migration", "hold:pre-migration", old_epoch, 1),
        )
        db.execute("UPDATE leases SET used = used + 1 WHERE run_id = ?", ("run-1",))

    with pytest.raises(ValueError, match="takeover"):
        ledger.recover_accounting("run-1", old_epoch)

    new_epoch = ledger.open_lease("run-1", max_steps=10)
    recovery = ledger.recover_accounting("run-1", new_epoch)

    assert recovery == AccountingRecovery(
        released=("new-unstarted", "tracked-step-hold"),
        unknown=("legacy-unmarked", "new-started", "pre-migration"),
        preserved_unknown=("already-unknown",),
    )
    assert ledger.recover_accounting("run-1", new_epoch) == recovery
    assert ledger.hold_state("run-1", "new-unstarted") == "released"
    assert ledger.hold_state("run-1", "new-started") == "unknown"
    assert ledger.hold_state("run-1", "already-unknown") == "unknown"
    assert ledger.hold_state("run-1", "tracked-step-hold") == "released"
    assert ledger.hold_state("run-1", "legacy-unmarked") == "unknown"
    assert ledger.hold_state("run-1", "pre-migration") == "unknown"
    assert ledger.used("run-1") == 5
    assert projection(ledger, "run-1") == (70, 700, 2)


def test_all_new_mutations_and_legacy_duplicate_paths_check_current_epoch(
    tmp_path: Path,
) -> None:
    """Stale epochs cannot mutate new records or replay legacy reservations."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    old_epoch = ledger.open_lease("run-1", max_steps=10)
    ledger.reserve_attempt(
        "run-1", old_epoch, "legacy", units=1, requires_start_marker=True
    )
    ledger.configure_limits("run-1", old_epoch, units(10, 1000, 10_000, 10))
    charge = units(1, 10, 10, 0)
    hold = ledger.reserve_charge("run-1", old_epoch, "attempt-1", charge)
    new_epoch = ledger.open_lease("run-1", max_steps=10)

    with pytest.raises(LeaseFenced):
        ledger.reserve_charge("run-1", old_epoch, "attempt-1", charge)
    with pytest.raises(LeaseFenced):
        ledger.reserve_attempt(
            "run-1", old_epoch, "legacy", units=1, requires_start_marker=True
        )
    with pytest.raises(LeaseFenced):
        ledger.mark_started("run-1", "attempt-1", old_epoch)
    with pytest.raises(LeaseFenced):
        ledger.prepare_commit("run-1", "attempt-1", hold.hold_id, old_epoch, "digest")
    assert new_epoch == old_epoch + 1


def test_sqlite_integer_range_is_checked_before_writes(tmp_path: Path) -> None:
    """Values outside signed SQLite INTEGER range fail before persistence."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=1)
    with pytest.raises(ValueError, match="SQLite integer"):
        ledger.configure_limits("run-1", epoch, units(1, SQLITE_MAX_INT + 1, 0, 0))

    ledger.configure_limits("run-1", epoch, units(1, SQLITE_MAX_INT, 0, 0))
    with pytest.raises(ValueError, match="SQLite integer"):
        ledger.reserve_charge("run-1", epoch, "attempt-1", units(1, SQLITE_MAX_INT + 1, 0, 0))


def test_migration_is_idempotent_and_preserves_legacy_history(tmp_path: Path) -> None:
    """Repeated schema-v2 initialization preserves all existing step history."""
    path = tmp_path / "ledger.sqlite3"
    first = StepLedger(path)
    epoch = first.open_lease("run-1", max_steps=3)
    legacy = first.reserve_attempt("run-1", epoch, "legacy", units=1)
    first.close()

    second = StepLedger(path)
    second.close()
    third = StepLedger(path)

    assert third.hold("run-1", "legacy") == legacy
    assert third.used("run-1") == 1
    assert third._db.execute(  # noqa: SLF001
        "SELECT version FROM accounting_schema"
    ).fetchone() == (2,)


def test_observe_time_persists_utc_high_water_and_refuses_rollback(tmp_path: Path) -> None:
    """UTC observations advance durably and reject a lower clock value."""
    ledger, epoch = configured_ledger(tmp_path)
    now = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)

    assert ledger.observe_time("run-1", epoch, now) is True
    assert ledger.observe_time("run-1", epoch, now) is False
    assert ledger.observe_time("run-1", epoch, now + timedelta(seconds=1)) is True
    with pytest.raises(ValueError, match="rollback"):
        ledger.observe_time("run-1", epoch, now - timedelta(microseconds=1))
    with pytest.raises(ValueError, match="aware"):
        ledger.observe_time("run-1", epoch, now.replace(tzinfo=None))
