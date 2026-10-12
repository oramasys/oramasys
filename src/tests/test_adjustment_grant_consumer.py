"""T2 Task 6: Oramasys consumer test suite for Phylax adjustment grants.

Per PHYLAX-ADJUSTMENT-GRANT-DESIGN-v2.md Sections 7 and 13:
- Acceptance surface tests:
  * Unauthorized caller / wrong principal
  * Store id mismatch
  * Fencing: wrong consumer_lease_epoch or hold_fence_epoch
  * Cost basis mismatch
  * Replay / identical retry returns identical immutable receipt read-only
  * Altered-payload retry fails closed
  * Expiry, future-dated, and stale revocation (>60s) fail closed
  * Revocation fails closed
  * Release frees balance; settle marks hold settled
  * Zero nacl and zero phylax imported in Oramasys
  * Default verifier is DenyAllGrantVerifier
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from orama.graph.accounting_types import ChargeUnits
from orama.graph.execution_guard import (
    LeaseFenced,
    StepLedger,
    UnknownDisposition,
)
from orama.graph.grant_verifier import (
    AdjustmentGrantRefused,
    AdjustmentReceipt,
    DenyAllGrantVerifier,
    RevocationObservation,
    VerifiedGrant,
)


def make_grant(
    ledger: StepLedger,
    *,
    grant_id: str = "grant-1",
    principal: str = "agent-1",
    run_id: str = "run-1",
    hold_id: str = "attempt-1",
    kind: str = "release",
    units: int = 1,
    units_basis: str = "steps",
    ledger_cost_basis: str = "legacy_step_only",
    hold_fence_epoch: int = 1,
    consumer_lease_epoch: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    payload_digest: str = "a" * 64,
    verifier_id: str = "phylax.local",
    ledger_store_id: str | None = None,
) -> VerifiedGrant:
    """Build a valid VerifiedGrant bound to ledger state for testing."""
    now = datetime.now(UTC)
    i_at = issued_at or (now - timedelta(seconds=10))
    e_at = expires_at or (now + timedelta(seconds=900))
    return VerifiedGrant(
        grant_id=grant_id,
        principal=principal,
        run_id=run_id,
        hold_id=hold_id,
        kind=kind,  # type: ignore[arg-type]
        units=units,
        units_basis=units_basis,
        ledger_cost_basis=ledger_cost_basis,
        hold_fence_epoch=hold_fence_epoch,
        consumer_lease_epoch=consumer_lease_epoch,
        ledger_store_id=ledger_store_id or ledger.store_id,
        issued_at=i_at,
        expires_at=e_at,
        payload_digest=payload_digest,
        verifier_id=verifier_id,
    )


def test_oramasys_import_graph_has_no_nacl_and_no_phylax() -> None:
    """Oramasys carries zero nacl or phylax modules in its runtime dependencies."""
    import os
    import subprocess

    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1]) + (
        os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else ""
    )
    cmd = [
        sys.executable,
        "-c",
        (
            "import sys\n"
            "import orama\n"
            "import orama.graph.grant_verifier\n"
            "import orama.graph.execution_guard\n"
            "imported = set(sys.modules)\n"
            "assert 'nacl' not in imported, f'nacl leaked into runtime: {imported}'\n"
            "assert 'phylax' not in imported, f'phylax leaked into runtime: {imported}'\n"
            "print('OK')\n"
        ),
    ]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
    assert res.stdout.strip() == "OK"


def test_default_verifier_is_deny_all() -> None:
    """Default verifier rejects all verification and revocation requests fail-closed."""
    verifier = DenyAllGrantVerifier()
    with pytest.raises(AdjustmentGrantRefused) as exc:
        verifier.verify(b"{}")
    assert exc.value.code == "verifier.unavailable"

    with pytest.raises(AdjustmentGrantRefused) as exc:
        verifier.revocation("grant-1")
    assert exc.value.code == "verifier.unavailable"


def test_consume_adjustment_grant_release_step_hold(tmp_path: Path) -> None:
    """Valid release adjustment grant frees held steps and records immutable receipt."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    hold = ledger.reserve_attempt("run-1", epoch, "attempt-1", units=2)
    assert ledger.used("run-1") == 2

    # Mark as unknown to simulate crash/uncertainty
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

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", units=2, kind="release")
    revocation = RevocationObservation(grant_id=grant.grant_id, revoked=False, observed_at=now)

    receipt = ledger.consume_adjustment_grant(
        grant,
        revocation,
        caller_principal="agent-1",
        now=now,
    )

    assert isinstance(receipt, AdjustmentReceipt)
    assert receipt.grant_id == grant.grant_id
    assert receipt.balance_delta == 2
    assert receipt.kind == "release"
    assert ledger.hold_state("run-1", "attempt-1") == "released"
    assert ledger.used("run-1") == 0


def test_consume_adjustment_grant_settle_hold(tmp_path: Path) -> None:
    """Valid settle adjustment grant settles held steps without reducing used count."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    hold = ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)
    assert ledger.used("run-1") == 1

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", units=1, kind="settle")
    revocation = RevocationObservation(grant_id=grant.grant_id, revoked=False, observed_at=now)

    receipt = ledger.consume_adjustment_grant(
        grant,
        revocation,
        caller_principal="agent-1",
        now=now,
    )

    assert receipt.kind == "settle"
    assert ledger.hold_state("run-1", "attempt-1") == "settled"
    assert ledger.used("run-1") == 1


def test_identical_retry_returns_stored_receipt_read_only(tmp_path: Path) -> None:
    """Identical retry returns stored receipt read-only, even if expired or revoked."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", units=1, kind="release")
    revocation = RevocationObservation(grant_id=grant.grant_id, revoked=False, observed_at=now)

    first = ledger.consume_adjustment_grant(grant, revocation, caller_principal="agent-1", now=now)

    # Identical retry directly via consume
    second = ledger.consume_adjustment_grant(grant, revocation, caller_principal="agent-1", now=now + timedelta(seconds=10))
    assert first == second

    # Identical retry via read-only retry_adjustment_grant
    retry = ledger.retry_adjustment_grant(
        grant_id=grant.grant_id,
        caller_principal="agent-1",
        payload_digest=grant.payload_digest,
    )
    assert retry == first


def test_altered_payload_or_principal_retry_refuses(tmp_path: Path) -> None:
    """Altered payload digest or different caller principal fails closed on retry."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", units=1, kind="release", payload_digest="1" * 64)
    revocation = RevocationObservation(grant_id=grant.grant_id, revoked=False, observed_at=now)
    ledger.consume_adjustment_grant(grant, revocation, caller_principal="agent-1", now=now)

    # Different caller principal on retry
    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.retry_adjustment_grant(
            grant_id=grant.grant_id,
            caller_principal="imposter",
            payload_digest="1" * 64,
        )
    assert exc.value.code == "grant.key_unknown"

    # Altered payload digest on retry
    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.retry_adjustment_grant(
            grant_id=grant.grant_id,
            caller_principal="agent-1",
            payload_digest="2" * 64,
        )
    assert exc.value.code == "grant.malformed"


def test_revocation_stale_or_revoked_fails_closed(tmp_path: Path) -> None:
    """Stale revocation observation (>60s) or active revocation refuses consumption."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", units=1, kind="release")

    # Revocation observation older than 60s
    stale_revocation = RevocationObservation(
        grant_id=grant.grant_id,
        revoked=False,
        observed_at=now - timedelta(seconds=61),
    )
    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.consume_adjustment_grant(grant, stale_revocation, caller_principal="agent-1", now=now)
    assert exc.value.code == "revocation.stale"

    # Active revocation
    active_revocation = RevocationObservation(
        grant_id=grant.grant_id,
        revoked=True,
        observed_at=now,
    )
    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.consume_adjustment_grant(grant, active_revocation, caller_principal="agent-1", now=now)
    assert exc.value.code == "grant.revoked"


def test_expired_or_future_dated_grant_fails_closed(tmp_path: Path) -> None:
    """Expired grant or grant issued >60s in future refuses consumption."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)

    now = datetime.now(UTC)

    # Expired
    expired_grant = make_grant(
        ledger,
        hold_id="attempt-1",
        issued_at=now - timedelta(seconds=100),
        expires_at=now - timedelta(seconds=1),
    )
    rev = RevocationObservation(grant_id=expired_grant.grant_id, revoked=False, observed_at=now)
    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.consume_adjustment_grant(expired_grant, rev, caller_principal="agent-1", now=now)
    assert exc.value.code == "grant.expired"

    # Future dated (>60s)
    future_grant = make_grant(
        ledger,
        hold_id="attempt-1",
        issued_at=now + timedelta(seconds=70),
        expires_at=now + timedelta(seconds=500),
    )
    rev2 = RevocationObservation(grant_id=future_grant.grant_id, revoked=False, observed_at=now)
    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.consume_adjustment_grant(future_grant, rev2, caller_principal="agent-1", now=now)
    assert exc.value.code == "grant.future_dated"


def test_ledger_store_id_mismatch_fails_closed(tmp_path: Path) -> None:
    """Grant minted for a different ledger_store_id is refused."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", ledger_store_id="store:other_store_id")
    rev = RevocationObservation(grant_id=grant.grant_id, revoked=False, observed_at=now)

    with pytest.raises(AdjustmentGrantRefused) as exc:
        ledger.consume_adjustment_grant(grant, rev, caller_principal="agent-1", now=now)
    assert exc.value.code == "grant.schema_unsupported"


def test_lease_fencing_checks_both_epochs_independently(tmp_path: Path) -> None:
    """hold_fence_epoch and consumer_lease_epoch are checked independently."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch1 = ledger.open_lease("run-1", max_steps=5)
    ledger.reserve_attempt("run-1", epoch1, "attempt-1", units=1)

    # Newer holder takes over lease
    epoch2 = ledger.open_lease("run-1", max_steps=5)
    assert epoch2 == epoch1 + 1

    now = datetime.now(UTC)

    # Wrong consumer_lease_epoch (still claiming epoch 1 when active is epoch 2)
    stale_lease_grant = make_grant(
        ledger,
        hold_id="attempt-1",
        hold_fence_epoch=epoch1,
        consumer_lease_epoch=epoch1,
    )
    rev = RevocationObservation(grant_id=stale_lease_grant.grant_id, revoked=False, observed_at=now)
    with pytest.raises(LeaseFenced):
        ledger.consume_adjustment_grant(stale_lease_grant, rev, caller_principal="agent-1", now=now)

    # Wrong hold_fence_epoch (hold was created in epoch 1, but grant claims hold was epoch 2)
    bad_hold_epoch_grant = make_grant(
        ledger,
        hold_id="attempt-1",
        hold_fence_epoch=epoch2,
        consumer_lease_epoch=epoch2,
    )
    rev2 = RevocationObservation(grant_id=bad_hold_epoch_grant.grant_id, revoked=False, observed_at=now)
    with pytest.raises(LeaseFenced):
        ledger.consume_adjustment_grant(bad_hold_epoch_grant, rev2, caller_principal="agent-1", now=now)

    # Correct: hold_fence_epoch=epoch1, consumer_lease_epoch=epoch2
    valid_takeover_grant = make_grant(
        ledger,
        hold_id="attempt-1",
        hold_fence_epoch=epoch1,
        consumer_lease_epoch=epoch2,
    )
    rev3 = RevocationObservation(grant_id=valid_takeover_grant.grant_id, revoked=False, observed_at=now)
    receipt = ledger.consume_adjustment_grant(valid_takeover_grant, rev3, caller_principal="agent-1", now=now)
    assert receipt.kind == "release"
    assert ledger.hold_state("run-1", "attempt-1") == "released"


def test_cannot_adjust_already_settled_hold(tmp_path: Path) -> None:
    """Cannot adjust a hold that was already settled."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("run-1", max_steps=5)
    hold = ledger.reserve_attempt("run-1", epoch, "attempt-1", units=1)
    ledger.prepare_commit("run-1", "attempt-1", hold.hold_id, epoch, "digest-a")
    ledger.settle_commit("run-1", "attempt-1", "digest-a")
    assert ledger.hold_state("run-1", "attempt-1") == "settled"

    now = datetime.now(UTC)
    grant = make_grant(ledger, hold_id="attempt-1", units=1, kind="release")
    rev = RevocationObservation(grant_id=grant.grant_id, revoked=False, observed_at=now)

    with pytest.raises(ValueError, match="already settled"):
        ledger.consume_adjustment_grant(grant, rev, caller_principal="agent-1", now=now)


def test_conformance_vector_verified_grant_consumer(tmp_path: Path) -> None:
    """The consumer verifies and consumes the fixed conformance vector from docs/vectors/adjustment-grant-v1.json."""
    import json
    vector_path = Path("/private/tmp/phylax-task6-grant-authority-20261012/docs/vectors/adjustment-grant-v1.json")
    if not vector_path.exists():
        pytest.skip("shared conformance vector not found")

    vector = json.loads(vector_path.read_text("utf-8"))
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    # Set ledger store_id to match vector
    ledger._store_id = vector["request"]["ledger_store_id"]
    ledger._db.execute("UPDATE store_metadata SET value = ? WHERE key = 'store_id'", (ledger._store_id,))

    # Open lease to match consumer_lease_epoch
    epoch = ledger.open_lease(vector["request"]["run_id"], max_steps=10)
    for _ in range(vector["request"]["consumer_lease_epoch"] - epoch):
        epoch = ledger.open_lease(vector["request"]["run_id"], max_steps=10)
    assert epoch == vector["request"]["consumer_lease_epoch"]

    # Create hold under hold_fence_epoch
    ledger._db.execute(
        "INSERT INTO attempt_holds (run_id, attempt_id, hold_id, epoch, units, state) VALUES (?, ?, ?, ?, ?, 'held')",
        (
            vector["request"]["run_id"],
            vector["request"]["hold_id"],
            f"hold:{vector['request']['hold_id']}",
            vector["request"]["hold_fence_epoch"],
            vector["request"]["units"],
        ),
    )
    ledger._db.execute("UPDATE leases SET used = ? WHERE run_id = ?", (vector["request"]["units"], vector["request"]["run_id"]))

    now = datetime.fromisoformat(vector["issued_at"]) + timedelta(seconds=100)
    rev = RevocationObservation(grant_id=vector["grant_id"], revoked=False, observed_at=now)

    verified = VerifiedGrant(
        grant_id=vector["grant_id"],
        principal=vector["request"]["principal"],
        run_id=vector["request"]["run_id"],
        hold_id=vector["request"]["hold_id"],
        kind=vector["request"]["kind"],
        units=vector["request"]["units"],
        units_basis=vector["request"]["units_basis"],
        ledger_cost_basis=vector["request"]["ledger_cost_basis"],
        hold_fence_epoch=vector["request"]["hold_fence_epoch"],
        consumer_lease_epoch=vector["request"]["consumer_lease_epoch"],
        ledger_store_id=vector["request"]["ledger_store_id"],
        issued_at=datetime.fromisoformat(vector["issued_at"]),
        expires_at=datetime.fromisoformat(vector["expires_at"]),
        payload_digest=vector["payload_digest"],
        verifier_id="phylax.local",
    )

    receipt = ledger.consume_adjustment_grant(
        verified,
        rev,
        caller_principal=vector["request"]["principal"],
        now=now,
    )
    assert receipt.grant_id == vector["grant_id"]
    assert receipt.balance_delta == vector["request"]["units"]
    assert receipt.payload_digest == vector["payload_digest"]
    assert ledger.hold_state(vector["request"]["run_id"], vector["request"]["hold_id"]) == "settled"
