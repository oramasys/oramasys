"""C2a: atomic claim transitions, claim-scope idempotency and version guards (IC-11..IC-15)."""
from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest

from orama.orchestrator_controller import store as store_module
from orama.orchestrator_controller.refusals import ClaimRefused
from orama.orchestrator_controller.store import Admission, ControllerStore

from .support import (
    ALL_TABLES,
    BASE_SHA,
    CLAIM_TABLES,
    PAYLOAD_DIGEST,
    RESULT_DIGEST,
    SOURCE_REF,
    FakeClock,
    admitted,
    declare,
    lease_request,
    open_store,
    request,
    table_snapshot,
)


@pytest.fixture
def clock() -> FakeClock:
    """A fresh controllable clock."""
    return FakeClock()


@pytest.fixture
def store(tmp_path, clock) -> ControllerStore:
    """A store with one declared pure task."""
    opened = open_store(tmp_path, clock)
    declare(opened)
    yield opened
    opened.close()


def _refusal(store: ControllerStore, req, principal: str = "agent-a") -> ClaimRefused:
    """Apply ``req`` expecting a refusal and return it."""
    with pytest.raises(ClaimRefused) as caught:
        store.apply_admitted(req, admitted(principal))
    return caught.value


def _claim(store: ControllerStore, principal: str = "agent-a", **overrides):
    """Claim task-1 as ``principal``."""
    req = request(principal=principal, idempotency_key=f"claim-{principal}", **overrides)
    return store.apply_admitted(req, admitted(principal))


def _count(store: ControllerStore, table: str) -> int:
    """Return the number of rows in ``table``."""
    return len(store._read_all(table))


# --- declaration -----------------------------------------------------------------------------


def test_declare_is_idempotent_and_conflicts_on_changed_content(store) -> None:
    """Re-declaring identical content is a no-op; different content is refused."""
    declare(store)
    assert store.task("task-1").version == 1
    with pytest.raises(ClaimRefused) as caught:
        store.declare_task(
            "task-1", source_ref=SOURCE_REF, expected_base_sha=BASE_SHA,
            payload_digest="0" * 64, effect_class="pure",
        )
    assert (caught.value.code, caught.value.status) == ("task.declaration_conflict", 409)


@pytest.mark.parametrize(
    "overrides",
    [
        {"effect_class": "maybe"},
        {"payload_digest": "nothex"},
        {"expected_base_sha": "xyz"},
        {"source_ref": "/abs"},
    ],
)
def test_declare_validates_inputs(store, overrides) -> None:
    """Declarations are validated like requests (IC-19 source line, IC-22 opaque values)."""
    values = {"source_ref": SOURCE_REF, "expected_base_sha": BASE_SHA,
              "payload_digest": PAYLOAD_DIGEST, "effect_class": "pure"}
    values.update(overrides)
    with pytest.raises(ValueError):
        store.declare_task("task-2", **values)


# --- claim -----------------------------------------------------------------------------------


def test_claim_creates_one_lease_and_commits_outbox_and_audit(store, clock) -> None:
    """IC-11: one transaction claims, bumps the version and writes outbox and audit."""
    receipt = _claim(store)
    assert receipt.operation == "claim" and receipt.task_state == "claimed"
    assert receipt.task_version == 2 and not receipt.replayed
    assert receipt.lease_expires_at == clock.now + timedelta(seconds=30)
    assert len(receipt.lease_token) >= 43
    task = store.task("task-1")
    assert (task.state, task.version) == ("claimed", 2)
    assert _count(store, "leases") == 1
    assert _count(store, "outbox") == 1 and _count(store, "audit") == 1


def test_lease_token_is_stored_only_as_a_digest(store) -> None:
    """IC-15: the leases table never holds the bearer token."""
    receipt = _claim(store)
    flat = repr(store._read_all("leases")) + repr(store._read_all("outbox")) + repr(store._read_all("audit"))
    assert receipt.lease_token not in flat


def test_unknown_task_is_404(store) -> None:
    """A task that was never declared is a determinate 404 that writes nothing."""
    before = table_snapshot(store, *CLAIM_TABLES)
    refusal = _refusal(store, request(task_id="task-404"))
    assert (refusal.code, refusal.status) == ("task.unknown", 404)
    assert table_snapshot(store, *CLAIM_TABLES) == before


def test_second_claim_conflicts_and_changes_nothing(store) -> None:
    """IC-11: the loser receives a conflict, never an ambiguous success."""
    _claim(store)
    before = table_snapshot(store, *ALL_TABLES)
    refusal = _refusal(store, request(principal="agent-b", idempotency_key="k-b"), "agent-b")
    assert (refusal.code, refusal.status) == ("task.already_claimed", 409)
    assert table_snapshot(store, *ALL_TABLES) == before


def test_stale_expected_version_is_409_and_state_unchanged(store) -> None:
    """IC-14 / section 10.1: a stale expected_task_version cannot mutate state."""
    before = table_snapshot(store, *ALL_TABLES)
    refusal = _refusal(store, request(expected_task_version=7))
    assert (refusal.code, refusal.status) == ("task.version_conflict", 409)
    assert table_snapshot(store, *ALL_TABLES) == before


@pytest.mark.parametrize(
    "overrides", [{"source_ref": "refs/heads/other"}, {"expected_base_sha": "1" * 40}]
)
def test_source_line_mismatch_is_refused(store, overrides) -> None:
    """IC-19: a stale source line cannot claim."""
    before = table_snapshot(store, *ALL_TABLES)
    assert _refusal(store, request(**overrides)).code == "task.source_mismatch"
    assert table_snapshot(store, *ALL_TABLES) == before


def test_admission_must_match_the_request_principal(store) -> None:
    """The store never applies a request under another principal's admission."""
    with pytest.raises(ClaimRefused) as caught:
        store.apply_admitted(request(), Admission(principal_id="agent-b"))
    assert (caught.value.code, caught.value.status) == ("capability.principal_mismatch", 403)


def test_admission_expired_at_lock_time_is_refused_and_preserves_clock_highwater(store, clock) -> None:
    """If capability expiry elapses before or during store lock, claim is refused and clock highwater is kept."""
    expiry = clock.now + timedelta(seconds=5)
    admission = Admission(principal_id="agent-a", expires_at=expiry)

    # Store clock advances past expiry before lock/transaction time
    clock.now = expiry + timedelta(seconds=1)

    with pytest.raises(ClaimRefused) as caught:
        store.apply_admitted(request(), admission)
    assert (caught.value.code, caught.value.status) == ("capability.expired", 401)

    # Task remains unclaimed
    assert store.task("task-1").state == "pending"
    # Idempotency table remains empty
    assert _count(store, "idempotency") == 0
    # Clock highwater mark was committed and preserved
    with store._lock:
        row = store._db.execute("SELECT value FROM controller_meta WHERE key = 'clock_highwater'").fetchone()
    assert row is not None and int(row[0]) == store_module.to_micros(clock.now)


# --- idempotency -----------------------------------------------------------------------------


def test_identical_replay_returns_the_original_receipt(store) -> None:
    """IC-13: the same request returns the original result without a second transition."""
    first = _claim(store)
    snapshot = table_snapshot(store, "tasks", "leases", "outbox")
    again = _claim(store)
    assert again.replayed and not first.replayed
    assert (again.receipt_id, again.lease_id, again.lease_token, again.task_version) == (
        first.receipt_id, first.lease_id, first.lease_token, first.task_version,
    )
    assert table_snapshot(store, "tasks", "leases", "outbox") == snapshot


def test_same_key_with_different_content_is_rejected(store) -> None:
    """IC-13: reusing a key with a different digest is refused, not served."""
    _claim(store)
    changed = request(idempotency_key="claim-agent-a", source_ref="refs/heads/other")
    refusal = _refusal(store, changed)
    assert (refusal.code, refusal.status) == ("idempotency.key_reused", 409)


def test_ic12_claim_scope_is_principal_operation_and_key(store) -> None:
    """IC-12: the same key under another principal or operation is a different scope."""
    first = _claim(store)
    other = _refusal(store, request(principal="agent-b", idempotency_key="claim-agent-a"), "agent-b")
    assert other.code == "task.already_claimed"
    released = store.apply_admitted(
        lease_request("release", first, idempotency_key="claim-agent-a"), admitted()
    )
    assert released.operation == "release" and not released.replayed
    tables = {row[0] for row in store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert not any("workflow" in name for name in tables)


def test_refusals_create_no_idempotency_record(store) -> None:
    """Only committed transitions are replayable; a refused request is evaluated afresh."""
    _refusal(store, request(expected_task_version=9, idempotency_key="k-x"))
    assert _count(store, "idempotency") == 0


# --- lease-bound operations ------------------------------------------------------------------


def test_renew_extends_without_changing_version(store, clock) -> None:
    """Renewal extends the one lease and keeps the task version."""
    claim = _claim(store)
    clock.advance(10)
    renewed = store.apply_admitted(lease_request("renew", claim), admitted())
    assert renewed.lease_expires_at == clock.now + timedelta(seconds=30)
    assert renewed.task_version == claim.task_version and renewed.lease_id == claim.lease_id
    assert renewed.lease_token is None


def test_wrong_token_and_wrong_principal_are_403(store) -> None:
    """IC-15: both the authorized principal and the active lease token are required."""
    claim = _claim(store)
    before = table_snapshot(store, *ALL_TABLES)
    bad_token = _refusal(store, lease_request("complete", claim, lease_token="x" * 43))
    assert (bad_token.code, bad_token.status) == ("lease.token_invalid", 403)
    thief = lease_request("complete", claim, principal="agent-b")
    assert _refusal(store, thief, "agent-b").code == "lease.principal_mismatch"
    assert table_snapshot(store, *ALL_TABLES) == before


def test_unknown_or_foreign_lease_is_409(store) -> None:
    """A lease id must name a lease of this task."""
    claim = _claim(store)
    declare(store, "task-2")
    assert _refusal(store, lease_request("renew", claim, lease_id="lease-nope")).code == "lease.unknown"
    foreign = lease_request("renew", claim, task_id="task-2", expected_task_version=1)
    assert _refusal(store, foreign).code == "lease.unknown"


def test_stale_version_on_lease_operation_is_409(store) -> None:
    """IC-14 holds for lease-bound operations too."""
    claim = _claim(store)
    refusal = _refusal(store, lease_request("complete", claim, expected_task_version=1))
    assert refusal.code == "task.version_conflict"


def test_complete_finalizes_once_with_receipt(store) -> None:
    """Completion is immutable, replayable and ends every later lease operation."""
    claim = _claim(store)
    done = store.apply_admitted(lease_request("complete", claim), admitted())
    assert (done.task_state, done.task_version, done.result_digest) == ("completed", 3, RESULT_DIGEST)
    assert store.apply_admitted(lease_request("complete", claim), admitted()).replayed
    late = lease_request("release", claim, expected_task_version=3)
    assert _refusal(store, late).code == "lease.not_active"
    assert _refusal(store, request(idempotency_key="again", expected_task_version=3)).code == "task.not_claimable"
    assert _count(store, "outbox") == 2


def test_release_returns_to_pending_and_fences_the_old_lease(store) -> None:
    """A release bumps the version; the old lease cannot act and a new claim can."""
    claim = _claim(store)
    released = store.apply_admitted(lease_request("release", claim), admitted())
    assert (released.task_state, released.task_version) == ("pending", 3)
    stale = lease_request("complete", claim, expected_task_version=3)
    assert _refusal(store, stale).code == "lease.not_active"
    successor = _claim(store, "agent-b", expected_task_version=3)
    assert successor.task_version == 4 and successor.lease_id != claim.lease_id


def test_fail_records_classified_terminal_failure(store) -> None:
    """A classified failure is terminal for the task."""
    claim = _claim(store)
    failed = store.apply_admitted(lease_request("fail", claim, failure_class="timeout"), admitted())
    assert (failed.task_state, failed.failure_class) == ("failed", "timeout")
    assert store.task("task-1").failure_class == "timeout"
    assert _refusal(store, request(idempotency_key="later", expected_task_version=3)).code == "task.not_claimable"


def test_late_worker_is_refused_once_the_lease_time_passed(store, clock) -> None:
    """IC-15/IC-18: lease expiry is the controller's clock; no sweep is needed to refuse."""
    claim = _claim(store)
    clock.advance(30)
    before = table_snapshot(store, *ALL_TABLES)
    for operation in ("renew", "complete", "release", "fail"):
        refusal = _refusal(store, lease_request(operation, claim))
        assert (refusal.code, refusal.status) == ("lease.expired", 409)
    assert table_snapshot(store, "tasks", "leases", "idempotency", "outbox") == {
        k: v for k, v in before.items() if k in ("tasks", "leases", "idempotency", "outbox")
    }


def test_backward_clock_step_cannot_revive_a_lease(store, clock) -> None:
    """The high-water mark keeps controller time monotonic across clock regressions."""
    claim = _claim(store)
    clock.advance(31)
    _refusal(store, lease_request("renew", claim, idempotency_key="r1"))
    clock.advance(-20)
    assert _refusal(store, lease_request("renew", claim, idempotency_key="r2")).code == "lease.expired"


# --- atomicity -------------------------------------------------------------------------------


def test_failure_inside_the_transaction_commits_nothing(store, monkeypatch) -> None:
    """IC-11: a fault while writing the outbox rolls back the claim, lease and key."""
    before = table_snapshot(store, *ALL_TABLES)

    def explode(*_args, **_kwargs):
        """Simulate a fault while the outbox row is built."""
        raise RuntimeError("outbox fault")

    monkeypatch.setattr(store_module, "build_redacted_payload", explode)
    with pytest.raises(RuntimeError):
        _claim(store)
    assert table_snapshot(store, *ALL_TABLES) == before


def test_busy_database_is_a_determinate_503(tmp_path, clock) -> None:
    """A write lock held elsewhere yields controller.busy with no state change."""
    store = ControllerStore(tmp_path / "state" / "c.db", clock=clock, busy_timeout=0.05)
    declare(store)
    blocker = sqlite3.connect(tmp_path / "state" / "c.db", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        refusal = _refusal(store, request())
        assert (refusal.code, refusal.status) == ("controller.busy", 503)
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert store.task("task-1").state == "pending"
    store.close()


def test_restart_preserves_state_and_never_reissues_an_unexpired_lease(tmp_path, clock) -> None:
    """IC-17: reopening keeps the active lease; another principal still conflicts."""
    first = open_store(tmp_path, clock)
    declare(first)
    claim = _claim(first)
    first.close()
    reopened = open_store(tmp_path, clock)
    assert reopened.task("task-1").state == "claimed"
    assert _refusal(reopened, request(principal="agent-b", idempotency_key="b"), "agent-b").code == "task.already_claimed"
    assert reopened.apply_admitted(lease_request("complete", claim), admitted()).task_state == "completed"
    reopened.close()
