"""C3: the opt-in expiry/release worker, fencing and recovery (IC-15..IC-18, D1)."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from orama.orchestrator_controller.expiry import ExpiryWorker
from orama.orchestrator_controller.refusals import ClaimRefused
from orama.orchestrator_controller.store import ControllerStore

from .support import (
    FakeClock,
    admitted,
    declare,
    lease_request,
    open_store,
    request,
)

OWNER_TTL = timedelta(seconds=60)
REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def clock() -> FakeClock:
    """A fresh controllable clock."""
    return FakeClock()


@pytest.fixture
def store(tmp_path, clock) -> ControllerStore:
    """A store with one declared pure task and a 30 second lease TTL."""
    opened = open_store(tmp_path, clock)
    declare(opened)
    yield opened
    opened.close()


def _claim(store: ControllerStore, principal: str = "agent-a", task_id: str = "task-1", version: int = 1):
    """Claim ``task_id`` as ``principal`` at ``version``."""
    req = request(principal=principal, task_id=task_id, expected_task_version=version,
                  idempotency_key=f"claim-{principal}-{task_id}-{version}")
    return store.apply_admitted(req, admitted(principal))


def _refusal(store: ControllerStore, req, principal: str = "agent-a") -> str:
    """Apply ``req`` expecting a refusal and return its code."""
    with pytest.raises(ClaimRefused) as caught:
        store.apply_admitted(req, admitted(principal))
    return caught.value.code


def _owner(store: ControllerStore, owner_id: str = "sweeper-1") -> int:
    """Acquire maintenance ownership and return the epoch."""
    return store.acquire_maintenance(owner_id, ttl=OWNER_TTL)


def _lease_state(store: ControllerStore, lease_id: str) -> str:
    """Return the persisted state of ``lease_id``."""
    rows = [row for row in store._read_all("leases") if row[0] == lease_id]
    return rows[0][7]


# --- opt-in only -----------------------------------------------------------------------------


def test_importing_the_package_starts_nothing() -> None:
    """No import-time thread, timer or database (Part 3 item 3)."""
    code = (
        "import threading, orama.orchestrator_controller as c;"
        "import orama.orchestrator_controller.expiry, orama.orchestrator_controller.store;"
        "import orama.orchestrator_controller.outbox, orama.orchestrator_controller.service;"
        "import orama.orchestrator_controller.ports;"
        "print(threading.active_count())"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         cwd=REPO_ROOT, env={"PYTHONPATH": str(REPO_ROOT / "src")})
    assert out.stdout.strip() == "1"


def test_no_install_time_entry_point_names_the_controller() -> None:
    """No console script, entry point or plugin hook starts the worker at install time."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "orchestrator_controller" not in text


# --- recovery rule ---------------------------------------------------------------------------


def test_nothing_recovers_before_expiry(store, clock) -> None:
    """A live lease is never recovered; one microsecond before expiry is still live."""
    claim = _claim(store)
    epoch = _owner(store)
    clock.now = claim.lease_expires_at - timedelta(microseconds=1)
    assert store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL) == ()
    assert store.task("task-1").state == "claimed"


def test_expiry_fences_the_old_holder_before_reassignment(store, clock) -> None:
    """D1: expiry bumps the version; the old token is rejected after a new claim."""
    old = _claim(store)
    epoch = _owner(store)
    clock.now = old.lease_expires_at
    (receipt,) = store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)
    assert (receipt.task_id, receipt.lease_id, receipt.disposition, receipt.task_version) == (
        "task-1", old.lease_id, "pending", 3,
    )
    assert _lease_state(store, old.lease_id) == "expired"
    new = _claim(store, "agent-b", version=3)
    for operation in ("renew", "complete", "release", "fail"):
        code = _refusal(store, lease_request(operation, old, expected_task_version=4))
        assert code == "lease.not_active"
    done = store.apply_admitted(lease_request("complete", new, principal="agent-b"), admitted("agent-b"))
    assert done.task_state == "completed"


def test_partitioned_worker_cannot_complete_after_fence(store, clock) -> None:
    """A late worker's replayed claim receipt grants nothing once it was fenced."""
    old = _claim(store)
    epoch = _owner(store)
    clock.now = old.lease_expires_at + timedelta(seconds=5)
    store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)
    _claim(store, "agent-b", version=3)
    replay = _claim(store)
    assert replay.replayed and replay.lease_id == old.lease_id
    assert _refusal(store, lease_request("complete", replay, expected_task_version=4)) == "lease.not_active"
    assert store.task("task-1").state == "claimed"


def test_external_effects_are_held_for_reconciliation(tmp_path, clock) -> None:
    """IC-16: an expired lease on an effectful task is never reissued nor reported as success."""
    store = open_store(tmp_path, clock)
    declare(store, "task-x", effect_class="external")
    claim = _claim(store, task_id="task-x")
    epoch = _owner(store)
    clock.now = claim.lease_expires_at
    (receipt,) = store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)
    assert receipt.disposition == "reconcile"
    task = store.task("task-x")
    assert (task.state, task.result_digest) == ("reconcile", None)
    assert _refusal(store, request(task_id="task-x", expected_task_version=3, idempotency_key="again"),
                    ) == "task.not_claimable"
    payload = json.loads(store._read_all("outbox")[-1][3])
    assert payload["kind"] == "claim.expired" and payload["disposition"] == "reconcile"
    store.close()


def test_sweeps_are_bounded_and_duplicate_sweeps_are_idempotent(store, clock) -> None:
    """Each sweep handles at most ``limit`` leases; a repeated sweep finds nothing."""
    for index in range(5):
        declare(store, f"task-{index + 10}")
        _claim(store, task_id=f"task-{index + 10}")
    epoch = _owner(store)
    clock.advance(31)
    sizes = [len(store.recover_expired("sweeper-1", epoch, limit=2, owner_ttl=OWNER_TTL)) for _ in range(4)]
    assert sizes == [2, 2, 1, 0]
    assert store.recover_expired("sweeper-1", epoch, limit=2, owner_ttl=OWNER_TTL) == ()


def test_recovery_skips_inconsistent_rows_instead_of_guessing(store, clock) -> None:
    """Recovery re-verifies the claim identity and version; a mismatch is left untouched."""
    claim = _claim(store)
    store._db.execute("UPDATE tasks SET version = version + 5 WHERE task_id = 'task-1'")
    epoch = _owner(store)
    clock.now = claim.lease_expires_at
    assert store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL) == ()
    assert _lease_state(store, claim.lease_id) == "active"


@pytest.mark.parametrize("limit", [0, -1, True, 10_001])
def test_limit_is_bounded(store, limit) -> None:
    """The batch size is a positive, bounded integer."""
    epoch = _owner(store)
    with pytest.raises(ValueError):
        store.recover_expired("sweeper-1", epoch, limit=limit, owner_ttl=OWNER_TTL)


# --- renewal racing expiry -------------------------------------------------------------------


def _race(tmp_path: Path, clock: FakeClock, offset_us: int) -> tuple[str, str, str]:
    """Race a renewal against a sweep at ``expires_at + offset_us`` on two connections."""
    holder = open_store(tmp_path, clock, name="race.db")
    sweeper = open_store(tmp_path, clock, name="race.db")
    declare(holder)
    claim = _claim(holder)
    epoch = sweeper.acquire_maintenance("sweeper-1", ttl=OWNER_TTL)
    clock.now = claim.lease_expires_at + timedelta(microseconds=offset_us)
    barrier = threading.Barrier(2)
    outcome: dict[str, str] = {}

    def renew() -> None:
        """Try to renew as the holder."""
        barrier.wait()
        try:
            holder.apply_admitted(lease_request("renew", claim), admitted())
            outcome["renew"] = "renewed"
        except ClaimRefused as refusal:
            outcome["renew"] = refusal.code

    def sweep() -> None:
        """Try to expire as the maintenance owner."""
        barrier.wait()
        recovered = sweeper.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)
        outcome["sweep"] = str(len(recovered))

    threads = [threading.Thread(target=renew), threading.Thread(target=sweep)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    state = _lease_state(holder, claim.lease_id)
    holder.close()
    sweeper.close()
    (tmp_path / "state" / "race.db").unlink()
    for suffix in ("-wal", "-shm"):
        (tmp_path / "state" / f"race.db{suffix}").unlink(missing_ok=True)
    return outcome["renew"], outcome["sweep"], state


@pytest.mark.parametrize("attempt", range(5))
def test_renewal_racing_expiry_is_safe(tmp_path, attempt) -> None:
    """At expiry the renewal always loses; one microsecond before, the sweep always does nothing.

    Which refusal the losing renewal sees depends on commit order, so the assertion checks
    the outcome vocabulary rather than a fixed schedule.
    """
    renew, swept, state = _race(tmp_path, FakeClock(), 0)
    assert renew in {"lease.expired", "lease.not_active"}
    assert (swept, state) == ("1", "expired")
    before_expiry = _race(tmp_path, FakeClock(), -1)
    assert before_expiry == ("renewed", "0", "active")


# --- maintenance ownership -------------------------------------------------------------------


def test_one_owner_per_database(tmp_path, clock) -> None:
    """A second worker on the same database is refused while the first owner is live."""
    first = open_store(tmp_path, clock)
    second = open_store(tmp_path, clock)
    epoch = first.acquire_maintenance("sweeper-1", ttl=OWNER_TTL)
    with pytest.raises(ClaimRefused) as caught:
        second.acquire_maintenance("sweeper-2", ttl=OWNER_TTL)
    assert caught.value.code == "worker.owner_conflict"
    assert first.release_maintenance("sweeper-1", epoch)
    assert second.acquire_maintenance("sweeper-2", ttl=OWNER_TTL) == epoch + 1
    first.close()
    second.close()


def test_crashed_owner_is_fenced_after_its_ttl(store, clock) -> None:
    """A crashed owner's row expires; the successor fences the old epoch."""
    old_epoch = _owner(store, "sweeper-1")
    clock.advance(OWNER_TTL.total_seconds())
    new_epoch = _owner(store, "sweeper-2")
    assert new_epoch == old_epoch + 1
    with pytest.raises(ClaimRefused) as caught:
        store.recover_expired("sweeper-1", old_epoch, limit=10, owner_ttl=OWNER_TTL)
    assert caught.value.code == "worker.fenced"
    assert not store.release_maintenance("sweeper-1", old_epoch)


def test_a_sweep_without_ownership_is_refused(store) -> None:
    """IC-18: recovery is controller-maintenance-only; no owner means no recovery."""
    with pytest.raises(ClaimRefused) as caught:
        store.recover_expired("anyone", 1, limit=10, owner_ttl=OWNER_TTL)
    assert caught.value.code == "worker.fenced"


def test_each_sweep_extends_the_owner_row(store, clock) -> None:
    """A sweeping owner stays the owner; the row expiry moves with each sweep."""
    epoch = _owner(store)
    clock.advance(50)
    store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)
    clock.advance(50)
    store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)


# --- the worker ------------------------------------------------------------------------------


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    """Poll ``predicate`` until it holds or ``timeout`` seconds pass."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def test_worker_explicit_start_status_stop(store, clock) -> None:
    """The worker runs only between explicit start and stop and releases ownership on stop."""
    worker = ExpiryWorker(store, interval=0.01, batch_limit=10, owner_ttl=OWNER_TTL, owner_id="sweeper-w")
    assert worker.status().state == "stopped"
    claim = _claim(store)
    worker.start()
    assert worker.status().state == "running"
    with pytest.raises(RuntimeError):
        worker.start()
    clock.now = claim.lease_expires_at
    assert _wait_for(lambda: worker.status().recovered == 1)
    status = worker.stop(timeout=5)
    assert status.state == "stopped" and status.sweeps >= 1
    assert _owner(store, "sweeper-next") == status.epoch + 1


def test_second_worker_refuses_to_start(tmp_path, clock) -> None:
    """Explicit start fails closed when another owner holds the database."""
    one = open_store(tmp_path, clock)
    two = open_store(tmp_path, clock)
    first = ExpiryWorker(one, interval=0.05, batch_limit=10, owner_ttl=OWNER_TTL)
    second = ExpiryWorker(two, interval=0.05, batch_limit=10, owner_ttl=OWNER_TTL)
    first.start()
    with pytest.raises(ClaimRefused):
        second.start()
    assert second.status().state == "stopped"
    first.stop(timeout=5)
    second.start()
    second.stop(timeout=5)
    one.close()
    two.close()


def test_fenced_worker_stops_itself(tmp_path, store, clock) -> None:
    """A worker whose owner epoch was superseded reports ``fenced`` and stops sweeping."""
    worker = ExpiryWorker(store, interval=0.01, batch_limit=10, owner_ttl=OWNER_TTL, owner_id="sweeper-w")
    worker.start()
    other = sqlite3.connect(tmp_path / "state" / "controller.db", isolation_level=None, timeout=5)
    other.execute("UPDATE maintenance_owner SET owner_id = 'usurper', epoch = epoch + 1")
    other.close()
    assert _wait_for(lambda: worker.status().state == "fenced")
    assert worker.status().last_error_code == "worker.fenced"
    assert worker.stop(timeout=5).state == "fenced"
    assert store._read_all("maintenance_owner")[0][1] == "usurper"


def test_sweep_once_requires_a_started_worker(store) -> None:
    """``sweep_once`` is an explicit call on a started worker only."""
    worker = ExpiryWorker(store, interval=1.0, batch_limit=10, owner_ttl=OWNER_TTL)
    with pytest.raises(RuntimeError):
        worker.sweep_once()


def test_clean_restart_resumes_recovery(tmp_path, clock) -> None:
    """After stop and reopen, a fresh worker recovers what expired while it was down."""
    store = open_store(tmp_path, clock)
    declare(store)
    worker = ExpiryWorker(store, interval=1.0, batch_limit=10, owner_ttl=OWNER_TTL)
    worker.start()
    worker.stop(timeout=5)
    claim = _claim(store)
    store.close()
    clock.now = claim.lease_expires_at + timedelta(seconds=1)
    reopened = open_store(tmp_path, clock)
    restarted = ExpiryWorker(reopened, interval=1.0, batch_limit=10, owner_ttl=OWNER_TTL)
    restarted.start()
    assert [r.lease_id for r in restarted.sweep_once()] == [claim.lease_id]
    assert restarted.sweep_once() == ()
    restarted.stop(timeout=5)
    reopened.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"interval": 0},
        {"batch_limit": 0},
        {"batch_limit": 10_001},
        {"interval": 40.0, "owner_ttl": timedelta(seconds=60)},
    ],
)
def test_worker_configuration_is_bounded(store, kwargs) -> None:
    """The owner TTL must outlive at least two sweep intervals; sizes are bounded."""
    values = {"interval": 0.1, "batch_limit": 10, "owner_ttl": OWNER_TTL}
    values.update(kwargs)
    with pytest.raises(ValueError):
        ExpiryWorker(store, **values)
