"""C3c: doc 68 section 10/10.1 and IC-1..IC-29 conformance for this slice.

Each IC that this slice reaches has a test here or in a sibling module; the contract
document's section 9 maps every IC to its evidence or records it as out of slice.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import textwrap
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

import orama.orchestrator_controller as controller_package
from orama.orchestrator_controller.outbox import OutboxPublisher
from orama.orchestrator_controller.refusals import REFUSAL_STATUS, ClaimRefused
from orama.orchestrator_controller.service import ControllerService
from orama.orchestrator_controller.store import ControllerStore

from .doubles import ATTESTED, AUDIENCE, Grant, GrantTableVerifier, TransportDouble
from .support import (
    ALL_TABLES,
    BASE_SHA,
    START,
    FakeClock,
    declare,
    open_store,
    raw,
    table_snapshot,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_DIR = Path(controller_package.__file__).parent
ALL_OPS = frozenset({"claim", "renew", "complete", "release", "fail"})
RACE_VOCABULARY = {"task.already_claimed", "task.version_conflict", "controller.busy"}
WORKERS = [f"worker-{index}" for index in range(10)]


def _grants(*principals: str, tasks: frozenset[str] = frozenset({"task-1"})) -> GrantTableVerifier:
    """A grant table giving each principal every operation on ``tasks`` for an hour."""
    return GrantTableVerifier({
        principal: Grant(ALL_OPS, tasks, START + timedelta(hours=1), proof=f"proof-{principal}")
        for principal in principals
    })


def _service(store: ControllerStore, clock: FakeClock, verifier: GrantTableVerifier) -> ControllerService:
    """Compose a service with an accepting transport double and ``verifier``."""
    return ControllerService(store, audience=AUDIENCE, clock=clock, capability_verifier=verifier,
                             transport_verifier=TransportDouble())


def _body(principal: str, operation: str = "claim", **overrides) -> dict:
    """A raw request from ``principal`` carrying its own proof."""
    return raw(operation, principal=principal, capability_proof=f"proof-{principal}",
               idempotency_key=f"{operation}-{principal}", **overrides)


def _active_leases(store: ControllerStore) -> list[tuple]:
    """Return every active lease row."""
    return [row for row in store._read_all("leases") if row[7] == "active"]


# --- IC-11 and Part 3 item 5: ten-worker races ------------------------------------------------


def test_ten_worker_race_one_controller(tmp_path) -> None:
    """Ten threads against one controller: exactly one committed claim, losers in vocabulary."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    service = _service(store, clock, _grants(*WORKERS))
    barrier = threading.Barrier(len(WORKERS))
    outcomes: dict[str, str] = {}

    def attempt(worker: str) -> None:
        """Claim after every worker is ready."""
        barrier.wait()
        try:
            outcomes[worker] = service.submit(_body(worker), transport=ATTESTED).task_state
        except ClaimRefused as refusal:
            outcomes[worker] = refusal.code
        except Exception as error:  # noqa: BLE001 - any other outcome must fail the test
            outcomes[worker] = f"error:{type(error).__name__}"

    threads = [threading.Thread(target=attempt, args=(w,)) for w in WORKERS]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert set(outcomes) == set(WORKERS)
    winners = [w for w, outcome in outcomes.items() if outcome == "claimed"]
    assert len(winners) == 1
    assert {o for w, o in outcomes.items() if w not in winners} <= RACE_VOCABULARY
    assert len(_active_leases(store)) == 1 and _active_leases(store)[0][2] == winners[0]
    assert store.task("task-1").version == 2
    store.close()


def test_ten_worker_race_separate_connections(tmp_path) -> None:
    """Ten connections to one database (a misdeployment): still one committed claim."""
    clock = FakeClock()
    stores = [open_store(tmp_path, clock) for _ in WORKERS]
    declare(stores[0])
    barrier = threading.Barrier(len(WORKERS))
    outcomes: dict[str, str] = {}

    def attempt(worker: str, store: ControllerStore) -> None:
        """Claim through this worker's own connection."""
        service = _service(store, clock, _grants(worker))
        barrier.wait()
        try:
            outcomes[worker] = service.submit(_body(worker), transport=ATTESTED).task_state
        except ClaimRefused as refusal:
            outcomes[worker] = refusal.code
        except Exception as error:  # noqa: BLE001 - any other outcome must fail the test
            outcomes[worker] = f"error:{type(error).__name__}"

    threads = [threading.Thread(target=attempt, args=pair) for pair in zip(WORKERS, stores)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert set(outcomes) == set(WORKERS)
    assert list(outcomes.values()).count("claimed") == 1
    assert {o for o in outcomes.values() if o != "claimed"} <= RACE_VOCABULARY
    assert len(_active_leases(stores[0])) == 1
    for store in stores:
        store.close()


_PROCESS_WORKER = textwrap.dedent(
    """
    import json, sys, time
    from datetime import UTC, datetime, timedelta
    from pathlib import Path
    from orama.orchestrator_controller.envelope import ClaimRequest
    from orama.orchestrator_controller.refusals import ClaimRefused
    from orama.orchestrator_controller.store import Admission, ControllerStore

    db, go, ready, worker = sys.argv[1:5]
    store = ControllerStore(db, clock=lambda: datetime.now(UTC), lease_ttl=timedelta(minutes=10))
    body = {"schema_version": "1", "operation": "claim", "task_id": "task-1", "principal": worker,
            "idempotency_key": "claim-" + worker, "expected_task_version": 1,
            "source_ref": "refs/heads/reviewed", "expected_base_sha": sys.argv[5]}
    request = ClaimRequest.from_mapping(body)
    Path(ready).touch()
    deadline = time.monotonic() + 30
    while not Path(go).exists() and time.monotonic() < deadline:
        time.sleep(0.001)
    try:
        outcome = store.apply_admitted(request, Admission(worker)).task_state
    except ClaimRefused as refusal:
        outcome = refusal.code
    print(json.dumps({"worker": worker, "outcome": outcome}))
    """
)


def test_ten_worker_race_isolated_processes(tmp_path) -> None:
    """Ten isolated processes race one database: one committed claim, outcomes in vocabulary."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    db = tmp_path / "state" / "controller.db"
    go = tmp_path / "go"
    procs = []
    for worker in WORKERS:
        ready = tmp_path / f"ready-{worker}"
        procs.append((ready, subprocess.Popen(
            [sys.executable, "-c", _PROCESS_WORKER, str(db), str(go), str(ready), worker, BASE_SHA],
            cwd=REPO_ROOT, env={"PYTHONPATH": str(REPO_ROOT / "src")},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )))
    deadline = time.monotonic() + 60
    while not all(ready.exists() for ready, _ in procs) and time.monotonic() < deadline:
        time.sleep(0.01)
    go.touch()
    outcomes = []
    for _, proc in procs:
        out, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err
        outcomes.append(json.loads(out)["outcome"])
    assert len(outcomes) == len(WORKERS)
    assert outcomes.count("claimed") == 1
    assert set(outcomes) - {"claimed"} <= RACE_VOCABULARY
    assert len(_active_leases(store)) == 1
    store.close()


# --- IC-1, IC-26, IC-27 and section 10 isolation ----------------------------------------------


def _imports(path: Path) -> set[str]:
    """Every module imported anywhere in ``path``, including lazy imports."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


def test_ic26_imports_are_stdlib_and_this_package_only() -> None:
    """IC-26: no PT, Phylax, Telos, Core or network import; one same-repository utility."""
    allowed_local = {"orama.graph.private_store"}
    for path in PACKAGE_DIR.glob("*.py"):
        for name in _imports(path):
            root = name.split(".")[0]
            assert (
                root in sys.stdlib_module_names
                or name.startswith("orama.orchestrator_controller")
                or name in allowed_local
            ), (path.name, name)


def test_section10_package_loads_without_v1_or_satellite_runtimes() -> None:
    """The controller imports and runs with no v1 runtime, Phylax, Telos or Core loaded."""
    code = (
        "import sys, orama.orchestrator_controller.service, orama.orchestrator_controller.expiry,"
        " orama.orchestrator_controller.outbox;"
        "bad = sorted(m for m in sys.modules if m.split('.')[0] in"
        " {'orchestrator', 'perpetua_tools', 'phylax', 'telos', 'perpetua_core', 'httpx', 'requests'});"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
                         env={"PYTHONPATH": str(REPO_ROOT / "src")}, check=True)
    assert out.stdout.strip() == "[]"


def test_ic1_only_the_store_and_migrations_write_sql() -> None:
    """IC-1: inside the package, only the store and its migrations issue write statements."""
    writers = set()
    for path in PACKAGE_DIR.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                head = node.value.lstrip().upper()
                if head.startswith(("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "ALTER ", "DROP ")):
                    writers.add(path.name)
    assert writers == {"store.py", "migrations.py"}


def test_ic27_no_other_application_module_uses_the_controller_store() -> None:
    """IC-27: no other ``src/orama`` module imports the controller's store or expiry worker."""
    orama_root = PACKAGE_DIR.parent
    offenders = []
    for path in orama_root.rglob("*.py"):
        if PACKAGE_DIR in path.parents:
            continue
        found = {n for n in _imports(path) if n.startswith("orama.orchestrator_controller")}
        if found:
            offenders.append((path.name, sorted(found)))
    assert offenders == []


# --- IC-2: observations never mutate ---------------------------------------------------------


@pytest.mark.parametrize("observation", [{"availability": "active"}, {"availability": "inactive"},
                                         {"heartbeat": "alive"}])
def test_ic2_observations_leave_every_record_unchanged(tmp_path, observation) -> None:
    """Section 10.1 IC-2: an envelope carrying an observation is refused and changes nothing."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    service = _service(store, clock, _grants("agent-a"))
    claim = service.submit(_body("agent-a"), transport=ATTESTED)
    before = table_snapshot(store, "tasks", "leases", "idempotency", "outbox", "maintenance_owner")
    body = _body("agent-a", "renew", lease_id=claim.lease_id, lease_token=claim.lease_token,
                 expected_task_version=2, **observation)
    with pytest.raises(ClaimRefused) as caught:
        service.submit(body, transport=ATTESTED)
    assert caught.value.status == 400
    assert table_snapshot(store, "tasks", "leases", "idempotency", "outbox", "maintenance_owner") == before
    store.close()


# --- IC-9 (persistence part) and IC-12 ------------------------------------------------------


def test_lineage_is_persisted_when_present_and_never_inferred(tmp_path) -> None:
    """Supplied lineage reaches audit and outbox; absent lineage stays absent."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    service = _service(store, clock, _grants("agent-a"))
    claim = service.submit(_body("agent-a"), transport=ATTESTED)
    service.submit(_body("agent-a", "release", lease_id=claim.lease_id, lease_token=claim.lease_token,
                         expected_task_version=2, lineage={"superseded_ref": "receipt-1"}),
                   transport=ATTESTED)
    audits = store._read_all("audit")
    assert audits[0][5] is None and json.loads(audits[1][5]) == {"superseded_ref": "receipt-1"}
    payloads = [json.loads(row[3]) for row in store._read_all("outbox")]
    assert "lineage" not in payloads[0] and payloads[1]["lineage"] == {"superseded_ref": "receipt-1"}
    store.close()


def test_ic12_claim_key_after_workflow_rerun_stays_in_claim_scope(tmp_path) -> None:
    """Section 10.1 IC-12: a rerun is a new declared task; the old key replays the old receipt."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    tables_before = {r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    service = _service(store, clock, _grants("agent-a", tasks=frozenset({"task-1", "task-1-rerun"})))
    first = service.submit(_body("agent-a"), transport=ATTESTED)
    service.submit(_body("agent-a", "complete", lease_id=first.lease_id, lease_token=first.lease_token,
                         expected_task_version=2), transport=ATTESTED)
    declare(store, "task-1-rerun")
    replay = service.submit(_body("agent-a"), transport=ATTESTED)
    assert replay.replayed and replay.task_id == "task-1" and replay.lease_id == first.lease_id
    assert store.task("task-1-rerun").state == "pending"
    tables_after = {r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables_after == tables_before and not any("workflow" in t for t in tables_after)
    store.close()


# --- IC-17 at the service level --------------------------------------------------------------


def test_ic17_restart_never_reissues_an_unexpired_lease(tmp_path) -> None:
    """Restart keeps the lease: another worker conflicts and the holder can still complete."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    verifier = _grants("agent-a", "agent-b")
    claim = _service(store, clock, verifier).submit(_body("agent-a"), transport=ATTESTED)
    store.close()
    reopened = open_store(tmp_path, clock)
    service = _service(reopened, clock, verifier)
    with pytest.raises(ClaimRefused) as caught:
        service.submit(_body("agent-b"), transport=ATTESTED)
    assert caught.value.code == "task.already_claimed"
    done = service.submit(_body("agent-a", "complete", lease_id=claim.lease_id,
                                lease_token=claim.lease_token, expected_task_version=2), transport=ATTESTED)
    assert done.task_state == "completed"
    reopened.close()


# --- isolated-worker end-to-end flows (doc 68 section 9 step 6) -------------------------------


class IsolatedWorker:
    """A remote worker double: it holds only receipts, never a database path (section 8)."""

    def __init__(self, service: ControllerService, principal: str, checkout_base: str) -> None:
        """Bind the worker to the service API, its identity and its verified checkout base."""
        self.service = service
        self.principal = principal
        self.checkout_base = checkout_base

    def run(self, *, drop_first_response: bool = False) -> str:
        """Claim, prove the base locally, then complete or fail; return the final task state."""
        claim_body = _body(self.principal)
        if drop_first_response:
            self.service.submit(claim_body, transport=ATTESTED)  # response lost in transit
        claim = self.service.submit(claim_body, transport=ATTESTED)
        lease = {"lease_id": claim.lease_id, "lease_token": claim.lease_token,
                 "expected_task_version": claim.task_version}
        if self.checkout_base != BASE_SHA:
            outcome = self.service.submit(_body(self.principal, "fail", failure_class="source_mismatch",
                                                **lease), transport=ATTESTED)
        else:
            outcome = self.service.submit(_body(self.principal, "complete", **lease), transport=ATTESTED)
        return outcome.task_state


def test_isolated_worker_completes_with_a_verified_base(tmp_path) -> None:
    """Happy path: receipt-driven claim and completion, two redacted events published."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    service = _service(store, clock, _grants("agent-a"))
    assert IsolatedWorker(service, "agent-a", BASE_SHA).run() == "completed"
    events = []
    OutboxPublisher(store, type("Sink", (), {"publish": lambda self, e: events.append(e)})()).publish_pending()
    assert [e.kind for e in events] == ["claim.claimed", "claim.completed"]
    store.close()


def test_isolated_worker_source_mismatch_fails_closed(tmp_path) -> None:
    """A worker whose checkout base differs records a classified failure, not a completion."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    service = _service(store, clock, _grants("agent-a"))
    assert IsolatedWorker(service, "agent-a", "1" * 40).run() == "failed"
    assert store.task("task-1").failure_class == "source_mismatch"
    store.close()


def test_isolated_worker_timeout_after_dispatch_retries_by_replay(tmp_path) -> None:
    """A lost claim response is retried with the same key: one lease, same token."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store)
    service = _service(store, clock, _grants("agent-a"))
    assert IsolatedWorker(service, "agent-a", BASE_SHA).run(drop_first_response=True) == "completed"
    assert len(store._read_all("leases")) == 1
    store.close()


def test_isolated_worker_lost_connectivity_is_decided_by_expiry(tmp_path) -> None:
    """Section 8 rule 4: a silent worker causes no transition until the controller expires it."""
    clock = FakeClock()
    store = open_store(tmp_path, clock)
    declare(store, effect_class="external")
    service = _service(store, clock, _grants("agent-a"))
    claim = service.submit(_body("agent-a"), transport=ATTESTED)
    clock.now = claim.lease_expires_at - timedelta(microseconds=1)
    assert store.task("task-1").state == "claimed"
    clock.now = claim.lease_expires_at
    epoch = store.acquire_maintenance("sweeper-1", ttl=timedelta(seconds=60))
    store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=timedelta(seconds=60))
    assert store.task("task-1").state == "reconcile"
    store.close()


# --- IC-24 vocabulary is closed ---------------------------------------------------------------


def test_ic24_vocabulary_is_closed_and_has_no_success_code() -> None:
    """Every refusal is a 4xx or 503 and none is a generic success."""
    assert all(status in {400, 401, 403, 404, 409, 503} for status in REFUSAL_STATUS.values())
    with pytest.raises(ValueError):
        ClaimRefused("ok")


def test_every_table_is_accounted_for(tmp_path) -> None:
    """The schema holds exactly the contract's tables, so nothing else can carry claim state."""
    store = open_store(tmp_path, FakeClock())
    names = {r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names - {"sqlite_sequence"} == set(ALL_TABLES) | {"controller_meta", "schema_migrations"}
    store.close()
