"""C3b: transactional outbox, redaction before egress and delivery safety (IC-5, IC-17, IC-21..IC-23)."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from orama.orchestrator_controller import outbox as outbox_module
from orama.orchestrator_controller.envelope import contains_topology
from orama.orchestrator_controller.outbox import (
    PAYLOAD_ALLOWLIST,
    EgressRefused,
    OutboxEvent,
    OutboxIntegrityError,
    OutboxPublisher,
    assert_egress_safe,
)
from orama.orchestrator_controller.refusals import ClaimRefused
from orama.orchestrator_controller.service import ControllerService
from orama.orchestrator_controller.store import ControllerStore

from .doubles import ATTESTED, AUDIENCE, Grant, GrantTableVerifier, TransportDouble
from .support import (
    ALL_TABLES,
    CLAIM_TABLES,
    START,
    FakeClock,
    admitted,
    declare,
    lease_request,
    open_store,
    raw,
    request,
    table_snapshot,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
OWNER_TTL = timedelta(seconds=60)


@dataclass
class RecordingSink:
    """An event sink double that records deliveries and can fail on demand."""

    delivered: list[OutboxEvent] = field(default_factory=list)
    fail_on: set[str] = field(default_factory=set)

    def publish(self, event: OutboxEvent) -> None:
        """Record ``event`` or raise when its id is configured to fail."""
        if event.event_id in self.fail_on:
            raise ConnectionError("sink unavailable")
        self.delivered.append(event)


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


def _claim(store: ControllerStore, **overrides):
    """Claim task-1 as agent-a."""
    return store.apply_admitted(request(**overrides), admitted())


def _payloads(store: ControllerStore) -> list[dict]:
    """Return every outbox payload in sequence order."""
    return [json.loads(row[3]) for row in store._read_all("outbox")]


# --- redaction -------------------------------------------------------------------------------


def test_ic21_payloads_are_allowlisted(store) -> None:
    """IC-21: no proof, token, principal, source line or digest of private data is emitted."""
    claim = _claim(store, lineage={"on_behalf_of": "agent-z"})
    (payload,) = _payloads(store)
    assert set(payload) <= set(PAYLOAD_ALLOWLIST)
    assert payload["lineage"] == {"on_behalf_of": "agent-z"}
    text = json.dumps(payload)
    for secret in (claim.lease_token, "proof-secret-material", "agent-a", "refs/heads/reviewed"):
        assert secret not in text


def test_outbox_row_and_audit_row_share_the_event(store) -> None:
    """The state change, audit and outbox rows commit together and correlate by event id."""
    _claim(store)
    (audit,) = store._read_all("audit")
    (row,) = store._read_all("outbox")
    assert audit[1] == row[1]


@pytest.mark.parametrize(
    "value",
    ["/opt/x", "~/x", "C:\\x", "x\\y", "10.0.0.7", "box:8080", "fe80::1", "localhost",
     "build.local", "nas.lan", "svc.internal", "router.home"],
)
def test_ic22_topology_fragments_are_detected(value) -> None:
    """IC-22: paths, IP literals, host:port and local hostnames are recognized."""
    assert contains_topology(value)
    with pytest.raises(EgressRefused):
        assert_egress_safe({"task_id": value})
    with pytest.raises(EgressRefused):
        assert_egress_safe({"lineage": {"prior_agent": value}})


@pytest.mark.parametrize("value", ["task-1", "lease-0123abcd", "claim.claimed", "agent_7", "v1.2"])
def test_ordinary_opaque_values_pass_the_scan(value) -> None:
    """Opaque identifiers and event kinds are not false positives."""
    assert not contains_topology(value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [("task_id", "build.local"), ("principal", "10.1.2.3"), ("idempotency_key", "localhost"),
     ("lineage", {"prior_agent": "nas.lan"})],
)
def test_ic22_topology_in_identifiers_is_refused_at_intake(field_name, value) -> None:
    """Topology-shaped identifiers never enter the store, so they cannot reach egress."""
    from orama.orchestrator_controller.envelope import ClaimRequest

    with pytest.raises(ClaimRefused) as caught:
        ClaimRequest.from_mapping(raw(**{field_name: value}))
    assert caught.value.code == "envelope.invalid"


def test_egress_scan_failure_aborts_the_transition(store, monkeypatch) -> None:
    """A payload that fails the scan rolls back the whole state change."""
    before = table_snapshot(store, *ALL_TABLES)

    def refuse(_payload) -> None:
        raise EgressRefused("forced")

    monkeypatch.setattr(outbox_module, "assert_egress_safe", refuse)
    with pytest.raises(EgressRefused):
        _claim(store)
    assert table_snapshot(store, *ALL_TABLES) == before


def test_ic22_every_emitted_artifact_is_clean(store, clock) -> None:
    """Section 10.1 IC-22: scan receipts, audit rows and events from a full lifecycle."""
    declare(store, "task-2", effect_class="external")
    receipts = []
    claim = _claim(store)
    receipts.append(claim)
    receipts.append(store.apply_admitted(lease_request("renew", claim), admitted()))
    receipts.append(store.apply_admitted(lease_request("release", claim), admitted()))
    again = store.apply_admitted(request(expected_task_version=3, idempotency_key="k2"), admitted())
    receipts.append(again)
    receipts.append(store.apply_admitted(lease_request("fail", again, failure_class="abandoned"), admitted()))
    other = store.apply_admitted(request(task_id="task-2", idempotency_key="k3"), admitted())
    epoch = store.acquire_maintenance("sweeper-1", ttl=OWNER_TTL)
    clock.now = other.lease_expires_at
    store.recover_expired("sweeper-1", epoch, limit=10, owner_ttl=OWNER_TTL)
    for receipt in receipts:
        body = json.loads(receipt.to_json())
        body.pop("lease_token")
        assert_egress_safe(body)
    for payload in _payloads(store):
        assert_egress_safe(payload)
    for row in store._read_all("audit"):
        assert not any(isinstance(value, str) and contains_topology(value) for value in row)
    assert len(_payloads(store)) == 6


# --- publisher -------------------------------------------------------------------------------


def test_publisher_delivers_in_sequence_and_marks_published(store) -> None:
    """Delivery is in sequence order; a published row is not delivered again."""
    claim = _claim(store)
    store.apply_admitted(lease_request("complete", claim), admitted())
    sink = RecordingSink()
    publisher = OutboxPublisher(store, sink)
    assert publisher.publish_pending(limit=10).delivered == 2
    assert [event.kind for event in sink.delivered] == ["claim.claimed", "claim.completed"]
    assert [event.sequence for event in sink.delivered] == sorted(e.sequence for e in sink.delivered)
    assert publisher.publish_pending(limit=10).delivered == 0
    assert all(row[7] is not None for row in store._read_all("outbox"))


def test_publish_does_not_touch_claim_authority(store) -> None:
    """Publishing and marking change only ``outbox`` delivery columns."""
    _claim(store)
    before = table_snapshot(store, *CLAIM_TABLES, "audit")
    OutboxPublisher(store, RecordingSink()).publish_pending(limit=10)
    assert table_snapshot(store, *CLAIM_TABLES, "audit") == before


def test_sink_failure_keeps_the_row_pending_and_stops(store) -> None:
    """A failing sink leaves the event and later events pending, preserving order."""
    claim = _claim(store)
    store.apply_admitted(lease_request("release", claim), admitted())
    first_id = store._read_all("outbox")[0][1]
    sink = RecordingSink(fail_on={first_id})
    report = OutboxPublisher(store, sink).publish_pending(limit=10)
    assert (report.delivered, report.failed_event_id) == (0, first_id)
    assert sink.delivered == []
    assert store._read_all("outbox")[0][8] == 1
    sink.fail_on.clear()
    assert OutboxPublisher(store, sink).publish_pending(limit=10).delivered == 2


def test_crash_between_send_and_mark_redelivers_the_same_event(tmp_path, clock, monkeypatch) -> None:
    """At-least-once: a lost mark causes a duplicate with the same id, deduplicated downstream."""
    store = open_store(tmp_path, clock)
    declare(store)
    _claim(store)
    sink = RecordingSink()

    def lost_mark(_event_id: str) -> bool:
        raise RuntimeError("process died before mark")

    monkeypatch.setattr(store, "mark_published", lost_mark)
    with pytest.raises(RuntimeError):
        OutboxPublisher(store, sink).publish_pending(limit=10)
    store.close()
    reopened = open_store(tmp_path, clock)
    OutboxPublisher(reopened, sink).publish_pending(limit=10)
    ids = [event.event_id for event in sink.delivered]
    assert len(ids) == 2 and len(set(ids)) == 1
    assert reopened.task("task-1").state == "claimed"
    reopened.close()


def test_tampered_payload_is_not_delivered(store) -> None:
    """IC-23 (partial): a payload whose digest no longer matches is refused, not sent."""
    _claim(store)
    store._db.execute("UPDATE outbox SET redacted_payload = '{\"kind\":\"claim.completed\"}'")
    sink = RecordingSink()
    with pytest.raises(OutboxIntegrityError):
        OutboxPublisher(store, sink).publish_pending(limit=10)
    assert sink.delivered == [] and store._read_all("outbox")[0][7] is None


@pytest.mark.parametrize("limit", [0, True, 10_001])
def test_publish_limit_is_bounded(store, limit) -> None:
    """Each publish pass is bounded."""
    with pytest.raises(ValueError):
        OutboxPublisher(store, RecordingSink()).publish_pending(limit=limit)


# --- IC-5: gossip is never a second writer ---------------------------------------------------


def test_ic5_duplicate_and_reordered_marks_cannot_mutate_claims(store) -> None:
    """Re-marking, reordering and unknown ids touch nothing but delivery bookkeeping."""
    claim = _claim(store)
    store.apply_admitted(lease_request("release", claim), admitted())
    first, second = (row[1] for row in store._read_all("outbox"))
    before = table_snapshot(store, *CLAIM_TABLES, "audit")
    assert store.mark_published(second) is True
    assert store.mark_published(first) is True
    assert store.mark_published(second) is False
    assert store.mark_published("event-forged") is False
    assert table_snapshot(store, *CLAIM_TABLES, "audit") == before


def test_ic5_replayed_event_cannot_be_turned_into_a_mutation(store, clock) -> None:
    """A published event lacks proof and lease token, so replaying it as a request is refused."""
    grants = GrantTableVerifier({"agent-a": Grant(frozenset({"claim", "renew", "complete", "release", "fail"}),
                                                  frozenset({"task-1"}), START + timedelta(hours=1))})
    service = ControllerService(store, audience=AUDIENCE, clock=clock, capability_verifier=grants,
                                transport_verifier=TransportDouble())
    service.submit(raw(), transport=ATTESTED)
    sink = RecordingSink()
    OutboxPublisher(store, sink).publish_pending(limit=10)
    (event,) = sink.delivered
    before = table_snapshot(store, *CLAIM_TABLES)
    forged_bodies = [
        dict(event.payload),
        {**raw("complete", lease_id=event.payload["lease_id"], lease_token="x" * 43,
               expected_task_version=event.payload["task_version"]), "capability_proof": "replayed"},
        raw("renew", lease_id=event.payload["lease_id"], lease_token="y" * 43,
            expected_task_version=event.payload["task_version"], principal="agent-b",
            capability_proof="proof-secret-material"),
    ]
    for body in forged_bodies:
        with pytest.raises(ClaimRefused):
            service.submit(body, transport=ATTESTED)
    assert table_snapshot(store, *CLAIM_TABLES) == before


def test_ic5_no_controller_entrypoint_ingests_events() -> None:
    """The only outbox-facing write is ``mark_published``; nothing accepts an event as input."""
    import inspect

    from orama.orchestrator_controller import expiry, service, store as store_module

    for module in (service, store_module, expiry):
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__:
                continue
            for method_name, method in inspect.getmembers(obj, inspect.isfunction):
                params = inspect.signature(method).parameters.values()
                accepted = " ".join(str(param.annotation) for param in params)
                assert "OutboxEvent" not in accepted, (obj.__name__, method_name)


# --- IC-17: restart and process death --------------------------------------------------------


def test_ic17_pending_outbox_survives_restart(tmp_path, clock) -> None:
    """A row committed before a restart is delivered after it."""
    store = open_store(tmp_path, clock)
    declare(store)
    _claim(store)
    store.close()
    reopened = open_store(tmp_path, clock)
    sink = RecordingSink()
    assert OutboxPublisher(reopened, sink).publish_pending(limit=10).delivered == 1
    reopened.close()


def test_ic17_process_killed_mid_publish(tmp_path) -> None:
    """Kill the controller inside the sink; restart delivers the row and reissues no lease."""
    state = tmp_path / "state"
    script = textwrap.dedent(
        f"""
        import os
        from datetime import UTC, datetime, timedelta
        from orama.orchestrator_controller.envelope import ClaimRequest
        from orama.orchestrator_controller.outbox import OutboxPublisher
        from orama.orchestrator_controller.store import Admission, ControllerStore

        store = ControllerStore({str(state / "controller.db")!r}, clock=lambda: datetime.now(UTC),
                                lease_ttl=timedelta(minutes=10))
        store.declare_task("task-1", source_ref="refs/heads/reviewed",
                           expected_base_sha="0123456789abcdef0123456789abcdef01234567",
                           payload_digest="f" * 64)
        body = {{"schema_version": "1", "operation": "claim", "task_id": "task-1",
                 "principal": "agent-a", "idempotency_key": "k1", "expected_task_version": 1,
                 "source_ref": "refs/heads/reviewed",
                 "expected_base_sha": "0123456789abcdef0123456789abcdef01234567"}}
        store.apply_admitted(ClaimRequest.from_mapping(body), Admission("agent-a"))

        class Dying:
            def publish(self, event):
                os._exit(9)

        OutboxPublisher(store, Dying()).publish_pending(limit=10)
        """
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO_ROOT,
                            env={"PYTHONPATH": str(REPO_ROOT / "src")}, capture_output=True, text=True)
    assert result.returncode == 9, result.stderr
    reopened = ControllerStore(state / "controller.db", clock=lambda: datetime.now(UTC),
                               lease_ttl=timedelta(minutes=10))
    sink = RecordingSink()
    assert OutboxPublisher(reopened, sink).publish_pending(limit=10).delivered == 1
    task = reopened.task("task-1")
    assert (task.state, task.version) == ("claimed", 2)
    with pytest.raises(ClaimRefused) as caught:
        reopened.apply_admitted(
            request(principal="agent-b", idempotency_key="k2"), admitted("agent-b")
        )
    assert caught.value.code == "task.already_claimed"
    active = [row for row in reopened._read_all("leases") if row[7] == "active"]
    assert len(active) == 1
    reopened.close()
    db = sqlite3.connect(state / "controller.db")
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    db.close()
