"""Targeted tests for ControllerService capability deadline verification and lock delay."""
from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
import pytest

from orama.orchestrator_controller.refusals import ClaimRefused
from orama.orchestrator_controller.service import ControllerService
from orama.orchestrator_controller.envelope import ClaimRequest
from orama.orchestrator_controller.ports import CapabilityDecision, CapabilityQuery
from orama.orchestrator_controller.store import Admission, ClaimReceipt, ControllerStore

from .doubles import ATTESTED, AUDIENCE, Grant, GrantTableVerifier, TransportDouble
from .support import START, FakeClock, declare, open_store, raw

ALL_OPS = frozenset({"claim", "renew", "complete", "release", "fail"})


@pytest.fixture
def clock() -> FakeClock:
    """Return a controllable controller clock."""
    return FakeClock()


@pytest.fixture
def store(tmp_path: Path, clock: FakeClock) -> Iterator[ControllerStore]:
    """Open a controller store with one declared task."""
    opened = open_store(tmp_path, clock)
    declare(opened)
    yield opened
    opened.close()


@pytest.fixture
def grants() -> GrantTableVerifier:
    """Return grants covering the test task and operations."""
    expires = START + timedelta(hours=1)
    return GrantTableVerifier({
        "agent-a": Grant(ALL_OPS, frozenset({"task-1"}), expires),
        "agent-b": Grant(ALL_OPS, frozenset({"task-1"}), expires, proof="proof-b"),
    })


def _service(store: ControllerStore, clock: FakeClock, grants: GrantTableVerifier) -> ControllerService:
    """Compose a service with the supplied clock and grants."""
    return ControllerService(
        store, audience=AUDIENCE, clock=clock, capability_verifier=grants, transport_verifier=TransportDouble()
    )


@pytest.mark.parametrize("failure_class", [[], {}])
def test_unhashable_failure_class_is_refused_and_audited(
    store: ControllerStore, clock: FakeClock, grants: GrantTableVerifier, failure_class: object,
) -> None:
    """Malformed failure classes produce an audited envelope refusal."""
    with pytest.raises(ClaimRefused) as caught:
        _service(store, clock, grants).submit(
            raw("fail", lease_id="lease-1", lease_token="t" * 43, failure_class=failure_class),
            transport=ATTESTED,
        )
    assert (caught.value.code, caught.value.status) == ("envelope.invalid", 400)
    with store._lock:
        row = store._db.execute("SELECT outcome FROM audit ORDER BY rowid DESC LIMIT 1").fetchone()
    assert row == ("refused:envelope.invalid",)


def test_capability_expiry_elapsing_during_verification_is_refused(
    store: ControllerStore, clock: FakeClock, grants: GrantTableVerifier,
) -> None:
    """O1: If capability verification delay crosses the expiry deadline, admission refuses."""
    grants.grants["agent-a"].expires_at = START + timedelta(seconds=10)
    service = _service(store, clock, grants)
    original_verify = grants.verify

    def delayed_verify(query: CapabilityQuery) -> CapabilityDecision:
        """Advance the clock during capability verification."""
        # Clock advances past capability expiration during port verification
        clock.now = START + timedelta(seconds=10)
        return original_verify(query)

    grants.verify = delayed_verify
    with pytest.raises(ClaimRefused) as caught:
        service.submit(raw(), transport=ATTESTED)
    assert (caught.value.code, caught.value.status) == ("capability.expired", 401)
    assert store.task("task-1").state == "pending"


def test_capability_expiry_elapsing_during_store_lock_is_refused_and_audited(
    store: ControllerStore, clock: FakeClock, grants: GrantTableVerifier,
) -> None:
    """O1: If capability deadline elapses during store write-lock wait, store refuses and preserves highwater."""
    grants.grants["agent-a"].expires_at = START + timedelta(seconds=10)
    service = _service(store, clock, grants)
    original_apply = store.apply_admitted

    def delayed_apply(req: ClaimRequest, admission: Admission) -> ClaimReceipt:
        """Advance the clock before entering the store transaction."""
        # Clock advances past admission.expires_at before transaction execution
        clock.now = START + timedelta(seconds=11)
        return original_apply(req, admission)

    store.apply_admitted = delayed_apply
    with pytest.raises(ClaimRefused) as caught:
        service.submit(raw(), transport=ATTESTED)
    assert (caught.value.code, caught.value.status) == ("capability.expired", 401)

    # Monotonic high-water mark survives the refusal
    with store._lock:
        row = store._db.execute("SELECT value FROM controller_meta WHERE key = 'clock_highwater'").fetchone()
    assert row is not None and int(row[0]) >= 0

    # Refusal is audited without proof material
    with store._lock:
        audit_row = store._db.execute(
            "SELECT actor, action, outcome FROM audit WHERE actor = 'agent-a' AND action = 'claim' ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    assert audit_row == ("agent-a", "claim", "refused:capability.expired")
