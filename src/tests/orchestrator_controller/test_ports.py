"""C3a: Telos/Phylax ports, admission order and fail-closed deny paths (IC-3..IC-6, IC-10, IC-24, IC-25)."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from orama.orchestrator_controller.ports import (
    CapabilityDecision,
    CapabilityQuery,
    DenyAllCapabilityVerifier,
    DenyAllTransportVerifier,
)
from orama.orchestrator_controller.refusals import ClaimRefused
from orama.orchestrator_controller.service import ControllerService
from orama.orchestrator_controller.store import ControllerStore

from .doubles import ATTESTED, AUDIENCE, FixedDecisionVerifier, Grant, GrantTableVerifier, TransportDouble
from .support import ALL_TABLES, START, FakeClock, declare, open_store, raw, table_snapshot

ALL_OPS = frozenset({"claim", "renew", "complete", "release", "fail"})
PROOF = "proof-secret-material"


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


@pytest.fixture
def grants() -> GrantTableVerifier:
    """A grant table where agent-a and agent-b may do everything on task-1 for an hour."""
    expires = START + timedelta(hours=1)
    return GrantTableVerifier({
        "agent-a": Grant(ALL_OPS, frozenset({"task-1"}), expires),
        "agent-b": Grant(ALL_OPS, frozenset({"task-1"}), expires, proof="proof-b"),
    })


def _service(store, clock, verifier, transport=None) -> ControllerService:
    """Compose a service with the given capability verifier and an accepting transport."""
    return ControllerService(
        store, audience=AUDIENCE, clock=clock,
        capability_verifier=verifier, transport_verifier=transport or TransportDouble(),
    )


def _refused(service: ControllerService, body: dict, transport=ATTESTED) -> ClaimRefused:
    """Submit ``body`` expecting a refusal and return it."""
    with pytest.raises(ClaimRefused) as caught:
        service.submit(body, transport=transport)
    return caught.value


def _audit_outcomes(store: ControllerStore) -> list[tuple[str, str, str]]:
    """Return (actor, action, outcome) for every audit row."""
    return [(row[2], row[3], row[4]) for row in store._read_all("audit")]


# --- defaults fail closed --------------------------------------------------------------------


def test_default_ports_deny_everything(store, clock) -> None:
    """With no adapters composed, every request is refused before any lookup."""
    service = ControllerService(store, audience=AUDIENCE, clock=clock)
    assert _refused(service, raw()).code == "transport.unverified"
    service = ControllerService(store, audience=AUDIENCE, clock=clock, transport_verifier=TransportDouble())
    assert _refused(service, raw()).code == "capability.unverifiable"
    assert isinstance(DenyAllCapabilityVerifier().verify(None), CapabilityDecision)  # type: ignore[arg-type]
    assert DenyAllTransportVerifier().verify(ATTESTED).verified is False


def test_success_path_through_both_ports(store, clock, grants) -> None:
    """A verified transport plus a covering capability reaches the store."""
    receipt = _service(store, clock, grants).submit(raw(), transport=ATTESTED)
    assert receipt.task_state == "claimed"
    (query,) = grants.calls
    assert (query.principal_id, query.operation, query.task_id, query.audience) == (
        "agent-a", "claim", "task-1", AUDIENCE,
    )


# --- transport (Telos) -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("transport", "attestation"),
    [(TransportDouble(), None), (TransportDouble(verified=False), ATTESTED),
     (TransportDouble(raises=True), ATTESTED)],
)
def test_unverified_transport_is_401(store, clock, grants, transport, attestation) -> None:
    """Missing, rejected or failing transport attestation refuses before capability."""
    refusal = _refused(_service(store, clock, grants, transport), raw(), transport=attestation)
    assert (refusal.code, refusal.status) == ("transport.unverified", 401)
    assert grants.calls == []


def test_ic6_verified_transport_alone_never_authorizes(store, clock) -> None:
    """IC-6: a verified channel (topology) without a capability is refused."""
    before = table_snapshot(store, "tasks", "leases", "idempotency")
    refusal = _refused(_service(store, clock, GrantTableVerifier()), raw())
    assert (refusal.code, refusal.status) == ("capability.invalid", 401)
    assert table_snapshot(store, "tasks", "leases", "idempotency") == before


def test_ic6_capability_queries_carry_no_topology() -> None:
    """The Phylax port sees principal, operation, task, audience and time; no channel data."""
    assert set(CapabilityQuery.__dataclass_fields__) == {
        "proof", "principal_id", "operation", "task_id", "audience", "at",
    }


# --- capability (Phylax) ---------------------------------------------------------------------


def test_missing_proof_is_401(store, clock, grants) -> None:
    """IC-3: an absent proof refuses ``capability.missing`` without calling the verifier."""
    body = raw()
    del body["capability_proof"]
    assert _refused(_service(store, clock, grants), body).code == "capability.missing"
    assert grants.calls == []


def test_wrong_proof_is_401(store, clock, grants) -> None:
    """IC-3: an invalid proof refuses."""
    refusal = _refused(_service(store, clock, grants), raw(capability_proof="forged"))
    assert (refusal.code, refusal.status) == ("capability.invalid", 401)


def test_revoked_principal_is_401(store, clock, grants) -> None:
    """IC-3/section 10: a revoked principal fails closed."""
    grants.grants["agent-a"].revoked = True
    assert _refused(_service(store, clock, grants), raw()).code == "capability.revoked"


def test_expired_capability_is_401_even_if_the_adapter_allowed(store, clock, grants) -> None:
    """The controller re-checks expiry at its own clock."""
    clock.now = START + timedelta(hours=1)
    refusal = _refused(_service(store, clock, grants), raw())
    assert (refusal.code, refusal.status) == ("capability.expired", 401)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"operations": frozenset({"renew"})}, "capability.insufficient"),
        ({"task_ids": frozenset({"task-9"})}, "capability.insufficient"),
        ({"audience": "another-controller"}, "capability.insufficient"),
    ],
)
def test_insufficient_scope_is_403(store, clock, grants, change, code) -> None:
    """IC-4: the capability must bind operation, task scope and controller audience."""
    for key, value in change.items():
        setattr(grants.grants["agent-a"], key, value)
    refusal = _refused(_service(store, clock, grants), raw())
    assert (refusal.code, refusal.status) == (code, 403)


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        (RuntimeError("issuer down"), "capability.unverifiable"),
        (None, "capability.unverifiable"),
        (CapabilityDecision(allowed=False, denial_code="something.else"), "capability.invalid"),
        (CapabilityDecision(allowed=True, principal_id="agent-z", operations=ALL_OPS,
                            task_ids=frozenset({"task-1"}), audience=AUDIENCE,
                            expires_at=START + timedelta(hours=1)), "capability.principal_mismatch"),
        (CapabilityDecision(allowed=True, principal_id="agent-a", operations=ALL_OPS,
                            task_ids=frozenset({"task-1"}), audience=AUDIENCE,
                            expires_at=None), "capability.unverifiable"),
        (CapabilityDecision(allowed=True, principal_id="agent-a", operations=ALL_OPS,
                            task_ids=frozenset({"task-1"}), audience=AUDIENCE,
                            expires_at=START + timedelta(hours=1), revoked=True), "capability.revoked"),
    ],
)
def test_unusable_adapter_answers_fail_closed(store, clock, answer, code) -> None:
    """A raising, malformed or inconsistent adapter answer never admits a request."""
    before = table_snapshot(store, "tasks", "leases", "idempotency")
    assert _refused(_service(store, clock, FixedDecisionVerifier(answer)), raw()).code == code
    assert table_snapshot(store, "tasks", "leases", "idempotency") == before


def test_ic4_capability_precedes_task_lookup(store, clock, grants, monkeypatch) -> None:
    """IC-4: an unauthorized request for an unknown task is 401, and the store is never reached."""
    calls: list[object] = []
    monkeypatch.setattr(store, "apply_admitted", lambda *args, **kwargs: calls.append(args))
    refusal = _refused(_service(store, clock, grants), raw(task_id="task-404", capability_proof="forged"))
    assert refusal.code == "capability.invalid" and calls == []


def test_ic28_projection_mismatch_precedes_capability(store, clock, grants) -> None:
    """IC-28: a mismatched projection is rejected before the capability port is asked."""
    refusal = _refused(_service(store, clock, grants), raw(actor_principal_id="agent-b"))
    assert refusal.code == "envelope.projection_mismatch" and grants.calls == []


# --- revocation during a lease ---------------------------------------------------------------


def test_revocation_mid_lease_blocks_completion(store, clock, grants) -> None:
    """Every lease operation re-verifies the capability: a revoked holder cannot complete."""
    service = _service(store, clock, grants)
    claim = service.submit(raw(), transport=ATTESTED)
    grants.grants["agent-a"].revoked = True
    body = raw("complete", lease_id=claim.lease_id, lease_token=claim.lease_token, expected_task_version=2)
    assert _refused(service, body).code == "capability.revoked"
    assert store.task("task-1").state == "claimed"


def test_revoked_principal_cannot_read_back_a_replay(store, clock, grants) -> None:
    """Replay passes the ports first: revocation also hides earlier receipts."""
    service = _service(store, clock, grants)
    service.submit(raw(), transport=ATTESTED)
    grants.grants["agent-a"].revoked = True
    assert _refused(service, raw()).code == "capability.revoked"


# --- IC-10 handoff ---------------------------------------------------------------------------


def test_ic10_successor_needs_its_own_capability(store, clock, grants) -> None:
    """IC-10: lineage names the prior holder but grants the successor nothing."""
    service = _service(store, clock, grants)
    claim = service.submit(raw(), transport=ATTESTED)
    service.submit(raw("release", lease_id=claim.lease_id, lease_token=claim.lease_token,
                       expected_task_version=2), transport=ATTESTED)
    lineage = {"on_behalf_of": "agent-a", "prior_agent": "agent-a", "takeover": True}
    handoff = raw(principal="agent-b", capability_proof="proof-b", expected_task_version=3,
                  idempotency_key="handoff", lineage=lineage)
    grants.grants["agent-b"].task_ids = frozenset({"task-9"})
    assert _refused(service, handoff).code == "capability.insufficient"
    grants.grants["agent-b"].task_ids = frozenset({"task-1"})
    receipt = service.submit(handoff, transport=ATTESTED)
    assert receipt.task_state == "claimed"
    audit = store._read_all("audit")[-1]
    assert json.loads(audit[5]) == lineage
    assert json.loads(store._read_all("outbox")[-1][3])["lineage"] == lineage


# --- IC-24 / IC-25 ---------------------------------------------------------------------------


def test_ic24_status_classes(store, clock, grants) -> None:
    """IC-24: 400 invalid, 401/403 unauthorized, 409 conflict; never a generic success."""
    service = _service(store, clock, grants)
    assert _refused(service, raw(schema_version="9")).status == 400
    assert _refused(service, raw(capability_proof="forged")).status == 401
    grants.grants["agent-a"].operations = frozenset({"renew"})
    assert _refused(service, raw()).status == 403
    grants.grants["agent-a"].operations = ALL_OPS
    assert _refused(service, raw(expected_task_version=5)).status == 409


def test_ic25_denials_are_audited_without_proof_material(tmp_path, store, clock, grants) -> None:
    """IC-25: every refusal is audited; no proof bytes reach any table or database file."""
    service = _service(store, clock, grants)
    secret = "forged-proof-material-0123"
    _refused(service, raw(capability_proof=secret))
    grants.grants["agent-a"].revoked = True
    _refused(service, raw(idempotency_key="k2"))
    _refused(service, raw(principal="not a principal"))
    _refused(service, raw(), transport=None)
    assert _audit_outcomes(store) == [
        ("agent-a", "claim", "refused:capability.invalid"),
        ("agent-a", "claim", "refused:capability.revoked"),
        ("unknown", "claim", "refused:envelope.invalid"),
        ("agent-a", "claim", "refused:transport.unverified"),
    ]
    blob = repr(table_snapshot(store, *ALL_TABLES))
    assert secret not in blob and PROOF not in blob
    for path in Path(tmp_path / "state").iterdir():
        data = path.read_bytes()
        assert secret.encode() not in data and PROOF.encode() not in data


def test_refusal_messages_carry_only_the_code(store, clock, grants) -> None:
    """A refusal's text is its code; no request content travels with it."""
    refusal = _refused(_service(store, clock, grants), raw(capability_proof="forged-xyz"))
    assert str(refusal) == "capability.invalid"


def test_service_requires_an_opaque_audience(store, clock) -> None:
    """The controller audience is an opaque identifier."""
    with pytest.raises(ValueError):
        ControllerService(store, audience="/controller", clock=clock)
