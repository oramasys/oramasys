"""E1 C2 Part 3 Sections 1-2 (consumer): verify, ingest, persist and apply revocation and cascade.

The vendored file is Phylax's ``docs/vectors/dispatch-events-v1.json`` byte for byte. Expected
digests come from a standard-library oracle, not from the consumer wire module under test.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from orama.graph.dispatch_attempts import (
    AUTHORIZATION_RULES,
    AttemptStateError,
    AuthorizationRefused,
    EventRefused,
    SqliteAttemptStore,
)
from orama.graph.dispatch_consumer_wire import (
    GENESIS_EVENT_DIGEST,
    event_digest,
    permit_payload_digest,
)
from orama.graph.effect_proposals import EffectScope
from tests.test_dispatch_attempts import (
    ATTEMPT,
    EXPECTED,
    GRANT,
    ISSUER,
    KEY,
    NOW,
    RESERVATION,
    SIG,
    VECTORS as PERMIT_VECTORS,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    Flow,
    db_path,
    snapshot,
)

EVENT_VECTOR_PATH = Path(__file__).parent / "vectors" / "dispatch-events-v1.json"
EVENT_VECTOR_SHA256 = "ee8075c89d67e4b62fdfcc28070eda163f9d597980e195da9035cfd566fa7b3a"
EVENTS: dict[str, Any] = json.loads(EVENT_VECTOR_PATH.read_text(encoding="utf-8"))
ORACLE_DIGESTS = (
    "8bae016107341fde2b9d9241b1b450b66791018f913a0c62299de8e2bba1302f",
    "d6f41cebbb64a45186ccc4c0bcd1e0dd66ed37f0e0c1689cdcc7cf4856538aed",
    "36469ce85187f112ed8c0953a0ec9ecae7a1ed99075b82aeed7029d6cb90e466",
    "c32f896b4e5c05a24ba137ccde6f2fdd923feaf516d03fd0baee8a0ea09b0858",
)
APPROVAL = "approval-1"
SCOPE = EffectScope("p-1", "g-1", "a" * 64, "b" * 64, "c" * 64, "dest-1")


def oracle_digest(version: int, kind: str, body: dict[str, Any], previous: str) -> str:
    """Digest an event with the standard library only (independent of the module under test)."""
    wrapper = {"body": body, "kind": kind, "previous_event_digest": previous, "version": version}
    text = json.dumps(wrapper, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def revoke(kind: str, subject: str) -> tuple[str, dict[str, Any]]:
    """Return a revocation (kind, body) pair."""
    return "revocation", {"subject_kind": kind, "subject_id": subject}


def cascade(approval: str, grants: list[str]) -> tuple[str, dict[str, Any]]:
    """Return a cascade (kind, body) pair."""
    return "cascade", {"approval_id": approval, "grant_ids": grants, "issuer_authority_version": 1}


def flow_after(prefix: list[tuple[str, dict[str, Any]]]) -> Flow:
    """Chain ``prefix`` events, then a finalization; the permit acknowledges the whole prefix."""
    chain: list[dict[str, Any]] = []
    previous = GENESIS_EVENT_DIGEST
    for version, (kind, body) in enumerate(prefix, start=1):
        digest = oracle_digest(version, kind, body, previous)
        chain.append({
            "version": version, "kind": kind, "body": body, "previous_event_digest": previous,
            "event_digest": digest, "issuer_key_id": KEY, "signature": SIG,
        })
        previous = digest
    r_f = len(prefix) + 1
    fin_id = f"fin-{r_f}"
    fin_digest = oracle_digest(r_f, "finalization", {"finalization_id": fin_id}, previous)
    pbody = deepcopy(PERMIT_VECTORS["permit"]["body"])
    pbody["revocation_version"] = len(prefix)
    permit = {**pbody, "payload_digest": permit_payload_digest(pbody), "issuer_signature": SIG}
    fbody = deepcopy(PERMIT_VECTORS["finalization"]["body"])
    fbody.update(
        permit_digest=permit["payload_digest"], revocation_version=r_f, finalization_id=fin_id,
        revocation_event_digest=fin_digest,
    )
    return Flow(permit, {**fbody, "issuer_signature": SIG}, chain)


def make_store(tmp_path: Path, approval: str | None = "") -> SqliteAttemptStore:
    """Return an ungoverned store whose vector attempt is bound to ``approval``.

    ``""`` is the single-approval binding (the only verifiable value at M2), ``None`` leaves the
    attempt undeclared, and any other value names the grant's second approval.
    """
    s = SqliteAttemptStore(db_path(tmp_path))
    s._create_attempt(ATTEMPT, GRANT, RESERVATION, second_approval_ref=approval)
    return s


@pytest.fixture
def store(tmp_path: Path) -> SqliteAttemptStore:
    """Return an ungoverned store with the vector attempt bound to a single approval."""
    return make_store(tmp_path)


def authorize(s: SqliteAttemptStore, flow: Flow, *, scope: EffectScope | None = None) -> None:
    """Ingest the flow's prefix and run Step 4.3."""
    s.ingest_events(ISSUER, flow.chain, FakeVerifier())
    s.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, NOW, verifier=FakeVerifier(), gates=FakeGates(),
        revocations=FakeRevocations(), issuer_id=ISSUER, expected=EXPECTED, scope=scope,
    )


def refused(s: SqliteAttemptStore, path: Path, flow: Flow, **kwargs: Any) -> str:
    """Require a Rule 4 refusal that writes nothing beyond the ingested prefix; return the reason."""
    s.ingest_events(ISSUER, flow.chain, FakeVerifier())
    before = snapshot(path)
    with pytest.raises(AuthorizationRefused) as excinfo:
        authorize(s, flow, **kwargs)
    assert excinfo.value.rule == "rule4"
    assert snapshot(path) == before, "a refused authorization wrote something"
    return excinfo.value.reason


# ------------------------------------------------------------------ vectors


def test_vendored_vectors_match_the_oracle() -> None:
    """The vendored file is byte-identical to the recorded copy and its digests equal the oracle."""
    assert hashlib.sha256(EVENT_VECTOR_PATH.read_bytes()).hexdigest() == EVENT_VECTOR_SHA256
    assert EVENTS["schema"] == "phylax.issuer-event-bodies.conformance.v1"
    previous = GENESIS_EVENT_DIGEST
    for event, expected in zip(EVENTS["events"], ORACLE_DIGESTS, strict=True):
        assert oracle_digest(event["version"], event["kind"], event["body"], previous) == expected
        assert event_digest(event["version"], event["kind"], event["body"], previous) == expected
        assert event["event_digest"] == expected
        previous = expected


def test_vendored_signed_chain_ingests_and_persists_facts(store: SqliteAttemptStore) -> None:
    """The four signed vector events ingest and are interpreted as authority facts."""
    store.ingest_events(ISSUER, EVENTS["events"], FakeVerifier())

    assert store.acked_through(ISSUER) == 4
    assert store.authority_facts(ISSUER) == {
        "revocations": [
            (1, "grant", "grant-vector-0001"), (2, "approval", "approval-vector-0001"),
            (4, "issuer", "issuer-vector-0001"),
        ],
        "cascades": [(3, "approval-vector-0001", 1, ["grant-vector-0002", "grant-vector-0003"])],
    }


# ------------------------------------------------------------------ ingestion


@pytest.mark.parametrize("case", EVENTS["malformed"], ids=lambda case: case["name"])
def test_ingest_refuses_malformed_bodies(
    store: SqliteAttemptStore, tmp_path: Path, case: dict[str, Any]
) -> None:
    """Every shared malformed body is refused as malformed and nothing is written."""
    event = {**EVENTS["events"][0], "kind": case["kind"], "body": case["body"]}
    before = snapshot(db_path(tmp_path))

    with pytest.raises(EventRefused) as excinfo:
        store.ingest_events(ISSUER, [event], FakeVerifier())

    assert excinfo.value.reason == "malformed"
    assert snapshot(db_path(tmp_path)) == before


def test_malformed_batch_persists_nothing(store: SqliteAttemptStore) -> None:
    """A valid event followed by a malformed one in the same batch leaves no ack and no fact."""
    bad = {**EVENTS["events"][1], "body": {"subject_kind": "approvals", "subject_id": "a"}}

    with pytest.raises(EventRefused):
        store.ingest_events(ISSUER, [EVENTS["events"][0], bad], FakeVerifier())

    assert store.acked_through(ISSUER) == 0
    assert store.authority_facts(ISSUER) == {"revocations": [], "cascades": []}


def test_ingest_persists_facts_with_the_ack(store: SqliteAttemptStore) -> None:
    """Each fact is recorded exactly when its event is acknowledged."""
    flow = flow_after([revoke("grant", "g-x"), cascade(APPROVAL, ["g-a", "g-b"])])
    store.ingest_events(ISSUER, flow.chain[:1], FakeVerifier())

    assert store.authority_facts(ISSUER) == {"revocations": [(1, "grant", "g-x")], "cascades": []}
    store.ingest_events(ISSUER, flow.chain[:2], FakeVerifier())
    assert store.authority_facts(ISSUER)["cascades"] == [(2, APPROVAL, 1, ["g-a", "g-b"])]
    assert store.acked_through(ISSUER) == 2


def test_replayed_batch_is_idempotent(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """Replaying an acknowledged batch changes no row."""
    store.ingest_events(ISSUER, EVENTS["events"], FakeVerifier())
    before = snapshot(db_path(tmp_path))

    store.ingest_events(ISSUER, EVENTS["events"], FakeVerifier())
    store.ingest_events(ISSUER, EVENTS["events"][1:3], FakeVerifier())

    assert snapshot(db_path(tmp_path)) == before


def test_fork_does_not_overwrite_recorded_facts(store: SqliteAttemptStore) -> None:
    """A different body at an acknowledged version is a divergence; the recorded fact stays."""
    store.ingest_events(ISSUER, EVENTS["events"][:1], FakeVerifier())
    body = {"subject_kind": "grant", "subject_id": "grant-other"}
    forked = {
        **EVENTS["events"][0], "body": body,
        "event_digest": oracle_digest(1, "revocation", body, GENESIS_EVENT_DIGEST),
    }

    with pytest.raises(EventRefused) as excinfo:
        store.ingest_events(ISSUER, [forked], FakeVerifier())

    assert excinfo.value.reason == "divergence"
    assert store.authority_facts(ISSUER)["revocations"] == [(1, "grant", "grant-vector-0001")]


# ------------------------------------------------------------------ Rule 4


def test_rule4_refuses_grant_revocation(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """An acknowledged revocation of this grant refuses dispatch."""
    assert refused(store, db_path(tmp_path), flow_after([revoke("grant", GRANT)])) == "grant_revoked"


def test_rule4_refuses_approval_revocation(tmp_path: Path) -> None:
    """A revocation of the approval bound to the attempt refuses dispatch, with no caller input."""
    bound = make_store(tmp_path, APPROVAL)
    flow = flow_after([revoke("approval", APPROVAL)])
    assert refused(bound, db_path(tmp_path), flow) == "approval_revoked"


def test_rule4_refuses_issuer_revocation(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """A revocation of this issuer refuses every grant from it."""
    assert refused(store, db_path(tmp_path), flow_after([revoke("issuer", ISSUER)])) == "issuer_revoked"


def test_rule4_refuses_cascade_listed_grant(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """A cascade that lists the grant refuses it whatever approval the attempt is bound to."""
    flow = flow_after([cascade(APPROVAL, ["a-first", GRANT, "z-last"])])
    assert refused(store, db_path(tmp_path), flow) == "cascade_listed"


def test_rule4_ignores_unrelated_facts(tmp_path: Path) -> None:
    """Other grants, approvals and issuers, and approvals other than the bound one, do not refuse."""
    bound = make_store(tmp_path, "approval-unrelated")
    flow = flow_after([
        revoke("grant", "grant-other"), revoke("approval", "approval-other"),
        revoke("issuer", "issuer-other"), revoke("approval", APPROVAL),
        cascade(APPROVAL, ["grant-other", "grant-zzz"]),
    ])

    authorize(bound, flow)

    assert bound.outbox_row(ATTEMPT) is not None


def test_single_approval_binding_matches_no_approval_revocation(store: SqliteAttemptStore) -> None:
    """The empty binding (single approval) is never matched by an approval revocation."""
    authorize(store, flow_after([revoke("approval", APPROVAL)]))

    assert store.outbox_row(ATTEMPT) is not None


def test_undeclared_binding_fails_closed_on_any_approval_revocation(tmp_path: Path) -> None:
    """An attempt created without a binding cannot be proven unrelated to a revoked approval."""
    undeclared = make_store(tmp_path, None)
    flow = flow_after([revoke("approval", "approval-anything")])

    assert refused(undeclared, db_path(tmp_path), flow) == "approval_undeclared"


def test_undeclared_binding_is_unaffected_without_approval_revocations(tmp_path: Path) -> None:
    """With no approval revoked, an undeclared attempt is judged by the other facts only."""
    undeclared = make_store(tmp_path, None)

    authorize(undeclared, flow_after([revoke("grant", "grant-other")]))

    assert undeclared.outbox_row(ATTEMPT) is not None


def test_cascade_listing_is_reported_before_an_undeclared_binding(tmp_path: Path) -> None:
    """When the grant is cascade-listed, that specific reason wins over the undeclared one."""
    undeclared = make_store(tmp_path, None)
    flow = flow_after([revoke("approval", APPROVAL), cascade(APPROVAL, [GRANT])])

    assert refused(undeclared, db_path(tmp_path), flow) == "cascade_listed"


def test_refusal_leaves_no_intent_outbox_use_or_reservation(tmp_path: Path) -> None:
    """In a governed store a Rule 4 refusal rolls back the reservation consumption with everything else."""
    from tests.test_dispatch_slice2 import harness as governed_harness

    revoked_dir, control_dir = tmp_path / "revoked", tmp_path / "control"
    revoked_dir.mkdir()
    control_dir.mkdir()
    h = governed_harness(revoked_dir)
    flow = flow_after([revoke("grant", GRANT)])
    h.store.ingest_events(ISSUER, flow.chain, FakeVerifier())
    before = snapshot(h.path)

    with pytest.raises(AuthorizationRefused) as excinfo:
        authorize(h.store, flow, scope=SCOPE)

    assert (excinfo.value.rule, excinfo.value.reason) == ("rule4", "grant_revoked")
    after = snapshot(h.path)
    after.pop("clock_high_water", None)
    before.pop("clock_high_water", None)
    assert after == before
    assert not after["dispatch_intents"] and not after["outbox"] and not after["grant_use"]

    control = governed_harness(control_dir)
    clean = flow_after([revoke("grant", "grant-other")])
    authorize(control.store, clean, scope=SCOPE)
    consumed = snapshot(control.path)
    assert consumed["grant_use"] and consumed["outbox"]
    assert consumed["reservations"] != after["reservations"], "control must consume the reservation"


@pytest.mark.parametrize("bad", [" ", "a b", "x" * 1025, "caf\u00e9", 7])
def test_approval_binding_must_be_empty_or_canonical(tmp_path: Path, bad: object) -> None:
    """A blank, spaced, overlong, non-ASCII or non-string binding fails closed at creation."""
    s = SqliteAttemptStore(db_path(tmp_path))
    with pytest.raises(ValueError):
        s._create_attempt(ATTEMPT, GRANT, RESERVATION, second_approval_ref=bad)  # type: ignore[arg-type]
    assert s.get_attempt(ATTEMPT) is None


def test_verified_dispatch_grant_accepts_the_canonical_identifier_boundary(tmp_path: Path) -> None:
    """A verified second approval may be exactly 1024 ASCII bytes, but never 1025."""
    from orama.graph.dispatch_attempts import VerifiedDispatchGrant

    accepted = VerifiedDispatchGrant(GRANT, "a" * 1024)
    store = SqliteAttemptStore(db_path(tmp_path))
    store.create_attempt(ATTEMPT, accepted, RESERVATION)

    assert store.get_attempt(ATTEMPT).second_approval_ref == "a" * 1024
    with pytest.raises(ValueError, match="second_approval_ref"):
        VerifiedDispatchGrant(GRANT, "a" * 1025)


def test_verified_dispatch_grant_copies_its_binding_without_a_raw_override(tmp_path: Path) -> None:
    """The public creation boundary accepts only verified dispatch-grant facts."""
    from orama.graph.dispatch_attempts import VerifiedDispatchGrant

    store = SqliteAttemptStore(db_path(tmp_path))
    store.create_attempt(
        ATTEMPT,
        VerifiedDispatchGrant(GRANT, APPROVAL),
        RESERVATION,
    )

    assert store.get_attempt(ATTEMPT).second_approval_ref == APPROVAL


def test_public_attempt_creation_refuses_a_raw_grant_id(tmp_path: Path) -> None:
    """Production creation cannot accept a caller-supplied approval binding source."""
    store = SqliteAttemptStore(db_path(tmp_path))

    with pytest.raises(TypeError, match="VerifiedDispatchGrant"):
        store.create_attempt(ATTEMPT, GRANT, RESERVATION)  # type: ignore[arg-type]
    assert store.get_attempt(ATTEMPT) is None


def test_approval_binding_is_part_of_the_idempotent_attempt(tmp_path: Path) -> None:
    """Repeating an attempt is a no-op only with the same binding; any change is refused."""
    s = make_store(tmp_path, APPROVAL)
    s._create_attempt(ATTEMPT, GRANT, RESERVATION, second_approval_ref=APPROVAL)
    for other in ("", None, "approval-2"):
        with pytest.raises(AttemptStateError):
            s._create_attempt(ATTEMPT, GRANT, RESERVATION, second_approval_ref=other)
    assert s.get_attempt(ATTEMPT).second_approval_ref == APPROVAL


def test_authorizing_caller_cannot_supply_the_approval_binding() -> None:
    """Step 4.3 takes no approval argument; the binding comes only from the persisted attempt."""
    assert "approval_ref" not in inspect.signature(SqliteAttemptStore.authorize_dispatch).parameters


def test_legacy_attempts_table_gains_an_undeclared_binding(tmp_path: Path) -> None:
    """A store created before the binding column migrates; old rows are undeclared and fail closed."""
    path = db_path(tmp_path)
    SqliteAttemptStore(path).close()
    legacy = sqlite3.connect(path)
    legacy.execute("ALTER TABLE dispatch_attempts DROP COLUMN second_approval_ref")
    legacy.execute(
        "INSERT INTO dispatch_attempts (attempt_id, grant_id, reservation_id, state, created_at)"
        " VALUES (?, ?, ?, 'created', '2026-10-24T00:00:00.000000Z')",
        (ATTEMPT, GRANT, RESERVATION),
    )
    legacy.commit()
    legacy.close()

    migrated = SqliteAttemptStore(path)

    assert migrated.get_attempt(ATTEMPT).second_approval_ref is None
    flow = flow_after([revoke("approval", APPROVAL)])
    assert refused(migrated, path, flow) == "approval_undeclared"


def test_no_new_authorization_rules() -> None:
    """Locked rule 8: the closed rule set is unchanged; new reasons are consumer-local."""
    assert AUTHORIZATION_RULES == frozenset({"rule1", "rule2", "rule3", "rule4", "rule5", "rule6"})

