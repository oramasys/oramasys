"""E1 C2 Part 3 Sections 1-2 (consumer): verify, ingest, persist and apply revocation and cascade.

The vendored file is Phylax's ``docs/vectors/dispatch-events-v1.json`` byte for byte. Expected
digests come from a standard-library oracle, not from the consumer wire module under test.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from orama.graph.dispatch_attempts import (
    AUTHORIZATION_RULES,
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


@pytest.fixture
def store(tmp_path: Path) -> SqliteAttemptStore:
    """Return an ungoverned store with the vector attempt created."""
    s = SqliteAttemptStore(db_path(tmp_path))
    s.create_attempt(ATTEMPT, GRANT, RESERVATION)
    return s


def authorize(
    s: SqliteAttemptStore, flow: Flow, approval_ref: str | None = None, *, scope: EffectScope | None = None
) -> None:
    """Ingest the flow's prefix and run Step 4.3."""
    s.ingest_events(ISSUER, flow.chain, FakeVerifier())
    s.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, NOW, verifier=FakeVerifier(), gates=FakeGates(),
        revocations=FakeRevocations(), issuer_id=ISSUER, expected=EXPECTED, scope=scope,
        approval_ref=approval_ref,
    )


def refused(
    s: SqliteAttemptStore, path: Path, flow: Flow, approval_ref: str | None = None, **kwargs: Any
) -> str:
    """Require a Rule 4 refusal that writes nothing beyond the ingested prefix; return the reason."""
    s.ingest_events(ISSUER, flow.chain, FakeVerifier())
    before = snapshot(path)
    with pytest.raises(AuthorizationRefused) as excinfo:
        authorize(s, flow, approval_ref, **kwargs)
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


def test_rule4_refuses_approval_revocation(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """A revocation of the grant's approval refuses dispatch when the caller names that approval."""
    flow = flow_after([revoke("approval", APPROVAL)])
    assert refused(store, db_path(tmp_path), flow, APPROVAL) == "approval_revoked"


def test_rule4_refuses_issuer_revocation(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """A revocation of this issuer refuses every grant from it."""
    assert refused(store, db_path(tmp_path), flow_after([revoke("issuer", ISSUER)])) == "issuer_revoked"


def test_rule4_refuses_cascade_listed_grant(store: SqliteAttemptStore, tmp_path: Path) -> None:
    """A cascade that lists the grant refuses it even when no approval_ref is supplied."""
    flow = flow_after([cascade(APPROVAL, ["a-first", GRANT, "z-last"])])
    assert refused(store, db_path(tmp_path), flow) == "cascade_listed"


def test_rule4_ignores_unrelated_facts(store: SqliteAttemptStore) -> None:
    """Other grants, approvals and issuers, and an approval the caller did not name, do not refuse."""
    flow = flow_after([
        revoke("grant", "grant-other"), revoke("approval", "approval-other"),
        revoke("issuer", "issuer-other"), revoke("approval", APPROVAL),
        cascade(APPROVAL, ["grant-other", "grant-zzz"]),
    ])

    authorize(store, flow, approval_ref="approval-unrelated")

    assert store.outbox_row(ATTEMPT) is not None


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


def test_approval_ref_must_be_canonical_text_when_given(store: SqliteAttemptStore) -> None:
    """A blank approval_ref fails closed instead of silently matching nothing."""
    with pytest.raises(ValueError):
        authorize(store, flow_after([revoke("grant", "grant-other")]), approval_ref=" ")


def test_no_new_authorization_rules() -> None:
    """Locked rule 8: the closed rule set is unchanged; new reasons are consumer-local."""
    assert AUTHORIZATION_RULES == frozenset({"rule1", "rule2", "rule3", "rule4", "rule5", "rule6"})

