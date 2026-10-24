"""E1 "C2" consumer store: durable attempts, the fence and the step 4.3 transaction.

Real SQLite files in ``tmp_path`` and fake ports. Oramasys has no cryptography: the
fake verifier is the only "signature" logic here and it is injected.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from orama.graph.dispatch_attempts import (
    AUTHORIZATION_RULES,
    AttemptAlreadyCommitted,
    AttemptRecord,
    AttemptStateError,
    AuthorizationRefused,
    EventRefused,
    ExpectedBinding,
    SqliteAttemptStore,
    _check_finalization,
    sender_precondition,
)
from orama.graph.dispatch_consumer_wire import (
    GENESIS_EVENT_DIGEST,
    WireError,
    event_digest,
    finalization_body,
    finalization_digest,
    permit_body,
    permit_payload_digest,
)

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "dispatch-permit-v1.json").read_text(encoding="utf-8")
)
SIG = "A" * 86  # base64url of 64 zero bytes: well-formed, verified only by the fake port
KEY = "phylax-vector-key-1"
ISSUER = "issuer-1"
NOW = datetime(2026, 10, 19, 4, 0, 40, tzinfo=UTC)
ATTEMPT = "attempt-vector-0001"
GRANT = "grant-vector-0001"
RESERVATION = "res-vector-0001"
EXPECTED = ExpectedBinding(
    request_digest="b" * 64, artifact_digest="c" * 64,
    configuration_policy_epoch=3, authority_epoch=5, ledger_store_id="vector-ledger",
)
DIVERGENCE_REFUSALS = {("rule5", "divergence"), ("rule5", "event_digest_mismatch")}
OUTBOX_COLUMNS = (
    "permit_id", "permit_digest", "finalization_digest", "r_p", "r_f", "authority_pair",
    "acked_through",
)


@dataclass
class FakeVerifier:
    """Injected verifier port with per-method switches and call recording."""

    permit_ok: bool = True
    finalization_ok: bool = True
    event_ok: bool = True
    calls: list[str] = field(default_factory=list)

    def verify_permit(self, key_id: str, body: Any, signature: str) -> bool:
        """Record and answer a permit verification."""
        self.calls.append(f"permit:{key_id}")
        return self.permit_ok

    def verify_finalization(self, key_id: str, body: Any, signature: str) -> bool:
        """Record and answer a finalization verification."""
        self.calls.append(f"finalization:{key_id}")
        return self.finalization_ok

    def verify_event(self, key_id: str, digest: str, signature: str) -> bool:
        """Record and answer an event verification."""
        self.calls.append(f"event:{key_id}")
        return self.event_ok


@dataclass
class FakeGates:
    """Consumer gate port: all gates hold unless switched off."""

    ok: bool = True
    seen: list[dict[str, Any]] = field(default_factory=list)

    def check(self, **kwargs: Any) -> bool:
        """Record the call and report the configured outcome."""
        self.seen.append(kwargs)
        return self.ok


@dataclass
class FakeRevocations:
    """Revocation port: a grant or a whole issuer is revoked once added to its set."""

    revoked_grants: set[str] = field(default_factory=set)
    revoked_issuers: set[str] = field(default_factory=set)
    seen: list[tuple[str, str]] = field(default_factory=list)

    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        """Report whether an acknowledged event revokes the grant or the issuer."""
        self.seen.append((grant_id, issuer_id))
        return grant_id in self.revoked_grants or issuer_id in self.revoked_issuers


@dataclass(frozen=True)
class Flow:
    """A self-consistent permit, finalization and issuer chain."""

    permit: dict[str, Any]
    fin: dict[str, Any]
    chain: list[dict[str, Any]]


def make_chain(length: int) -> list[dict[str, Any]]:
    """Build a valid hash-chained list of finalization events from genesis."""
    events: list[dict[str, Any]] = []
    previous = GENESIS_EVENT_DIGEST
    for version in range(1, length + 1):
        body = {"finalization_id": f"fin-{version}"}
        digest = event_digest(version, "finalization", body, previous)
        events.append(
            {
                "version": version, "kind": "finalization", "body": body,
                "previous_event_digest": previous, "event_digest": digest,
                "issuer_key_id": KEY, "signature": SIG,
            }
        )
        previous = digest
    return events


def build_flow(
    r_p: int = 1,
    r_f: int = 2,
    permit_changes: dict[str, Any] | None = None,
    fin_changes: dict[str, Any] | None = None,
) -> Flow:
    """Build a consistent flow, applying changes BEFORE the digests are computed."""
    chain = make_chain(max(r_f, 1))
    pbody = deepcopy(VECTORS["permit"]["body"])
    pbody["revocation_version"] = r_p
    pbody.update(permit_changes or {})
    permit = {**pbody, "payload_digest": permit_payload_digest(pbody), "issuer_signature": SIG}
    fbody = deepcopy(VECTORS["finalization"]["body"])
    fbody.update(
        permit_digest=permit["payload_digest"], revocation_version=r_f,
        finalization_id=f"fin-{r_f}", revocation_event_digest=chain[r_f - 1]["event_digest"],
    )
    fbody.update(fin_changes or {})
    return Flow(permit, {**fbody, "issuer_signature": SIG}, chain)


def vector_flow() -> Flow:
    """Return the vendored Phylax vector as a flow (permit, finalization, events)."""
    return Flow(
        json.loads(VECTORS["permit"]["wire"]),
        json.loads(VECTORS["finalization"]["wire"]),
        VECTORS["events"],
    )


def db_path(tmp_path: Path) -> Path:
    """Return the store file path under a not-yet-created private directory."""
    return tmp_path / "store" / "attempts.db"


def snapshot(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    """Dump every table of the store through an independent connection."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        names = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        return {n: sorted(conn.execute(f"SELECT * FROM {n}").fetchall(), key=repr) for n in names}
    finally:
        conn.close()


@dataclass
class Harness:
    """A store plus its ports, prepared with the attempt and the acknowledged prefix."""

    store: SqliteAttemptStore
    path: Path
    verifier: FakeVerifier
    gates: FakeGates
    revocations: FakeRevocations

    def authorize(self, flow: Flow, now: datetime = NOW, attempt: str = ATTEMPT) -> None:
        """Run step 4.3 for the flow with the default expected binding."""
        self.store.authorize_dispatch(
            attempt, flow.permit, flow.fin, now,
            verifier=self.verifier, gates=self.gates, revocations=self.revocations,
            issuer_id=ISSUER, expected=EXPECTED,
        )

    def ingest(self, events: list[dict[str, Any]]) -> None:
        """Ingest events through the verifier port."""
        self.store.ingest_events(ISSUER, events, self.verifier)

    def refused(self, flow: Flow, now: datetime = NOW) -> AuthorizationRefused:
        """Authorize, require a refusal, prove nothing was written, return the refusal."""
        before = snapshot(self.path)
        with pytest.raises(AuthorizationRefused) as excinfo:
            self.authorize(flow, now)
        refusal = excinfo.value
        assert refusal.rule in AUTHORIZATION_RULES
        after = snapshot(self.path)
        if (refusal.rule, refusal.reason) in DIVERGENCE_REFUSALS:
            before.pop("issuer_divergence")
            after.pop("issuer_divergence")
        assert after == before, "a refused authorization wrote something"
        return refusal

    def refused_rule(self, flow: Flow, now: datetime = NOW) -> str:
        """Authorize, require a refusal, prove nothing was written, return the rule."""
        return self.refused(flow, now).rule


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    """Open a store with the vector attempt created."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path)
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    return Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())


def ready(harness: Harness, flow: Flow, ingested: int | None = None) -> None:
    """Ingest the first ``ingested`` events (default: through R_p) of the flow's chain."""
    count = flow.permit["revocation_version"] if ingested is None else ingested
    if count:
        harness.ingest(flow.chain[:count])


# ---------------------------------------------------------------- happy path


def test_vector_flow_authorizes_and_writes_intent_use_and_outbox(harness: Harness) -> None:
    """The vendored vector authorizes; intent, grant use and a complete outbox row exist."""
    flow = vector_flow()
    ready(harness, flow)

    harness.authorize(flow)

    snap = snapshot(harness.path)
    assert [r[0] for r in snap["grant_use"]] == [GRANT]
    assert len(snap["dispatch_intents"]) == 1
    row = harness.store.outbox_row(ATTEMPT)
    assert row is not None
    assert row["permit_id"] == "permit-vector-0001"
    assert row["permit_digest"] == VECTORS["permit"]["payload_digest"]
    assert row["finalization_digest"] == VECTORS["finalization"]["finalization_digest"]
    assert (row["r_p"], row["r_f"], row["acked_through"]) == (1, 2, 2)
    assert row["authority_pair"] == "3:5"
    assert harness.store.acked_through(ISSUER) == 2
    assert sender_precondition(harness.store, ATTEMPT) is True
    record = harness.store.get_attempt(ATTEMPT)
    assert record is not None and record.state == "authorized"
    assert harness.gates.seen[0]["authority_pair"] == "3:5"


def test_vector_finalization_digest_matches_recomputation() -> None:
    """The finalization digest written to the outbox is the recomputed vector value."""
    fin = vector_flow().fin
    assert finalization_digest(finalization_body(fin)) == (
        VECTORS["finalization"]["finalization_digest"]
    )
    assert permit_payload_digest(permit_body(vector_flow().permit)) == (
        VECTORS["permit"]["payload_digest"]
    )


def test_sender_precondition_false_without_a_complete_outbox_row(harness: Harness) -> None:
    """An attempt with no outbox row, or an incomplete one, can never be sent."""
    assert sender_precondition(harness.store, ATTEMPT) is False
    assert sender_precondition(harness.store, "no-such-attempt") is False
    conn = sqlite3.connect(harness.path)
    conn.execute(
        "INSERT INTO outbox (attempt_id, grant_id, permit_id, permit_digest,"
        " finalization_digest, r_p, r_f, authority_pair, acked_through)"
        " VALUES (?, ?, '', 'd', 'f', 1, 2, '3:5', 2)",
        (ATTEMPT, GRANT),
    )
    conn.commit()
    conn.close()
    assert sender_precondition(harness.store, ATTEMPT) is False


@pytest.mark.parametrize("column", OUTBOX_COLUMNS)
def test_outbox_rejects_null_in_every_required_column(harness: Harness, column: str) -> None:
    """NOT NULL on each outbox column except payload is enforced by the schema itself."""
    values = {
        "permit_id": "p", "permit_digest": "d", "finalization_digest": "f", "r_p": 1,
        "r_f": 2, "authority_pair": "3:5", "acked_through": 2,
    }
    values[column] = None  # type: ignore[assignment]
    conn = sqlite3.connect(harness.path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO outbox (attempt_id, grant_id, permit_id, permit_digest,"
            " finalization_digest, r_p, r_f, authority_pair, acked_through)"
            " VALUES ('a', 'g', :permit_id, :permit_digest, :finalization_digest, :r_p,"
            " :r_f, :authority_pair, :acked_through)",
            values,
        )
    conn.close()


def test_outbox_payload_may_be_null(harness: Harness) -> None:
    """Payload is the one nullable outbox column."""
    conn = sqlite3.connect(harness.path)
    conn.execute(
        "INSERT INTO outbox (attempt_id, grant_id, permit_id, permit_digest,"
        " finalization_digest, r_p, r_f, authority_pair, acked_through, payload)"
        " VALUES ('a', 'g', 'p', 'd', 'f', 1, 2, '3:5', 2, NULL)"
    )
    conn.close()


def test_authorization_rule_set_is_closed() -> None:
    """The refusal rule names are exactly rule1..rule6 and nothing else is accepted."""
    assert AUTHORIZATION_RULES == {f"rule{n}" for n in range(1, 7)}
    with pytest.raises(ValueError):
        AuthorizationRefused("rule7", "x")  # type: ignore[arg-type]


# ---------------------------------------------------------------- rule 1


def test_rule1_refuses_a_bad_permit_signature(harness: Harness) -> None:
    """A permit the verifier port rejects is refused under rule 1."""
    flow = vector_flow()
    ready(harness, flow)
    harness.verifier.permit_ok = False

    assert harness.refused_rule(flow) == "rule1"


def test_rule1_refuses_a_tampered_permit_digest(harness: Harness) -> None:
    """A payload_digest that is not the recomputed digest is refused under rule 1."""
    flow = vector_flow()
    ready(harness, flow)
    bad = Flow({**flow.permit, "payload_digest": "e" * 64}, flow.fin, flow.chain)

    assert harness.refused_rule(bad) == "rule1"


@pytest.mark.parametrize(
    "changes",
    [
        {"reservation_id": "res-other"},
        {"grant_id": "grant-other"},
        {"attempt_id": "attempt-other"},
        {"request_digest": "9" * 64},
        {"artifact_digest": "8" * 64},
        {"authority_epoch": 6},
        {"configuration_policy_epoch": 4},
    ],
)
def test_rule1_refuses_an_unbound_permit(harness: Harness, changes: dict[str, Any]) -> None:
    """A permit for another reservation, request, artifact or authority pair is refused."""
    flow = build_flow(permit_changes=changes)
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule1"


def test_rule1_expiry_is_strict(harness: Harness) -> None:
    """now == expires_at is refused; one microsecond earlier is accepted."""
    flow = vector_flow()
    ready(harness, flow)
    expires = datetime(2026, 10, 19, 4, 1, 31, tzinfo=UTC)

    assert harness.refused_rule(flow, now=expires) == "rule1"
    harness.authorize(flow, now=expires - timedelta(microseconds=1))

    assert sender_precondition(harness.store, ATTEMPT) is True


def test_rule1_replay_of_a_recorded_permit_is_refused(harness: Harness) -> None:
    """Presenting the same permit again after step 4.3 recorded it is refused."""
    flow = vector_flow()
    ready(harness, flow)
    harness.authorize(flow)

    assert harness.refused_rule(flow) == "rule1"


def test_malformed_wire_is_refused_without_writes(harness: Harness) -> None:
    """A permit wire with an extra key is refused under rule 1."""
    flow = vector_flow()
    ready(harness, flow)

    assert harness.refused_rule(Flow({**flow.permit, "x": 1}, flow.fin, flow.chain)) == "rule1"


# ---------------------------------------------------------------- rules 2 and 3


def test_rule2_refuses_when_acked_through_is_below_r_p(harness: Harness) -> None:
    """Nothing acknowledged yet while R_p is 1: refused under rule 2."""
    flow = vector_flow()

    assert harness.refused_rule(flow) == "rule2"


def test_rule2_refuses_a_gapped_acknowledgement(harness: Harness) -> None:
    """Versions 1 and 3 held but not 2: the contiguous mark is 1, so R_p=3 is refused."""
    flow = build_flow(r_p=3, r_f=4)
    conn = sqlite3.connect(harness.path)
    for event in (flow.chain[0], flow.chain[2]):
        conn.execute(
            "INSERT INTO issuer_cascade_ack VALUES (?, ?, ?, 'x')",
            (ISSUER, event["version"], event["event_digest"]),
        )
    conn.commit()
    conn.close()

    assert harness.store.acked_through(ISSUER) == 1
    assert harness.refused_rule(flow) == "rule2"


def test_rule3_refuses_when_r_p_is_below_the_permits_recorded_ack(harness: Harness) -> None:
    """R_p (1) below the permit's recorded consumer_acked_through (2): rule 3."""
    flow = build_flow(r_p=1, r_f=3, permit_changes={"consumer_acked_through": 2})
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule3"


# ---------------------------------------------------------------- rule 4


def test_rule4_refuses_a_revoked_grant(harness: Harness) -> None:
    """An acknowledged revocation of the grant refuses dispatch under rule 4."""
    flow = vector_flow()
    ready(harness, flow)
    harness.revocations.revoked_grants.add(GRANT)

    assert harness.refused_rule(flow) == "rule4"


# ---------------------------------------------------------------- rule 5


def test_rule5_refuses_a_bad_finalization_signature(harness: Harness) -> None:
    """A finalization the verifier port rejects is refused under rule 5."""
    flow = vector_flow()
    ready(harness, flow)
    harness.verifier.finalization_ok = False

    assert harness.refused_rule(flow) == "rule5"


@pytest.mark.parametrize(
    "changes",
    [
        {"permit_id": "permit-other"},
        {"permit_digest": "7" * 64},
        {"attempt_id": "attempt-other"},
        {"reservation_id": "res-other"},
        {"ledger_store_id": "ledger-other"},
        {"authority_epoch": 6},
    ],
)
def test_rule5_refuses_an_unbound_finalization(harness: Harness, changes: dict[str, Any]) -> None:
    """A finalization not bound to this permit, attempt and reservation is refused."""
    flow = build_flow(fin_changes=changes)
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_finalization_expiry_is_strict(harness: Harness) -> None:
    """A finalization with now == expires_at is refused; one microsecond earlier passes."""
    flow = build_flow(fin_changes={"expires_at": "2026-10-19T04:00:40.000000Z"})
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule5"
    harness.authorize(flow, now=NOW - timedelta(microseconds=1))


def test_rule5_refuses_an_already_recorded_finalization(harness: Harness) -> None:
    """A finalization digest already recorded for another intent is refused."""
    flow = vector_flow()
    ready(harness, flow)
    conn = sqlite3.connect(harness.path)
    conn.execute(
        "INSERT INTO dispatch_intents VALUES ('other', 'other-grant', 'other-permit', 'd', ?,"
        " 1, 2, '3:5', 2)",
        (VECTORS["finalization"]["finalization_digest"],),
    )
    conn.commit()
    conn.close()

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_requires_r_f_above_r_p(harness: Harness) -> None:
    """R_f equal to R_p is refused."""
    flow = build_flow(r_p=2, r_f=2, fin_changes={"consumer_acked_through": 1})
    ready(harness, flow, ingested=2)

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_requires_r_f_above_the_finalizations_signed_ack(harness: Harness) -> None:
    """R_f not above the finalization's own consumer_acked_through is refused."""
    flow = build_flow(fin_changes={"consumer_acked_through": 2})
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_requires_acked_through_at_least_r_f_minus_one(harness: Harness) -> None:
    """A gap between the acknowledged mark and R_f - 1 is refused."""
    flow = build_flow(r_p=1, r_f=4)
    ready(harness, flow, ingested=1)

    refusal = harness.refused(flow)
    assert refusal.rule == "rule5"
    assert refusal.reason == "acked_through_below_r_f_minus_1"


def test_rule5_event_digest_must_equal_the_rebuilt_wrapper(harness: Harness) -> None:
    """A revocation_event_digest that is not the wrapper hash is refused."""
    flow = build_flow(fin_changes={"revocation_event_digest": "1" * 64})
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_finalization_id_alone_is_not_the_event_preimage(harness: Harness) -> None:
    """A digest of the bare finalization_id never satisfies the event check."""
    bare = hashlib.sha256(b"fin-2").hexdigest()
    flow = build_flow(fin_changes={"revocation_event_digest": bare})
    ready(harness, flow)

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_refuses_a_version_held_with_a_different_digest(harness: Harness) -> None:
    """Version R_f already stored with another digest is a fork: refused."""
    flow = build_flow()
    ready(harness, flow)
    conn = sqlite3.connect(harness.path)
    conn.execute("INSERT INTO issuer_cascade_ack VALUES (?, 2, ?, 'x')", (ISSUER, "5" * 64))
    conn.commit()
    conn.close()

    assert harness.refused_rule(flow) == "rule5"


def test_rule5_refuses_when_any_divergence_is_recorded(harness: Harness) -> None:
    """A recorded divergence refuses even an otherwise valid finalization."""
    flow = vector_flow()
    ready(harness, flow)
    conn = sqlite3.connect(harness.path)
    conn.execute("INSERT INTO issuer_divergence VALUES (?, 9, 'a', 'b', 'x')", (ISSUER,))
    conn.commit()
    conn.close()

    assert harness.refused_rule(flow) == "rule5"


# ---------------------------------------------------------------- rule 6


def test_rule6_refuses_when_a_consumer_gate_fails(harness: Harness) -> None:
    """A failing role/epoch/ownership/fencing/lease gate refuses under rule 6."""
    flow = vector_flow()
    ready(harness, flow)
    harness.gates.ok = False

    assert harness.refused_rule(flow) == "rule6"


def test_rule6_refuses_a_fenced_attempt(harness: Harness) -> None:
    """A fence created before authorize makes authorize refuse; nothing is written."""
    flow = vector_flow()
    ready(harness, flow)
    harness.store.fence(ATTEMPT)

    assert harness.refused_rule(flow) == "rule6"
    assert sender_precondition(harness.store, ATTEMPT) is False


def test_rule6_refuses_a_consumed_grant_use(harness: Harness) -> None:
    """A grant whose single use is already consumed is refused."""
    flow = vector_flow()
    ready(harness, flow)
    conn = sqlite3.connect(harness.path)
    conn.execute("INSERT INTO grant_use VALUES (?, 'other-attempt', 'x')", (GRANT,))
    conn.commit()
    conn.close()

    assert harness.refused_rule(flow) == "rule6"


def test_rule6_failure_rolls_back_the_event_recorded_by_rule5(harness: Harness) -> None:
    """Event R_f is recorded inside the transaction, so a rule 6 refusal drops it."""
    flow = vector_flow()
    ready(harness, flow)
    harness.gates.ok = False

    harness.refused_rule(flow)

    assert harness.store.acked_through(ISSUER) == 1


def test_a_recorded_unavailable_attempt_cannot_authorize(harness: Harness) -> None:
    """An attempt that ended unavailable is not live for step 4.3."""
    flow = vector_flow()
    ready(harness, flow)
    harness.store.record_unavailable(ATTEMPT)

    assert harness.refused_rule(flow) == "rule6"


def test_unknown_attempt_and_naive_clock_fail_closed(harness: Harness) -> None:
    """An unknown attempt id and a naive now are programming errors, never a permit."""
    flow = vector_flow()
    ready(harness, flow)
    with pytest.raises(ValueError):
        harness.authorize(flow, attempt="nope")
    with pytest.raises(ValueError):
        harness.authorize(flow, now=datetime(2026, 10, 19, 4, 0, 40))


# ---------------------------------------------------------------- fence races


def test_authorize_committed_before_fence_makes_fence_refuse(harness: Harness) -> None:
    """Once step 4.3 committed, fence raises and leaves the attempt unfenced."""
    flow = vector_flow()
    ready(harness, flow)
    harness.authorize(flow)

    with pytest.raises(AttemptAlreadyCommitted):
        harness.store.fence(ATTEMPT)
    record = harness.store.get_attempt(ATTEMPT)
    assert record is not None and record.fenced is False


def test_fence_is_idempotent_before_commit(harness: Harness) -> None:
    """Fencing twice before any commit is fine."""
    harness.store.fence(ATTEMPT)
    harness.store.fence(ATTEMPT)
    record = harness.store.get_attempt(ATTEMPT)
    assert record is not None and record.fenced is True


def test_threaded_race_between_fence_and_authorize_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    """Two store objects on one file: exactly one of fence and authorize wins, 30 times."""
    fence_wins = authorize_wins = 0
    for iteration in range(30):
        path = tmp_path / f"race-{iteration}" / "attempts.db"
        flow = vector_flow()
        setup = SqliteAttemptStore(path)
        setup._create_attempt(ATTEMPT, GRANT, RESERVATION)
        setup.ingest_events(ISSUER, flow.chain[:1], FakeVerifier())
        setup.close()
        fencer, authorizer = SqliteAttemptStore(path), SqliteAttemptStore(path)
        barrier = threading.Barrier(2)
        outcome: dict[str, Any] = {}

        def do_fence() -> None:
            """Fence the attempt once both racers are released."""
            barrier.wait()
            try:
                fencer.fence(ATTEMPT)
                outcome["fence"] = "ok"
            except AttemptAlreadyCommitted:
                outcome["fence"] = "refused"
            except BaseException as error:  # noqa: BLE001 - surfaced by the assertion below
                outcome["fence"] = error

        def do_authorize() -> None:
            """Authorize the attempt once both racers are released."""
            barrier.wait()
            try:
                authorizer.authorize_dispatch(
                    ATTEMPT, flow.permit, flow.fin, NOW, verifier=FakeVerifier(),
                    gates=FakeGates(), revocations=FakeRevocations(), issuer_id=ISSUER,
                    expected=EXPECTED,
                )
                outcome["authorize"] = "ok"
            except AuthorizationRefused as refusal:
                outcome["authorize"] = refusal.rule
            except BaseException as error:  # noqa: BLE001 - surfaced by the assertion below
                outcome["authorize"] = error

        threads = [threading.Thread(target=do_fence), threading.Thread(target=do_authorize)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        fencer.close()
        authorizer.close()

        snap = snapshot(path)
        fenced = snap["dispatch_attempts"][0][4]
        used = len(snap["grant_use"])
        if outcome["fence"] == "ok":
            assert outcome["authorize"] == "rule6", outcome
            assert (fenced, used) == (1, 0), outcome
            fence_wins += 1
        else:
            assert outcome["fence"] == "refused", outcome
            assert outcome["authorize"] == "ok", outcome
            assert (fenced, used) == (0, 1), outcome
            authorize_wins += 1
    assert fence_wins + authorize_wins == 30


# ---------------------------------------------------------------- events / divergence


def test_ingest_records_contiguous_events_and_is_idempotent(harness: Harness) -> None:
    """Valid chained events are recorded; re-ingesting the same ones changes nothing."""
    chain = make_chain(3)
    harness.ingest(chain)
    harness.ingest(chain[:2])

    assert harness.store.acked_through(ISSUER) == 3
    assert not harness.store.is_diverged(ISSUER)


def test_ingest_flags_and_refuses_a_version_with_a_different_digest(harness: Harness) -> None:
    """A stored version re-ingested with another digest: refusal plus a divergence flag."""
    harness.ingest(make_chain(2))
    other = deepcopy(make_chain(2))
    body = {"finalization_id": "fin-FORK"}
    digest = event_digest(2, "finalization", body, other[0]["event_digest"])
    forked = {**other[1], "body": body, "event_digest": digest}

    with pytest.raises(EventRefused) as excinfo:
        harness.ingest([forked])

    assert excinfo.value.reason == "divergence"
    assert harness.store.is_diverged(ISSUER)
    assert harness.store.acked_through(ISSUER) == 2


def test_divergence_makes_a_later_authorize_refuse(harness: Harness) -> None:
    """After a flagged fork, even a fully valid finalization is refused under rule 5."""
    flow = vector_flow()
    ready(harness, flow)
    forked = {
        **flow.chain[0], "body": {"finalization_id": "fin-FORK"},
        "event_digest": event_digest(
            1, "finalization", {"finalization_id": "fin-FORK"}, GENESIS_EVENT_DIGEST
        ),
    }
    with pytest.raises(EventRefused):
        harness.ingest([forked])

    assert harness.refused_rule(flow) == "rule5"


def test_ingest_refuses_without_flagging_a_gap_bad_signature_or_bad_digest(
    harness: Harness,
) -> None:
    """Gap, signature and digest failures are refused and write nothing."""
    chain = make_chain(3)
    before = snapshot(harness.path)
    with pytest.raises(EventRefused, match="gap"):
        harness.ingest([chain[2]])
    harness.verifier.event_ok = False
    with pytest.raises(EventRefused, match="event_signature"):
        harness.ingest(chain[:1])
    harness.verifier.event_ok = True
    with pytest.raises(EventRefused, match="event_digest"):
        harness.ingest([{**chain[0], "event_digest": "3" * 64}])
    with pytest.raises(EventRefused, match="malformed"):
        harness.ingest([{**chain[0], "extra": 1}])

    assert snapshot(harness.path) == before


def test_ingest_flags_a_previous_digest_that_forks_the_stored_chain(harness: Harness) -> None:
    """An event whose previous digest differs from the stored version-1 digest is a fork."""
    harness.ingest(make_chain(1))
    previous = "4" * 64
    body = {"finalization_id": "fin-2"}
    event = {
        "version": 2, "kind": "finalization", "body": body,
        "previous_event_digest": previous,
        "event_digest": event_digest(2, "finalization", body, previous),
        "issuer_key_id": KEY, "signature": SIG,
    }

    with pytest.raises(EventRefused) as excinfo:
        harness.ingest([event])

    assert excinfo.value.reason == "divergence"
    assert harness.store.is_diverged(ISSUER)


def test_ingest_refuses_the_opaque_revocation_body_and_accepts_the_closed_one(
    harness: Harness,
) -> None:
    """Part 3 Sections 1-2 replace slice 1's opaque bodies: only the closed body ingests."""
    def revocation(body: dict[str, Any]) -> dict[str, Any]:
        """Return a one-event chain carrying ``body`` as a revocation."""
        digest = event_digest(1, "revocation", body, GENESIS_EVENT_DIGEST)
        return {
            "version": 1, "kind": "revocation", "body": body,
            "previous_event_digest": GENESIS_EVENT_DIGEST, "event_digest": digest,
            "issuer_key_id": KEY, "signature": SIG,
        }

    with pytest.raises(WireError):
        event_digest(1, "revocation", {"grant_id": GRANT}, GENESIS_EVENT_DIGEST)
    harness.ingest([revocation({"subject_kind": "grant", "subject_id": GRANT})])

    assert harness.store.acked_through(ISSUER) == 1


# ---------------------------------------------------------------- durability


def test_create_attempt_is_durable_across_close_and_reopen(tmp_path: Path) -> None:
    """The attempt row survives close and reopen with its identity intact."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path)
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    store.close()

    reopened = SqliteAttemptStore(path)

    record = reopened.get_attempt(ATTEMPT)
    assert record is not None
    assert (record.grant_id, record.reservation_id, record.state) == (
        GRANT, RESERVATION, "created",
    )


def test_create_attempt_is_idempotent_but_refuses_a_different_binding(tmp_path: Path) -> None:
    """The same attempt_id with the same binding is a no-op; a different one is refused."""
    store = SqliteAttemptStore(db_path(tmp_path))
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    with pytest.raises(AttemptStateError):
        store._create_attempt(ATTEMPT, GRANT, "res-other")
    with pytest.raises(ValueError):
        store._create_attempt(" ", GRANT, RESERVATION)


def test_store_directory_and_file_are_private(tmp_path: Path) -> None:
    """The private-store conventions apply: directory 0700 and file 0600."""
    path = db_path(tmp_path)
    SqliteAttemptStore(path)

    assert (path.parent.stat().st_mode & 0o777, path.stat().st_mode & 0o777) == (0o700, 0o600)


def test_mark_transmitted_is_durable(tmp_path: Path) -> None:
    """The transmitted flag survives reopen and moves created to transmitted."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path)
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    store.mark_transmitted(ATTEMPT)
    store.close()

    record = SqliteAttemptStore(path).get_attempt(ATTEMPT)

    assert record is not None and record.transmitted is True and record.state == "transmitted"


def test_record_unavailable_holds_the_reservation_and_creates_nothing(
    harness: Harness,
) -> None:
    """Unavailable keeps the same reservation, mints no second attempt and writes no intent."""
    harness.store.mark_transmitted(ATTEMPT)
    harness.store.record_unavailable(ATTEMPT)

    snap = snapshot(harness.path)
    assert len(snap["dispatch_attempts"]) == 1
    record = harness.store.get_attempt(ATTEMPT)
    assert record is not None
    assert (record.state, record.reservation_id, record.transmitted) == (
        "unavailable", RESERVATION, True,
    )
    assert snap["grant_use"] == snap["dispatch_intents"] == snap["outbox"] == []


def test_record_unavailable_after_commit_is_refused(harness: Harness) -> None:
    """A committed attempt can no longer be recorded as unavailable."""
    flow = vector_flow()
    ready(harness, flow)
    harness.authorize(flow)

    with pytest.raises(AttemptAlreadyCommitted):
        harness.store.record_unavailable(ATTEMPT)


def test_crash_and_restart_between_ingest_and_authorize(tmp_path: Path) -> None:
    """Reopening the file between ingest and authorize loses neither events nor attempt."""
    path = db_path(tmp_path)
    flow = vector_flow()
    first = SqliteAttemptStore(path)
    first._create_attempt(ATTEMPT, GRANT, RESERVATION)
    first.ingest_events(ISSUER, flow.chain[:1], FakeVerifier())
    first.close()

    second = SqliteAttemptStore(path)
    assert second.acked_through(ISSUER) == 1
    second.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, NOW, verifier=FakeVerifier(), gates=FakeGates(),
        revocations=FakeRevocations(), issuer_id=ISSUER, expected=EXPECTED,
    )

    assert sender_precondition(second, ATTEMPT) is True


def test_all_refusals_seen_use_the_closed_rule_set(harness: Harness) -> None:
    """Every rule value raised across the six rule scenarios is one of rule1..rule6."""
    flow = vector_flow()
    seen = {harness.refused_rule(flow)}  # rule2: nothing acknowledged
    ready(harness, flow)
    harness.revocations.revoked_grants.add(GRANT)
    seen.add(harness.refused_rule(flow))  # rule4
    harness.revocations.revoked_grants.clear()
    harness.verifier.permit_ok = False
    seen.add(harness.refused_rule(flow))  # rule1
    harness.verifier.permit_ok = True
    harness.gates.ok = False
    seen.add(harness.refused_rule(flow))  # rule6

    assert seen == {"rule1", "rule2", "rule4", "rule6"}
    assert seen <= AUTHORIZATION_RULES


# ------------------------------------------------- F1 ledger binding (rules 1 and 5)


def test_rule1_refuses_a_permit_for_another_ledger(harness: Harness) -> None:
    """A permit whose ledger differs from the expected one fails rule 1 permit_binding."""
    flow = build_flow(permit_changes={"ledger_store_id": "ledger-other"})
    ready(harness, flow)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule1", "permit_binding")


def test_rule5_refuses_a_finalization_for_another_ledger(harness: Harness) -> None:
    """A finalization whose ledger differs fails rule 5 finalization_binding."""
    flow = build_flow(fin_changes={"ledger_store_id": "ledger-other"})
    ready(harness, flow)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule5", "finalization_binding")


def test_rule5_checks_the_expected_ledger_itself() -> None:
    """Even if permit and finalization agree, a ledger other than expected is refused."""
    flow = build_flow(
        permit_changes={"ledger_store_id": "ledger-other"},
        fin_changes={"ledger_store_id": "ledger-other"},
    )
    attempt = AttemptRecord(ATTEMPT, GRANT, RESERVATION, "created", False, False, None)
    db = sqlite3.connect(":memory:")

    with pytest.raises(AuthorizationRefused) as excinfo:
        _check_finalization(
            db, attempt, flow.permit, flow.fin, NOW, FakeVerifier(), ISSUER, EXPECTED
        )

    assert (excinfo.value.rule, excinfo.value.reason) == ("rule5", "finalization_binding")


# ------------------------------------------------- F2 revocation port


def test_rule4_refuses_an_issuer_wide_revocation(harness: Harness) -> None:
    """A revocation of the whole issuer (not the grant) refuses under rule 4."""
    flow = vector_flow()
    ready(harness, flow)
    harness.revocations.revoked_issuers.add(ISSUER)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule4", "grant_revoked")
    assert harness.revocations.seen[-1] == (GRANT, ISSUER)


# ------------------------------------------------- F3 persisted divergence


def _plant_fork(harness: Harness) -> Flow:
    """Hold version 2 with another digest, so a good R_f=2 finalization is a fork."""
    flow = build_flow()
    ready(harness, flow)
    conn = sqlite3.connect(harness.path)
    conn.execute("INSERT INTO issuer_cascade_ack VALUES (?, 2, ?, 'x')", (ISSUER, "5" * 64))
    conn.commit()
    conn.close()
    return flow


def test_divergence_refusal_persists_the_flag_and_blocks_later_authorize(
    harness: Harness,
) -> None:
    """A rule 5 divergence refusal records the flag after rollback; later flows are refused."""
    flow = _plant_fork(harness)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule5", "divergence")
    assert harness.store.is_diverged(ISSUER) is True
    again = harness.refused(build_flow())
    assert (again.rule, again.reason) == ("rule5", "divergence_or_gap")
    assert harness.store.get_attempt(ATTEMPT).state == "created"  # type: ignore[union-attr]


def test_event_digest_mismatch_refusal_persists_the_flag(harness: Harness) -> None:
    """A rebuilt wrapper that differs from the signed digest also flags the issuer."""
    flow = build_flow(fin_changes={"revocation_event_digest": "1" * 64})
    ready(harness, flow)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule5", "event_digest_mismatch")
    assert harness.store.is_diverged(ISSUER) is True
    again = harness.refused(build_flow())
    assert (again.rule, again.reason) == ("rule5", "divergence_or_gap")


def test_other_refusals_never_flag_divergence_or_write(harness: Harness) -> None:
    """Gate, signature and replay refusals write nothing, divergence flag included."""
    flow = vector_flow()
    ready(harness, flow)
    harness.gates.ok = False
    harness.refused(flow)
    harness.gates.ok = True
    harness.verifier.finalization_ok = False
    harness.refused(flow)
    harness.verifier.finalization_ok = True
    harness.revocations.revoked_grants.add(GRANT)
    harness.refused(flow)

    assert harness.store.is_diverged(ISSUER) is False


# ------------------------------------------------- F4 lifetime caps

_T0 = "2026-10-19T04:00:00.000000Z"


@pytest.mark.parametrize(
    ("expires", "passes"),
    [
        ("2026-10-19T04:01:30.000000Z", True),
        ("2026-10-19T04:01:30.000001Z", False),
        ("2026-10-19T04:00:00.000000Z", False),
    ],
    ids=["exactly-90s", "90s-plus-1us", "expires-equals-issued"],
)
def test_rule1_permit_lifetime_cap_boundaries(
    harness: Harness, expires: str, passes: bool
) -> None:
    """A permit lives strictly more than 0 and at most 90 seconds."""
    flow = build_flow(
        permit_changes={"issued_at": _T0, "expires_at": expires},
        fin_changes={"expires_at": expires if passes else "2026-10-19T04:01:31.000000Z"},
    )
    ready(harness, flow)
    if passes:
        harness.authorize(flow)
        return

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule1", "lifetime_exceeds_cap")


@pytest.mark.parametrize(
    ("issued", "expires"),
    [
        ("2026-10-19T04:00:01.000000Z", "2026-10-19T04:01:31.000001Z"),
        ("2026-10-19T04:00:31.000000Z", "2026-10-19T04:00:31.000000Z"),
    ],
    ids=["90s-plus-1us", "expires-equals-issued"],
)
def test_rule5_finalization_lifetime_cap(harness: Harness, issued: str, expires: str) -> None:
    """A finalization over 90 seconds or not after issued_at is refused under rule 5."""
    permit_expiry = {
        "issued_at": "2026-10-19T04:00:02.000000Z", "expires_at": "2026-10-19T04:01:32.000000Z",
    }
    flow = build_flow(
        permit_changes=permit_expiry,
        fin_changes={"issued_at": issued, "expires_at": expires},
    )
    ready(harness, flow)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule5", "lifetime_exceeds_cap")


def test_rule5_finalization_may_end_with_the_permit_but_not_after(harness: Harness) -> None:
    """Finalization expiry equal to the permit expiry passes; one microsecond later is refused."""
    flow = build_flow(fin_changes={"expires_at": "2026-10-19T04:01:31.000001Z"})
    ready(harness, flow)

    refusal = harness.refused(flow)

    assert (refusal.rule, refusal.reason) == ("rule5", "finalization_outlives_permit")
    harness.authorize(build_flow())
