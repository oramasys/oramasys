"""E1 C2 Part 3 section 3.3 conformance against the real consumer store.

Mirrors the reference-model suite in orama-system (tests/e1_part3_conformance) so the same
rules run against ``SqliteAttemptStore``. Fake ports only; Oramasys holds no cryptography.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from orama.graph.dispatch_anchor import (
    assert_not_quarantined,
    AnchorConflict,
    AnchorFloorRefused,
    AnchorQuarantined,
    AnchorRefused,
)
from orama.graph.dispatch_attempts import (
    AttemptStateError,
    EventRefused,
    OperatorRefused,
    SqliteAttemptStore,
    VerifiedDispatchGrant,
)
from orama.graph.dispatch_consumer_wire import event_digest
from orama.graph.effect_proposals import EffectScope
from tests.test_dispatch_attempts import (
    ATTEMPT,
    EXPECTED,
    GRANT,
    ISSUER,
    KEY,
    NOW,
    RESERVATION,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    Harness,
    build_flow,
    db_path,
    harness,  # noqa: F401  (fixture re-export)
    make_chain,
    snapshot,
)


@dataclass
class TrustedKeys:
    allowed: dict[str, set[str]] = field(default_factory=lambda: {ISSUER: {KEY}})

    def key_belongs_to(self, issuer_id: str, key_id: str) -> bool:
        return key_id in self.allowed.get(issuer_id, set())


@dataclass
class Operator:
    reference: str | None = "operator-1"

    def authorize(self, operation: str, *, subject: str) -> str | None:
        return self.reference


def boot(h: Harness, event: dict[str, Any], keys: TrustedKeys | None = None) -> None:
    h.store.bootstrap_anchor(
        ISSUER, event, h.verifier, trusted_keys=keys or TrustedKeys(), now=NOW
    )


def forged_anchor(version: int = 5, previous: str = "d" * 64) -> dict[str, Any]:
    body = {"finalization_id": f"other-{version}"}
    digest = event_digest(version, "finalization", body, previous)
    return {
        "version": version, "kind": "finalization", "body": body,
        "previous_event_digest": previous, "event_digest": digest,
        "issuer_key_id": KEY, "signature": "A" * 86,
    }


def quarantined(h: Harness, version: int = 5) -> list[dict[str, Any]]:
    chain = make_chain(version + 3)
    boot(h, chain[version - 1])
    with pytest.raises(AnchorConflict):
        boot(h, forged_anchor(version))
    return chain


F3_SCOPE = EffectScope(
    principal="f3-principal",
    graph_id="f3-graph",
    policy_hash="a" * 64,
    operation_digest="b" * 64,
    artifact_identity="c" * 64,
    destination="f3-destination",
)
F3_PROPOSAL = "f3-proposal"


def f3_stores(tmp_path: Path) -> tuple[SqliteAttemptStore, SqliteAttemptStore, Path]:
    """Return independent governed stores backed by one prepared SQLite database."""
    path = db_path(tmp_path)
    first = SqliteAttemptStore(path, governed=True)
    second = SqliteAttemptStore(path, governed=True)
    first.create_attempt(ATTEMPT, VerifiedDispatchGrant(GRANT), RESERVATION)
    first.propose(F3_PROPOSAL, F3_SCOPE, NOW)
    first.reserve(RESERVATION, F3_PROPOSAL, F3_SCOPE, NOW + timedelta(hours=1), NOW)
    return first, second, path


def f3_boot(store: SqliteAttemptStore, event: dict[str, Any]) -> None:
    """Bootstrap through an independently constructed store instance."""
    store.bootstrap_anchor(ISSUER, event, FakeVerifier(), trusted_keys=TrustedKeys(), now=NOW)


def test_cold_bootstrap_persists_identity_floor_and_base(harness: Harness) -> None:  # noqa: F811
    anchor = make_chain(5)[4]

    boot(harness, anchor)

    rec = harness.store.anchor_record(ISSUER)
    assert rec == {
        "issuer_id": ISSUER, "issuer_key_id": KEY, "version": 5,
        "event_digest": anchor["event_digest"], "anchor_floor": 5, "base_version": 5,
        "base_digest": anchor["event_digest"], "quarantined": 0,
    }
    assert harness.store.acked_through(ISSUER) == 5


def test_independent_stores_accept_an_identical_bootstrap_and_restart_readback(
    tmp_path: Path,
) -> None:
    """Two connections share an idempotent bootstrap and a restart reads the same anchor."""
    first, second, path = f3_stores(tmp_path)
    anchor = make_chain(5)[4]
    try:
        f3_boot(first, anchor)
        f3_boot(second, anchor)
    finally:
        first.close()
        second.close()

    reopened = SqliteAttemptStore(path, governed=True)
    try:
        assert reopened.anchor_record(ISSUER) == {
            "issuer_id": ISSUER,
            "issuer_key_id": KEY,
            "version": 5,
            "event_digest": anchor["event_digest"],
            "anchor_floor": 5,
            "base_version": 5,
            "base_digest": anchor["event_digest"],
            "quarantined": 0,
        }
        assert reopened.acked_through(ISSUER) == 5
    finally:
        reopened.close()


def test_independent_store_bootstrap_race_quarantines_and_survives_restart(
    tmp_path: Path,
) -> None:
    """Two independent connections race without a shared application mutex or sleeps."""
    first, second, path = f3_stores(tmp_path)
    original, conflicting = make_chain(5)[4], forged_anchor()
    ready = threading.Barrier(3)
    release = threading.Event()
    pending = object()
    outcomes: list[object] = [pending, pending]

    def bootstrap(index: int, store: SqliteAttemptStore, anchor: dict[str, Any]) -> None:
        """Wait for both SQLite connections, then retain the bootstrap result for assertion."""
        try:
            ready.wait()
            release.wait()
            f3_boot(store, anchor)
        except BaseException as error:  # noqa: BLE001 - the assertion classifies each racer
            outcomes[index] = error
        else:
            outcomes[index] = None

    threads = [
        threading.Thread(target=bootstrap, args=(0, first, original), daemon=True),
        threading.Thread(target=bootstrap, args=(1, second, conflicting), daemon=True),
    ]
    try:
        for thread in threads:
            thread.start()
        ready.wait()
        release.set()
        for thread in threads:
            thread.join(timeout=30)
        assert not [thread for thread in threads if thread.is_alive()]
        assert all(outcome is not pending for outcome in outcomes), outcomes
        assert sum(outcome is None for outcome in outcomes) == 1, outcomes
        assert sum(isinstance(outcome, AnchorConflict) for outcome in outcomes) == 1, outcomes
    finally:
        release.set()
        first.close()
        second.close()

    reopened = SqliteAttemptStore(path, governed=True)
    try:
        record = reopened.anchor_record(ISSUER)
        assert record is not None
        assert record["event_digest"] in {original["event_digest"], conflicting["event_digest"]}
        assert record["quarantined"] == 1
        with sqlite3.connect(path) as db:
            evidence = db.execute(
                "SELECT evidence FROM issuer_anchor_conflicts WHERE issuer_id = ?", (ISSUER,)
            ).fetchall()
        assert len(evidence) == 1
        assert json.loads(evidence[0][0])["event_digest"] != record["event_digest"]
    finally:
        reopened.close()


def test_peer_committed_floor_refuses_authorization_without_consuming_or_writing(
    tmp_path: Path,
) -> None:
    """A floor committed by one connection blocks a peer before reservation or effects mutate."""
    first, second, path = f3_stores(tmp_path)
    flow = build_flow(r_p=3, r_f=4)
    try:
        f3_boot(first, make_chain(5)[4])
        # Stabilize the governed high-water row before the refusal snapshot; this test targets
        # anchor-floor atomicity rather than the independently qualified clock mechanism.
        second.observe_clock(NOW)
        before = snapshot(path)

        with pytest.raises(AnchorFloorRefused) as caught:
            second.authorize_dispatch(
                ATTEMPT,
                flow.permit,
                flow.fin,
                NOW,
                verifier=FakeVerifier(),
                gates=FakeGates(),
                revocations=FakeRevocations(),
                issuer_id=ISSUER,
                expected=EXPECTED,
                scope=F3_SCOPE,
            )

        assert caught.value.reason == "anchor_floor.permit_below_floor"
        after = snapshot(path)
        for table in ("reservations", "grant_use", "dispatch_intents", "outbox"):
            assert after[table] == before[table]
    finally:
        first.close()
        second.close()


def test_gap_does_not_advance_but_next_event_does(harness: Harness) -> None:  # noqa: F811
    chain = make_chain(8)
    boot(harness, chain[4])

    with pytest.raises(EventRefused) as caught:
        harness.ingest([chain[6]])  # gap at 6
    assert caught.value.reason == "gap"
    assert harness.store.acked_through(ISSUER) == 5
    harness.ingest([chain[5]])
    assert harness.store.acked_through(ISSUER) == 6
    harness.ingest([chain[6], chain[7]])
    assert harness.store.acked_through(ISSUER) == 8


def test_events_below_anchor_are_refused_without_persisting(harness: Harness) -> None:  # noqa: F811
    chain = make_chain(5)
    boot(harness, chain[4])
    before = snapshot(harness.path)

    with pytest.raises(EventRefused) as caught:
        harness.ingest([chain[0]])

    assert caught.value.reason == "below_anchor"
    assert snapshot(harness.path) == before
    assert harness.store.acked_through(ISSUER) == 5
    assert all(v >= 5 for v in _ack_versions(harness))


def _ack_versions(h: Harness) -> list[int]:
    return [r[0] for r in sqlite3.connect(h.path).execute("SELECT version FROM issuer_cascade_ack")]


@pytest.mark.parametrize("mutate", ["digest", "body", "version"])
def test_bad_digest_or_shape_is_plain_refusal_persisting_nothing(
    harness: Harness, mutate: str  # noqa: F811
) -> None:
    anchor = deepcopy(make_chain(5)[4])
    if mutate == "digest":
        anchor["event_digest"] = "0" * 64
    elif mutate == "body":
        anchor["body"] = {"finalization_id": "tampered"}
    else:
        anchor = make_chain(1)[0]  # version 1 is not a pruned anchor

    before = snapshot(harness.path)
    with pytest.raises(AnchorRefused):
        boot(harness, anchor)

    assert snapshot(harness.path) == before


def test_key_supplied_only_by_event_is_not_trusted(harness: Harness) -> None:  # noqa: F811
    with pytest.raises(AnchorRefused):
        boot(harness, make_chain(5)[4], TrustedKeys(allowed={ISSUER: set()}))
    with pytest.raises(AnchorRefused):
        boot(harness, make_chain(5)[4], TrustedKeys(allowed={"other": {KEY}}))

    assert harness.store.anchor_record(ISSUER) is None


def test_bad_signature_is_plain_refusal(harness: Harness) -> None:  # noqa: F811
    harness.verifier.event_ok = False

    with pytest.raises(AnchorRefused):
        boot(harness, make_chain(5)[4])

    assert harness.store.anchor_record(ISSUER) is None


def test_identical_retry_is_noop_and_keeps_acked_through(harness: Harness) -> None:  # noqa: F811
    chain = make_chain(7)
    boot(harness, chain[4])
    harness.ingest(chain[5:7])

    boot(harness, chain[4])

    assert harness.store.acked_through(ISSUER) == 7
    assert harness.store.anchor_record(ISSUER)["quarantined"] == 0


def test_conflicting_retry_refuses_quarantines_and_keeps_values(harness: Harness) -> None:  # noqa: F811
    quarantined(harness)

    rec = harness.store.anchor_record(ISSUER)
    assert rec["quarantined"] == 1
    assert rec["event_digest"] == make_chain(5)[4]["event_digest"]


def test_different_key_identity_on_repeat_quarantines(harness: Harness) -> None:  # noqa: F811
    anchor = make_chain(5)[4]
    boot(harness, anchor)
    other = {**anchor, "issuer_key_id": "key-2"}
    keys = TrustedKeys(allowed={ISSUER: {KEY, "key-2"}})

    with pytest.raises(AnchorConflict):
        boot(harness, other, keys)

    assert harness.store.anchor_record(ISSUER)["issuer_key_id"] == KEY


def test_lower_version_retry_cannot_lower_floor(harness: Harness) -> None:  # noqa: F811
    chain = make_chain(9)
    boot(harness, chain[8])

    with pytest.raises(AnchorConflict):
        boot(harness, chain[2])

    assert harness.store.anchor_record(ISSUER)["anchor_floor"] == 9


def test_quarantine_blocks_authorization_without_writes_and_is_per_issuer(
    harness: Harness,  # noqa: F811
) -> None:
    flow = build_flow(r_p=1, r_f=2)
    quarantined(harness)
    before = snapshot(harness.path)

    with pytest.raises(AnchorQuarantined) as caught:
        harness.authorize(flow)

    assert caught.value.reason == "anchor_quarantined"
    assert snapshot(harness.path) == before
    assert harness.store.anchor_record(ISSUER) is not None  # read-only stays possible
    db = sqlite3.connect(harness.path)
    assert_not_quarantined(db, "issuer-2")  # another issuer is not blocked


def test_matching_later_bootstrap_does_not_clear_quarantine(harness: Harness) -> None:  # noqa: F811
    chain = quarantined(harness)

    boot(harness, chain[4])

    assert harness.store.anchor_record(ISSUER)["quarantined"] == 1


@pytest.mark.parametrize("reference,evidence", [(None, "ev"), ("", "ev"), ("  ", "ev")])
def test_clear_requires_operator_reference(harness: Harness, reference: Any, evidence: str) -> None:  # noqa: F811
    quarantined(harness)

    with pytest.raises(OperatorRefused):
        harness.store.clear_anchor_quarantine(
            ISSUER, operator=Operator(reference), trusted_evidence=evidence, now=NOW
        )

    assert harness.store.anchor_record(ISSUER)["quarantined"] == 1


@pytest.mark.parametrize("evidence", ["", "   "])
def test_clear_requires_trusted_evidence(harness: Harness, evidence: str) -> None:  # noqa: F811
    quarantined(harness)

    with pytest.raises(ValueError):
        harness.store.clear_anchor_quarantine(
            ISSUER, operator=Operator(), trusted_evidence=evidence, now=NOW
        )


def test_clear_needs_an_existing_quarantine(harness: Harness) -> None:  # noqa: F811
    boot(harness, make_chain(5)[4])

    with pytest.raises(AttemptStateError):
        harness.store.clear_anchor_quarantine(
            ISSUER, operator=Operator(), trusted_evidence="ev", now=NOW
        )


def test_audited_clear_appends_immutable_log_and_keeps_floor(harness: Harness) -> None:  # noqa: F811
    quarantined(harness)

    harness.store.clear_anchor_quarantine(
        ISSUER, operator=Operator("op-7"), trusted_evidence="signed note", now=NOW
    )

    assert harness.store.anchor_record(ISSUER)["quarantined"] == 0
    assert harness.store.anchor_record(ISSUER)["anchor_floor"] == 5
    db = sqlite3.connect(harness.path)
    rows = db.execute(
        "SELECT previous_record, accepted_record, operator_reference, trusted_evidence "
        "FROM anchor_quarantine_log"
    ).fetchall()
    assert len(rows) == 1
    previous, accepted, operator_reference, trusted_evidence = rows[0]
    assert (operator_reference, trusted_evidence) == ("op-7", "signed note")
    assert json.loads(previous)["quarantined"] == 1
    assert json.loads(accepted)["quarantined"] == 0
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE anchor_quarantine_log SET trusted_evidence = 'x'")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM anchor_quarantine_log")


def test_permit_below_floor_is_refused_with_no_writes_and_reservation_kept(
    harness: Harness,  # noqa: F811
) -> None:
    flow = build_flow(r_p=3, r_f=4)
    boot(harness, make_chain(6)[5])
    before = snapshot(harness.path)

    with pytest.raises(AnchorFloorRefused) as caught:
        harness.authorize(flow)

    assert caught.value.reason == "anchor_floor.permit_below_floor"
    assert snapshot(harness.path) == before


def test_permit_at_floor_authorizes_on_a_checkpoint_aware_base(harness: Harness) -> None:  # noqa: F811
    flow = build_flow(r_p=3, r_f=4)
    boot(harness, flow.chain[2])  # anchor at version 3 == floor
    harness.ingest(flow.chain[3:4])

    harness.authorize(flow)

    row = sqlite3.connect(harness.path).execute(
        "SELECT state FROM dispatch_attempts WHERE attempt_id = ?", (ATTEMPT,)
    ).fetchone()
    assert row == ("authorized",)


def test_issuer_without_an_anchor_has_no_floor(harness: Harness) -> None:  # noqa: F811
    flow = build_flow(r_p=1, r_f=2)
    harness.ingest(flow.chain[:1])

    harness.authorize(flow)  # no AnchorFloorRefused


def test_crash_inside_bootstrap_leaves_nothing(harness: Harness, monkeypatch: Any) -> None:  # noqa: F811
    import orama.graph.dispatch_anchor as anchor

    real = anchor.install_or_quarantine

    def crash(db: sqlite3.Connection, *args: Any) -> bool:
        real(db, *args)
        raise RuntimeError("crash after anchor insert")

    monkeypatch.setattr(anchor, "install_or_quarantine", crash)
    before = snapshot(harness.path)

    with pytest.raises(RuntimeError):
        boot(harness, make_chain(5)[4])

    assert snapshot(harness.path) == before
