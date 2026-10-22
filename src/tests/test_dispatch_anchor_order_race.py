"""Part 3 section 3.3: gate order when several rules fail, and concurrent bootstrap races.

Pins the order implemented in ``SqliteAttemptStore._authorize_in_transaction``: anchor
quarantine, then Rule 1, then the anchor-floor gate, then Rules 2 and 3 (acknowledgement
coverage). A refusal reports the first failing gate and never merges reasons.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from orama.graph.dispatch_anchor import AnchorConflict, AnchorFloorRefused, AnchorQuarantined
from orama.graph.dispatch_attempts import AuthorizationRefused, SqliteAttemptStore
from tests.test_dispatch_anchor import TrustedKeys, boot, forged_anchor, quarantined
from tests.test_dispatch_attempts import (
    ATTEMPT,
    GRANT,
    ISSUER,
    NOW,
    RESERVATION,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    Harness,
    build_flow,
    harness,  # noqa: F401  (fixture re-export)
    make_chain,
    snapshot,
)


def test_quarantine_is_reported_before_rule1_and_the_floor(harness: Harness) -> None:  # noqa: F811
    quarantined(harness, version=6)
    harness.verifier.permit_ok = False  # Rule 1 would also fail
    flow = build_flow(r_p=3, r_f=4)  # and R_p is below the floor

    before = snapshot(harness.path)
    with pytest.raises(AnchorQuarantined):
        harness.authorize(flow)

    assert snapshot(harness.path) == before


def test_rule1_is_reported_before_the_floor(harness: Harness) -> None:  # noqa: F811
    boot(harness, make_chain(6)[5])
    harness.verifier.permit_ok = False
    flow = build_flow(r_p=3, r_f=4)

    with pytest.raises(AuthorizationRefused) as caught:
        harness.authorize(flow)

    assert caught.value.rule == "rule1"


def test_floor_is_reported_before_rule3_when_both_fail(harness: Harness) -> None:  # noqa: F811
    boot(harness, make_chain(6)[5])
    flow = build_flow(r_p=3, r_f=4, permit_changes={"consumer_acked_through": 5})  # Rule 3 fails too

    before = snapshot(harness.path)
    with pytest.raises(AnchorFloorRefused):
        harness.authorize(flow)

    assert snapshot(harness.path) == before


def test_rule3_is_reported_when_the_floor_holds(harness: Harness) -> None:  # noqa: F811
    boot(harness, make_chain(3)[2])  # floor 3
    flow = build_flow(r_p=3, r_f=4, permit_changes={"consumer_acked_through": 5})

    with pytest.raises(AuthorizationRefused) as caught:
        harness.authorize(flow)

    assert caught.value.rule == "rule3"


def _store(tmp_path: Path) -> SqliteAttemptStore:
    store = SqliteAttemptStore(tmp_path / "race" / "attempts.db")
    store.create_attempt(ATTEMPT, GRANT, RESERVATION)
    return store


def _run_threads(workers: list) -> list:
    barrier = threading.Barrier(len(workers))
    results: list = [None] * len(workers)

    def run(index: int, work) -> None:
        barrier.wait()
        try:
            results[index] = work()
        except BaseException as error:  # noqa: BLE001 - recorded for the assertion
            results[index] = error

    threads = [threading.Thread(target=run, args=(i, w)) for i, w in enumerate(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    return results


def test_concurrent_identical_bootstraps_install_exactly_one_record(tmp_path: Path) -> None:
    store = _store(tmp_path)
    anchor = make_chain(6)[5]
    keys, verifier = TrustedKeys(), FakeVerifier()

    results = _run_threads([
        lambda: store.bootstrap_anchor(ISSUER, anchor, verifier, trusted_keys=keys, now=NOW)
        for _ in range(8)
    ])

    assert all(r is None for r in results), results
    rec = store.anchor_record(ISSUER)
    assert rec["event_digest"] == anchor["event_digest"] and rec["quarantined"] == 0
    assert store.acked_through(ISSUER) == 6
    count = sqlite3.connect(tmp_path / "race" / "attempts.db").execute(
        "SELECT COUNT(*) FROM issuer_anchor"
    ).fetchone()[0]
    assert count == 1


def test_concurrent_conflicting_bootstrap_quarantines_and_keeps_the_first_values(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    original, conflicting = make_chain(6)[5], forged_anchor(6)
    keys, verifier = TrustedKeys(), FakeVerifier()
    work = [
        lambda: store.bootstrap_anchor(ISSUER, original, verifier, trusted_keys=keys, now=NOW),
        lambda: store.bootstrap_anchor(ISSUER, conflicting, verifier, trusted_keys=keys, now=NOW),
    ]

    results = _run_threads(work * 3)

    persisted = store.anchor_record(ISSUER)["event_digest"]
    assert persisted in {original["event_digest"], conflicting["event_digest"]}
    errors = [r for r in results if r is not None]
    assert all(isinstance(e, AnchorConflict) for e in errors), errors
    # whichever installed first is kept; the other is a conflict that quarantined
    assert errors and store.anchor_record(ISSUER)["quarantined"] == 1


def test_authorization_after_a_concurrent_floor_commit_applies_the_floor(tmp_path: Path) -> None:
    store = _store(tmp_path)
    anchor = make_chain(6)[5]
    harness_like = Harness(store, tmp_path / "race" / "attempts.db", FakeVerifier(),
                           FakeGates(), FakeRevocations())
    flow = build_flow(r_p=3, r_f=4)

    results = _run_threads([
        lambda: store.bootstrap_anchor(
            ISSUER, anchor, harness_like.verifier, trusted_keys=TrustedKeys(), now=NOW
        ),
        lambda: harness_like.authorize(flow),
    ])

    # Either the authorization ran first (no acknowledgement coverage, so Rule 2 refuses and the
    # bootstrap then installs) or the floor committed first and the floor gate refuses. It is
    # never authorized.
    assert results[0] in (None,) or isinstance(results[0], Exception)
    refusal = results[1]
    assert isinstance(refusal, (AnchorFloorRefused, AuthorizationRefused)), refusal
    assert sqlite3.connect(tmp_path / "race" / "attempts.db").execute(
        "SELECT COUNT(*) FROM dispatch_intents"
    ).fetchone()[0] == 0
