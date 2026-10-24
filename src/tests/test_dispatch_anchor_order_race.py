"""Part 3 section 3.3: gate order when several rules fail, and concurrent bootstrap races.

Pins the order implemented in ``SqliteAttemptStore._authorize_in_transaction``: anchor
quarantine, then Rule 1, then the anchor-floor gate, then Rules 2 and 3 (acknowledgement
coverage). A refusal reports the first failing gate and never merges reasons.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from orama.graph.dispatch_anchor import (
    AnchorConflict,
    AnchorFloorRefused,
    AnchorQuarantined,
)
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
    """Anchor quarantine wins over a failing Rule 1 and a below-floor permit, and writes nothing."""
    quarantined(harness, version=6)
    harness.verifier.permit_ok = False  # Rule 1 would also fail
    flow = build_flow(r_p=3, r_f=4)  # and R_p is below the floor

    before = snapshot(harness.path)
    with pytest.raises(AnchorQuarantined):
        harness.authorize(flow)

    assert snapshot(harness.path) == before


def test_rule1_is_reported_before_the_floor(harness: Harness) -> None:  # noqa: F811
    """With no quarantine, a Rule 1 failure is reported before the anchor-floor gate."""
    boot(harness, make_chain(6)[5])
    harness.verifier.permit_ok = False
    flow = build_flow(r_p=3, r_f=4)

    with pytest.raises(AuthorizationRefused) as caught:
        harness.authorize(flow)

    assert caught.value.rule == "rule1"


def test_floor_is_reported_before_rule3_when_both_fail(harness: Harness) -> None:  # noqa: F811
    """A below-floor permit is refused by the floor gate before Rule 3, and writes nothing."""
    boot(harness, make_chain(6)[5])
    flow = build_flow(r_p=3, r_f=4, permit_changes={"consumer_acked_through": 5})  # Rule 3 fails too

    before = snapshot(harness.path)
    with pytest.raises(AnchorFloorRefused):
        harness.authorize(flow)

    assert snapshot(harness.path) == before


def test_rule3_is_reported_when_the_floor_holds(harness: Harness) -> None:  # noqa: F811
    """When the permit is at the floor, the next failing gate (Rule 3) is the one reported."""
    boot(harness, make_chain(3)[2])  # floor 3
    flow = build_flow(r_p=3, r_f=4, permit_changes={"consumer_acked_through": 5})

    with pytest.raises(AuthorizationRefused) as caught:
        harness.authorize(flow)

    assert caught.value.rule == "rule3"


PENDING = object()
"""Marker for a worker that never recorded a result; distinct from a successful ``None``."""

JOIN_SECONDS = 30


def _store(tmp_path: Path) -> SqliteAttemptStore:
    """Return a fresh store with the shared attempt already created."""
    store = SqliteAttemptStore(tmp_path / "race" / "attempts.db")
    store.create_attempt(ATTEMPT, GRANT, RESERVATION)
    return store


def _db(tmp_path: Path) -> sqlite3.Connection:
    """Open a second connection to the race store for read-only assertions."""
    return sqlite3.connect(tmp_path / "race" / "attempts.db")


def _run_threads(workers: list[Callable[[], object]]) -> list[object]:
    """Start every worker behind one barrier and return each result or raised exception.

    Workers are daemon threads, so a stuck worker cannot hold the test process open. A worker
    still alive after its join deadline, or one that never recorded a result, fails the test:
    a pending worker is never mistaken for a ``None`` success.
    """
    barrier = threading.Barrier(len(workers))
    results: list[object] = [PENDING] * len(workers)

    def run(index: int, work: Callable[[], object]) -> None:
        """Wait at the barrier, then record the worker's return value or exception."""
        barrier.wait()
        try:
            results[index] = work()
        except BaseException as error:  # noqa: BLE001 - recorded for the assertion
            results[index] = error

    threads = [
        threading.Thread(target=run, args=(i, w), daemon=True) for i, w in enumerate(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=JOIN_SECONDS)
    stuck = [i for i, thread in enumerate(threads) if thread.is_alive()]
    assert not stuck, f"workers still running after {JOIN_SECONDS}s: {stuck}"
    assert all(r is not PENDING for r in results), results
    return results


def _bootstrap(store: SqliteAttemptStore, anchor: dict) -> Callable[[], object]:
    """Return a worker that bootstraps ``anchor`` with trusted keys and a fake verifier."""
    return lambda: store.bootstrap_anchor(
        ISSUER, anchor, FakeVerifier(), trusted_keys=TrustedKeys(), now=NOW
    )


def _race_harness(store: SqliteAttemptStore, tmp_path: Path) -> Harness:
    """Wrap ``store`` in the shared harness with default fakes."""
    return Harness(store, tmp_path / "race" / "attempts.db", FakeVerifier(), FakeGates(),
                   FakeRevocations())


def _intent_count(tmp_path: Path) -> int:
    """Return how many dispatch intents exist (authorization writes one on success)."""
    return _db(tmp_path).execute("SELECT COUNT(*) FROM dispatch_intents").fetchone()[0]


def test_run_threads_fails_a_worker_that_does_not_finish(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that outlives its join deadline fails the helper instead of reading as None."""
    monkeypatch.setattr(sys.modules[__name__], "JOIN_SECONDS", 0.05)
    release = threading.Event()
    try:
        with pytest.raises(AssertionError, match="still running"):
            _run_threads([lambda: release.wait(5)])
    finally:
        release.set()


def test_concurrent_identical_bootstraps_install_exactly_one_record(tmp_path: Path) -> None:
    """Eight identical concurrent bootstraps all succeed and persist exactly one anchor row."""
    store = _store(tmp_path)
    anchor = make_chain(6)[5]

    results = _run_threads([_bootstrap(store, anchor) for _ in range(8)])

    assert all(r is None for r in results), results
    rec = store.anchor_record(ISSUER)
    assert rec["event_digest"] == anchor["event_digest"] and rec["quarantined"] == 0
    assert store.acked_through(ISSUER) == 6
    assert _db(tmp_path).execute("SELECT COUNT(*) FROM issuer_anchor").fetchone()[0] == 1


def test_concurrent_conflicting_bootstrap_quarantines_and_keeps_the_first_values(
    tmp_path: Path,
) -> None:
    """The first anchor to commit is kept; every call is judged against the anchor it sent.

    A call that submitted the persisted anchor succeeds (an identical repeat is a no-op even
    under quarantine); a call that submitted the other anchor raises ``AnchorConflict`` and
    leaves one evidence row. An implementation that overwrote the digest on conflict would
    make some call for the persisted anchor fail, or leave the loser's evidence unmatched.
    """
    store = _store(tmp_path)
    original, conflicting = make_chain(6)[5], forged_anchor(6)
    submitted = [original, conflicting] * 3

    results = _run_threads([_bootstrap(store, anchor) for anchor in submitted])

    record = store.anchor_record(ISSUER)
    winner = record["event_digest"]
    assert winner in {original["event_digest"], conflicting["event_digest"]}
    for anchor, result in zip(submitted, results, strict=True):
        if anchor["event_digest"] == winner:
            assert result is None, (anchor["event_digest"], result)
        else:
            assert isinstance(result, AnchorConflict), (anchor["event_digest"], result)
    losers = [a for a in submitted if a["event_digest"] != winner]
    assert record["quarantined"] == 1
    evidence = [
        json.loads(row[0])["event_digest"]
        for row in _db(tmp_path).execute("SELECT evidence FROM issuer_anchor_conflicts")
    ]
    assert evidence == [a["event_digest"] for a in losers]


def test_floor_committed_first_refuses_with_the_floor_gate(tmp_path: Path) -> None:
    """Controlled order: once the floor commits, a concurrent below-floor permit is refused.

    The bootstrap thread finishes before the authorization thread starts, so the refusal must
    be ``AnchorFloorRefused`` specifically, not any earlier or later rule.
    """
    store = _store(tmp_path)
    race = _race_harness(store, tmp_path)
    anchor = make_chain(6)[5]

    [installed] = _run_threads([_bootstrap(store, anchor)])
    [refusal] = _run_threads([lambda: race.authorize(build_flow(r_p=3, r_f=4))])

    assert installed is None
    assert store.anchor_record(ISSUER)["anchor_floor"] == 6
    assert isinstance(refusal, AnchorFloorRefused), refusal
    assert _intent_count(tmp_path) == 0


def test_authorization_first_refuses_on_missing_acknowledgement(tmp_path: Path) -> None:
    """Controlled order: with no anchor yet, the authorization refuses under Rule 2.

    The later bootstrap still installs, and nothing was authorized in between.
    """
    store = _store(tmp_path)
    race = _race_harness(store, tmp_path)
    anchor = make_chain(6)[5]

    [refusal] = _run_threads([lambda: race.authorize(build_flow(r_p=3, r_f=4))])
    [installed] = _run_threads([_bootstrap(store, anchor)])

    assert isinstance(refusal, AuthorizationRefused) and refusal.rule == "rule2", refusal
    assert installed is None
    assert store.anchor_record(ISSUER)["event_digest"] == anchor["event_digest"]
    assert _intent_count(tmp_path) == 0


def test_authorization_after_a_concurrent_floor_commit_applies_the_floor(tmp_path: Path) -> None:
    """Racing bootstrap and authorization: bootstrap succeeds, and the refusal matches an order.

    Either the floor committed first (``AnchorFloorRefused``) or the authorization ran first
    (``AuthorizationRefused`` under Rule 2). No other refusal is accepted, and nothing is ever
    authorized.
    """
    store = _store(tmp_path)
    race = _race_harness(store, tmp_path)
    anchor = make_chain(6)[5]

    installed, refusal = _run_threads([
        _bootstrap(store, anchor),
        lambda: race.authorize(build_flow(r_p=3, r_f=4)),
    ])

    assert installed is None, installed
    assert store.anchor_record(ISSUER)["event_digest"] == anchor["event_digest"]
    floor_first = isinstance(refusal, AnchorFloorRefused)
    auth_first = isinstance(refusal, AuthorizationRefused) and refusal.rule == "rule2"
    assert floor_first or auth_first, refusal
    assert _intent_count(tmp_path) == 0
