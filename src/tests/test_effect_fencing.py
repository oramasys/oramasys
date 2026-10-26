"""Fencing epoch committed with authorization, and terminal pre-dispatch refusals (DRAFT)."""
from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import (
    AttemptStateError,
    AuthorizationRefused,
    ClockQuarantined,
    OperatorRefused,
    SqliteAttemptStore,
)
from orama.graph.effect_fencing import FencingRefused, admit_epoch, require_epoch
from orama.graph.effect_proposals import ReservationRefused
from tests.test_dispatch_attempts import (
    ATTEMPT,
    EXPECTED,
    ISSUER,
    NOW,
    Harness,
    ready,
    vector_flow,
)
from tests.test_effect_seam import SCOPE, authorize, governed, quiet_snapshot

OPERATOR_REF = "operator-ref-1"


class Operator:
    """OperatorAuthority double: authorizes with a fixed reference, or refuses."""

    def __init__(self, reference: str | None = OPERATOR_REF) -> None:
        """Set the reference returned (None refuses)."""
        self.reference, self.calls = reference, []

    def authorize(self, operation: str, *, subject: str) -> str | None:
        """Record the call and answer as scripted."""
        self.calls.append((operation, subject))
        return self.reference


def terminal(h: Harness, scope=SCOPE, now: datetime = NOW) -> None:
    """Run the terminal-refusal authorization wrapper with the harness ports."""
    flow = vector_flow()
    h.store.authorize_dispatch_terminal(
        ATTEMPT, flow.permit, flow.fin, now, verifier=h.verifier, gates=h.gates,
        revocations=h.revocations, issuer_id=ISSUER, expected=EXPECTED, scope=scope,
    )


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    """Provide a governed harness with the proposal and reservation in place."""
    harness = governed(tmp_path)
    yield harness
    harness.store.close()


# --------------------------------------------------------------- fencing epoch


def test_authorization_stamps_the_integer_epoch_and_the_current_mark(h: Harness) -> None:
    """The epoch the attempt authorized under is stored as an integer with the ledger transition."""
    assert h.store.fencing_epoch(ATTEMPT) is None and h.store.current_fencing_epoch() is None
    ready(h, vector_flow())
    authorize(h, SCOPE)
    assert h.store.fencing_epoch(ATTEMPT) == EXPECTED.authority_epoch == 5
    assert h.store.current_fencing_epoch() == 5
    row = h.store._db.execute(
        "SELECT typeof(fencing_epoch) FROM dispatch_attempts WHERE attempt_id = ?", (ATTEMPT,)
    ).fetchone()
    assert row == ("integer",)


def test_a_refused_authorization_leaves_no_epoch_behind(h: Harness) -> None:
    """The epoch is part of the one transaction: refusal writes neither stamp nor mark."""
    ready(h, vector_flow())
    h.verifier.permit_ok = False
    before = quiet_snapshot(h.path)
    with pytest.raises(AuthorizationRefused):
        authorize(h, SCOPE)
    assert quiet_snapshot(h.path) == before
    assert h.store.fencing_epoch(ATTEMPT) is None and h.store.current_fencing_epoch() is None


def test_a_stale_epoch_cannot_authorize(h: Harness) -> None:
    """After the epoch advanced past the consumer binding, authorization refuses and writes nothing."""
    ready(h, vector_flow())
    h.store.advance_fencing_epoch(6, operator=Operator(), now=NOW)
    before = quiet_snapshot(h.path)
    with pytest.raises(AuthorizationRefused) as excinfo:
        authorize(h, SCOPE)
    assert (excinfo.value.rule, excinfo.value.reason) == ("rule6", "fencing_epoch_stale")
    assert quiet_snapshot(h.path) == before
    assert h.store.outbox_row(ATTEMPT) is None


def test_the_stamp_survives_reopening(tmp_path: Path) -> None:
    """The epoch is durable, not in-memory."""
    h = governed(tmp_path)
    ready(h, vector_flow())
    authorize(h, SCOPE)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        assert reopened.fencing_epoch(ATTEMPT) == 5 and reopened.current_fencing_epoch() == 5
    finally:
        reopened.close()


def test_advancing_the_epoch_needs_an_authenticated_operator_and_is_strictly_increasing(
    h: Harness,
) -> None:
    """Refused operator, equal, lower and invalid epochs all fail; accepted ones are logged."""
    with pytest.raises(OperatorRefused):
        h.store.advance_fencing_epoch(6, operator=Operator(None), now=NOW)
    with pytest.raises(OperatorRefused):
        h.store.advance_fencing_epoch(6, operator=Operator("  "), now=NOW)
    assert h.store.current_fencing_epoch() is None
    h.store.advance_fencing_epoch(6, operator=Operator(), now=NOW)
    for bad in (6, 5, 0, -1, True, 7.0, "7"):
        with pytest.raises(AttemptStateError):
            h.store.advance_fencing_epoch(bad, operator=Operator(), now=NOW)  # type: ignore[arg-type]
    h.store.advance_fencing_epoch(7, operator=Operator(), now=NOW)
    log = h.store._db.execute("SELECT epoch, operator_ref FROM fencing_epoch_log ORDER BY id").fetchall()
    assert log == [(6, OPERATOR_REF), (7, OPERATOR_REF)]
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        h.store._db.execute("DELETE FROM fencing_epoch_log")


def test_epoch_helpers_refuse_non_integers() -> None:
    """Only a real integer of at least 1 is an epoch."""
    for bad in (0, -3, True, False, 1.5, "1", None):
        with pytest.raises(FencingRefused):
            require_epoch(bad)
    assert require_epoch(1) == 1
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE fencing_epoch_current (id INTEGER PRIMARY KEY CHECK (id = 1),"
                 " epoch INTEGER NOT NULL CHECK (epoch >= 1))")
    admit_epoch(conn, 3)
    admit_epoch(conn, 3)
    admit_epoch(conn, 4)
    with pytest.raises(FencingRefused, match="stale"):
        admit_epoch(conn, 3)


def test_an_attempts_table_from_before_the_epoch_is_migrated_in_place(tmp_path: Path) -> None:
    """The ad hoc migration adds the column; an old row keeps NULL and so has no epoch."""
    path = tmp_path / "old" / "attempts.db"
    # The store refuses a state directory or database that is not private to its owner.
    path.parent.mkdir(mode=0o700)
    path.parent.chmod(0o700)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE dispatch_attempts (attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL,"
        " reservation_id TEXT NOT NULL, state TEXT NOT NULL, fenced INTEGER NOT NULL DEFAULT 0,"
        " transmitted INTEGER NOT NULL DEFAULT 0, permit_id TEXT, permit_digest TEXT,"
        " finalization_digest TEXT, r_p INTEGER, r_f INTEGER, created_at TEXT NOT NULL,"
        " second_approval_ref TEXT)"
    )
    conn.execute(
        "INSERT INTO dispatch_attempts (attempt_id, grant_id, reservation_id, state, created_at)"
        " VALUES ('old-attempt', 'g', 'r', 'created', '2026-01-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()
    path.chmod(0o600)
    store = SqliteAttemptStore(path)
    try:
        assert store.fencing_epoch("old-attempt") is None
        assert store.get_attempt("old-attempt") is not None
        store._create_attempt("new-attempt", "g2", "r2")
    finally:
        store.close()
    SqliteAttemptStore(path).close()  # a second open is idempotent


# ------------------------------------------------------------ terminal refusals


def test_a_pre_dispatch_refusal_is_terminal_and_replays_identically(h: Harness) -> None:
    """The first refusal is stored; replays return it without re-evaluating, even if now fixable."""
    ready(h, vector_flow())
    h.verifier.permit_ok = False
    with pytest.raises(AuthorizationRefused) as first:
        terminal(h)
    stored = h.store.terminal_refusal(ATTEMPT)
    assert stored is not None and stored.kind == "authorization"
    assert (stored.rule, stored.reason) == (first.value.rule, first.value.reason) == ("rule1", "permit_signature")
    h.verifier.permit_ok = True
    calls = len(h.verifier.calls)
    with pytest.raises(AuthorizationRefused) as replay:
        terminal(h)
    assert (replay.value.rule, replay.value.reason) == ("rule1", "permit_signature")
    assert len(h.verifier.calls) == calls, "a terminal refusal must not re-verify"
    with pytest.raises(AuthorizationRefused):
        terminal(h, now=NOW + timedelta(seconds=1))
    assert h.store.outbox_row(ATTEMPT) is None
    assert h.store.fencing_epoch(ATTEMPT) is None


def test_the_terminal_refusal_survives_a_restart(tmp_path: Path) -> None:
    """Reopening the store still returns the same refusal for the identity."""
    h = governed(tmp_path)
    ready(h, vector_flow())
    h.verifier.permit_ok = False
    with pytest.raises(AuthorizationRefused):
        terminal(h)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        h2 = Harness(reopened, h.path, h.verifier, h.gates, h.revocations)
        h2.verifier.permit_ok = True
        with pytest.raises(AuthorizationRefused) as replay:
            terminal(h2)
        assert replay.value.reason == "permit_signature"
    finally:
        reopened.close()


def test_a_reservation_refusal_is_terminal_too(h: Harness) -> None:
    """A scope mismatch is a pre-dispatch refusal recorded and replayed as the same refusal."""
    ready(h, vector_flow())
    wrong = replace(SCOPE, principal="mallory")
    with pytest.raises(ReservationRefused) as first:
        terminal(h, scope=wrong)
    assert first.value.reason == "scope_mismatch"
    stored = h.store.terminal_refusal(ATTEMPT)
    assert stored is not None and stored.kind == "reservation"
    with pytest.raises(ReservationRefused) as replay:
        terminal(h, scope=SCOPE)
    assert replay.value.reason == "scope_mismatch"
    assert h.store.outbox_row(ATTEMPT) is None


def test_replaying_an_authorized_attempt_records_no_refusal(h: Harness) -> None:
    """A second authorize of an attempt that already committed refuses but never burns it."""
    ready(h, vector_flow())
    terminal(h)
    with pytest.raises((AuthorizationRefused, ReservationRefused)):
        terminal(h)
    assert h.store.terminal_refusal(ATTEMPT) is None
    assert h.store.outbox_row(ATTEMPT) is not None
    with pytest.raises(AttemptStateError):
        h.store.record_terminal_refusal(ATTEMPT, "authorization", "rule1", "x", NOW)


def test_a_clock_quarantine_is_operational_and_not_recorded(h: Harness) -> None:
    """A backward clock step quarantines dispatch but does not burn the attempt identity."""
    ready(h, vector_flow())
    h.store.observe_clock(NOW)
    with pytest.raises(ClockQuarantined):
        terminal(h, now=NOW - timedelta(minutes=10))
    assert h.store.terminal_refusal(ATTEMPT) is None


def test_the_refusal_table_is_append_only_and_first_wins(h: Harness) -> None:
    """Triggers abort UPDATE and DELETE and the first recorded refusal is the kept one."""
    first = h.store.record_terminal_refusal(ATTEMPT, "authorization", "rule1", "first", NOW)
    second = h.store.record_terminal_refusal(ATTEMPT, "reservation", None, "second", NOW)
    assert first == second and second.reason == "first"
    for statement in ("UPDATE attempt_refusals SET reason = 'x'", "DELETE FROM attempt_refusals"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            h.store._db.execute(statement)
    with pytest.raises(ValueError):
        h.store.record_terminal_refusal(ATTEMPT, "made_up", None, "x", NOW)
    with pytest.raises(ValueError):
        h.store.record_terminal_refusal("no-such-attempt", "authorization", "rule1", "x", NOW)


def test_the_plain_store_path_is_unchanged_by_the_terminal_wrapper(h: Harness) -> None:
    """authorize_dispatch itself still refuses without recording, so E1 behaviour is untouched."""
    ready(h, vector_flow())
    h.verifier.permit_ok = False
    with pytest.raises(AuthorizationRefused):
        authorize(h, SCOPE)
    assert h.store.terminal_refusal(ATTEMPT) is None
    h.verifier.permit_ok = True
    authorize(h, SCOPE)
    assert h.store.outbox_row(ATTEMPT) is not None
