"""E1 T3 first seam: proposals, scoped single-use reservations and unknown-first outcomes.

Real SQLite files and the slice-1 fake ports. No provider transport exists anywhere here.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import AuthorizationRefused, SqliteAttemptStore
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.effect_proposals import (
    PROPOSAL_SCHEMA,
    SCOPE_FIELDS,
    EffectScope,
    ReservationRefused,
    consume_reservation,
    record_proposal,
    reserve,
)
from tests.test_dispatch_attempts import (
    ATTEMPT,
    EXPECTED,
    GRANT,
    ISSUER,
    NOW,
    RESERVATION,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    Harness,
    db_path,
    ready,
    snapshot,
    vector_flow,
)

PROPOSAL = "proposal-0001"
SCOPE = EffectScope(
    principal="principal-1", graph_id="graph-1", policy_hash="a" * 64,
    operation_digest="b" * 64, artifact_identity="c" * 64, destination="dest-1",
)
LIVE_UNTIL = NOW + timedelta(hours=1)


def governed(tmp_path: Path) -> Harness:
    """Open a governed store with the vector attempt, proposal and reservation in place."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path, governed=True)
    store.create_attempt(ATTEMPT, GRANT, RESERVATION)
    store.propose(PROPOSAL, SCOPE, NOW)
    store.reserve(RESERVATION, PROPOSAL, SCOPE, LIVE_UNTIL, NOW)
    return Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())


def authorize(h: Harness, scope: EffectScope | None, now=NOW) -> None:
    """Run step 4.3 with an explicit scope."""
    flow = vector_flow()
    h.store.authorize_dispatch(
        ATTEMPT, flow.permit, flow.fin, now, verifier=h.verifier, gates=h.gates,
        revocations=h.revocations, issuer_id=ISSUER, expected=EXPECTED, scope=scope,
    )


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    """Provide a fresh governed harness with its matching proposal and reservation."""
    return governed(tmp_path)


def authorized(h: Harness) -> None:
    """Advance a governed harness through readiness and the authorized step 4.3 transaction."""
    ready(h, vector_flow())
    authorize(h, SCOPE)


# ------------------------------------------------ proposal distinct from authorization


def test_a_proposal_stores_scope_only_and_precedes_any_grant(tmp_path: Path) -> None:
    """A proposal persists its scope without creating attempts or consuming a grant."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path, governed=True)
    store.propose(PROPOSAL, SCOPE, NOW)
    snap = snapshot(path)
    assert len(snap["effect_proposals"]) == 1
    assert snap["dispatch_attempts"] == [] and snap["grant_use"] == []
    columns = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(effect_proposals)")}
    assert columns == {"proposal_id", *SCOPE_FIELDS, "created_at"}


def test_recording_the_same_proposal_is_idempotent_but_a_different_scope_is_refused(
    tmp_path: Path,
) -> None:
    """A repeated identical proposal is idempotent, while a changed scope conflicts."""
    store = SqliteAttemptStore(db_path(tmp_path), governed=True)
    store.propose(PROPOSAL, SCOPE, NOW)
    store.propose(PROPOSAL, SCOPE, NOW)
    with pytest.raises(ReservationRefused) as excinfo:
        store.propose(PROPOSAL, replace(SCOPE, destination="other"), NOW)
    assert excinfo.value.reason == "proposal_conflict"


@pytest.mark.parametrize("field", SCOPE_FIELDS)
def test_a_scope_requires_every_field(field: str) -> None:
    """Every member of the six-field scope must contain non-blank text."""
    with pytest.raises(ValueError, match=field):
        replace(SCOPE, **{field: "  "})


# ------------------------------------------------------------- forged inputs


def test_a_reservation_for_an_unknown_proposal_is_refused(tmp_path: Path) -> None:
    """A reservation cannot be created before its durable proposal exists."""
    store = SqliteAttemptStore(db_path(tmp_path), governed=True)
    with pytest.raises(ReservationRefused) as excinfo:
        store.reserve(RESERVATION, "no-such-proposal", SCOPE, LIVE_UNTIL, NOW)
    assert excinfo.value.reason == "proposal_unknown"


def test_a_reservation_must_carry_the_proposals_own_scope(tmp_path: Path) -> None:
    """Reservation creation rejects a scope that differs from the proposal it names."""
    store = SqliteAttemptStore(db_path(tmp_path), governed=True)
    store.propose(PROPOSAL, SCOPE, NOW)
    with pytest.raises(ReservationRefused) as excinfo:
        store.reserve(RESERVATION, PROPOSAL, replace(SCOPE, principal="mallory"), LIVE_UNTIL, NOW)
    assert excinfo.value.reason == "scope_mismatch"


def test_a_reservation_that_is_already_expired_is_refused(tmp_path: Path) -> None:
    """A reservation must expire strictly after the instant it is recorded."""
    store = SqliteAttemptStore(db_path(tmp_path), governed=True)
    store.propose(PROPOSAL, SCOPE, NOW)
    with pytest.raises(ReservationRefused) as excinfo:
        store.reserve(RESERVATION, PROPOSAL, SCOPE, NOW, NOW)
    assert excinfo.value.reason == "reservation_expired"


def test_a_governed_store_refuses_dispatch_without_a_scope(tmp_path: Path) -> None:
    """Governed authorization requires a scope and leaves storage unchanged when absent."""
    h = governed(tmp_path)
    ready(h, vector_flow())
    before = snapshot(h.path)
    with pytest.raises(ReservationRefused) as excinfo:
        authorize(h, None)
    assert excinfo.value.reason == "scope_required"
    assert snapshot(h.path) == before


def test_a_governed_store_refuses_dispatch_when_no_reservation_exists(tmp_path: Path) -> None:
    """Governed authorization refuses an attempt whose reservation has not been recorded."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path, governed=True)
    store.create_attempt(ATTEMPT, GRANT, RESERVATION)
    h = Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())
    ready(h, vector_flow())
    with pytest.raises(ReservationRefused) as excinfo:
        authorize(h, SCOPE)
    assert excinfo.value.reason == "reservation_unknown"


# ----------------------------------------------- changed scope / cross-agent transfer


@pytest.mark.parametrize("field", SCOPE_FIELDS)
def test_any_changed_scope_field_is_refused_and_leaves_the_reservation_unused(
    h: Harness, field: str
) -> None:
    """A caller cannot alter any one scope dimension while retaining the reservation."""
    ready(h, vector_flow())
    before = snapshot(h.path)
    with pytest.raises(ReservationRefused) as excinfo:
        authorize(h, replace(SCOPE, **{field: "changed"}))
    assert excinfo.value.reason == "scope_mismatch"
    assert snapshot(h.path) == before


# -------------------------------------------------------------- expiry, revocation


def test_an_expired_reservation_is_refused_at_the_boundary(h: Harness) -> None:
    """Authorization at the exact expiry boundary refuses the reservation."""
    ready(h, vector_flow())
    with pytest.raises(ReservationRefused) as excinfo:
        authorize(h, SCOPE, now=LIVE_UNTIL)
    assert excinfo.value.reason == "reservation_expired"


def test_a_revoked_grant_is_refused_and_the_reservation_stays_unused(h: Harness) -> None:
    """A revocation rolls back the reservation consumption performed before rule four."""
    ready(h, vector_flow())
    h.revocations.revoked_grants.add(GRANT)
    with pytest.raises(AuthorizationRefused) as excinfo:
        authorize(h, SCOPE)
    assert (excinfo.value.rule, excinfo.value.reason) == ("rule4", "grant_revoked")
    used = sqlite3.connect(h.path).execute(
        "SELECT consumed_attempt_id FROM reservations"
    ).fetchone()
    assert used == (None,)


# ------------------------------------------------------------------ concurrency


def test_exactly_one_of_two_racing_consumers_wins(tmp_path: Path) -> None:
    """The reservation's single-use update permits exactly one concurrent consumer."""
    path = db_path(tmp_path)
    first = SqliteAttemptStore(path, governed=True)
    second = SqliteAttemptStore(path, governed=True)
    first.propose(PROPOSAL, SCOPE, NOW)
    first.reserve(RESERVATION, PROPOSAL, SCOPE, LIVE_UNTIL, NOW)
    barrier = threading.Barrier(2)
    results: list[str] = []

    def race(store: SqliteAttemptStore, attempt: str) -> None:
        """Compete for the same reservation after both workers reach the barrier."""
        barrier.wait()
        try:
            with store._immediate() as db:
                consume_reservation(db, RESERVATION, attempt, SCOPE, NOW)
            results.append("won")
        except ReservationRefused as refusal:
            results.append(refusal.reason)

    threads = [threading.Thread(target=race, args=(s, a))
               for s, a in ((first, "attempt-a"), (second, "attempt-b"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["reservation_consumed", "won"]


def test_the_authorize_transaction_consumes_the_reservation_exactly_once(h: Harness) -> None:
    """A successful step 4.3 transaction consumes the reservation exactly once."""
    authorized(h)
    row = sqlite3.connect(h.path).execute("SELECT consumed_attempt_id FROM reservations").fetchone()
    assert row == (ATTEMPT,)
    with pytest.raises(ReservationRefused) as excinfo:
        with h.store._immediate() as db:
            consume_reservation(db, RESERVATION, "attempt-2", SCOPE, NOW)
    assert excinfo.value.reason == "reservation_consumed"


# ------------------------------------------------- unknown-first, restart, no retry


def test_authorization_leaves_the_effect_unknown_with_no_send_started(h: Harness) -> None:
    """Authorization records an unknown effect but has not started external delivery."""
    authorized(h)
    row = h.store.outbox_row(ATTEMPT)
    assert row is not None
    assert (row["outcome"], row["outcome_evidence"], row["send_started"]) == ("unknown", None, 0)


def test_restart_after_commit_before_send_keeps_unknown_and_one_send_available(
    tmp_path: Path,
) -> None:
    """A restart preserves unknown state and permits only the one original send."""
    h = governed(tmp_path)
    authorized(h)
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    row = reopened.outbox_row(ATTEMPT)
    assert row is not None and (row["outcome"], row["send_started"]) == ("unknown", 0)
    reopened.begin_send(ATTEMPT)
    reopened.close()
    again = SqliteAttemptStore(h.path, governed=True)
    with pytest.raises(OutcomeRefused) as excinfo:
        again.begin_send(ATTEMPT)
    assert excinfo.value.reason == "send_already_started"


def test_a_second_dispatch_of_an_unknown_attempt_is_refused(h: Harness) -> None:
    """An unknown outcome never authorizes a second send for the same attempt."""
    authorized(h)
    h.store.begin_send(ATTEMPT)
    with pytest.raises(OutcomeRefused) as excinfo:
        h.store.begin_send(ATTEMPT)
    assert excinfo.value.reason == "send_already_started"
    row = h.store.outbox_row(ATTEMPT)
    assert row is not None and row["outcome"] == "unknown"


def test_a_send_needs_an_authorized_outbox_row(h: Harness) -> None:
    """The sender cannot run before authorization has created its complete outbox row."""
    from orama.graph.dispatch_attempts import AttemptStateError

    with pytest.raises(AttemptStateError):
        h.store.begin_send(ATTEMPT)


# ------------------------------------------------------------ outcome settlement


def test_an_outcome_cannot_be_recorded_before_a_send_started(h: Harness) -> None:
    """Settlement evidence is accepted only after the durable send-start marker exists."""
    authorized(h)
    with pytest.raises(OutcomeRefused) as excinfo:
        h.store.record_outcome(ATTEMPT, "confirmed", "provider-receipt-1")
    assert excinfo.value.reason == "send_not_started"


@pytest.mark.parametrize("outcome", ["confirmed", "failed"])
def test_unknown_settles_only_with_an_evidence_reference(h: Harness, outcome: str) -> None:
    """Confirmed and failed outcomes require a non-empty provider evidence reference."""
    authorized(h)
    h.store.begin_send(ATTEMPT)
    with pytest.raises(OutcomeRefused) as excinfo:
        h.store.record_outcome(ATTEMPT, outcome, None)
    assert excinfo.value.reason == "evidence_required"
    h.store.record_outcome(ATTEMPT, outcome, "provider-receipt-1")
    row = h.store.outbox_row(ATTEMPT)
    assert row is not None
    assert (row["outcome"], row["outcome_evidence"]) == (outcome, "provider-receipt-1")


def test_a_settled_outcome_is_terminal_and_never_returns_to_unknown(h: Harness) -> None:
    """A settled outcome is terminal and cannot be rewritten to any later state."""
    authorized(h)
    h.store.begin_send(ATTEMPT)
    h.store.record_outcome(ATTEMPT, "failed", "provider-receipt-1")
    for later in ("confirmed", "failed", "unknown"):
        with pytest.raises(OutcomeRefused) as excinfo:
            h.store.record_outcome(ATTEMPT, later, "provider-receipt-2")
        assert excinfo.value.reason == "outcome_terminal"


def test_the_outbox_check_constraint_rejects_any_other_outcome(h: Harness) -> None:
    """SQLite itself constrains outbox outcomes to the closed three-state vocabulary."""
    authorized(h)
    with pytest.raises(sqlite3.IntegrityError):
        sqlite3.connect(h.path).execute("UPDATE outbox SET outcome = 'applied'")


# ------------------------------------------------------------ schema compatibility


def test_an_outbox_created_before_the_outcome_columns_is_migrated(tmp_path: Path) -> None:
    """Opening an older database adds the outcome columns required by the new lifecycle."""
    path = db_path(tmp_path)
    SqliteAttemptStore(path).close()
    conn = sqlite3.connect(path)
    conn.executescript(
        "DROP TABLE outbox; CREATE TABLE outbox ("
        " attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, permit_id TEXT NOT NULL,"
        " permit_digest TEXT NOT NULL, finalization_digest TEXT NOT NULL, r_p INTEGER NOT NULL,"
        " r_f INTEGER NOT NULL, authority_pair TEXT NOT NULL, acked_through INTEGER NOT NULL,"
        " payload TEXT);"
    )
    conn.close()
    SqliteAttemptStore(path).close()
    names = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(outbox)")}
    assert {"outcome", "outcome_evidence", "send_started"} <= names


def test_the_proposal_schema_is_part_of_the_store_schema() -> None:
    """The shared proposal schema remains publicly importable and has its two expected tables."""
    assert len(PROPOSAL_SCHEMA) == 2
    assert record_proposal and reserve  # public API stays importable


# ------------------------------------------------ governed must be explicit on any product path

SRC_ROOT = Path(__file__).resolve().parents[1] / "orama"


def ungoverned_constructions(source: str) -> list[int]:
    """Return line numbers of ``SqliteAttemptStore(...)`` calls lacking ``governed=True``."""
    import ast

    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name != "SqliteAttemptStore":
            continue
        governed = [kw for kw in node.keywords if kw.arg == "governed"]
        explicit = (
            len(governed) == 1
            and isinstance(governed[0].value, ast.Constant)
            and governed[0].value.value is True
        )
        if not explicit:
            lines.append(node.lineno)
    return lines


def test_the_scanner_flags_a_store_built_without_governed_true() -> None:
    """The AST guard rejects omitted, false, and dynamic governed constructor arguments."""
    assert ungoverned_constructions("SqliteAttemptStore(path)") == [1]
    assert ungoverned_constructions("m.SqliteAttemptStore(path, governed=False)") == [1]
    assert ungoverned_constructions("SqliteAttemptStore(path, governed=flag)") == [1]
    assert ungoverned_constructions("SqliteAttemptStore(path, governed=True)") == []


def test_no_product_code_builds_an_attempt_store_without_governed_true() -> None:
    """Every product construction outside the store implementation explicitly enables governance."""
    offenders = {
        str(path.relative_to(SRC_ROOT)): lines
        for path in sorted(SRC_ROOT.rglob("*.py"))
        if path.name != "dispatch_attempts.py"
        for lines in [ungoverned_constructions(path.read_text(encoding="utf-8"))]
        if lines
    }
    assert offenders == {}, f"serving paths must pass governed=True: {offenders}"


# ------------------------------------------- the reservation scope is bound to the permit


def reserved_for(tmp_path: Path, scope: EffectScope) -> Harness:
    """A governed store whose reservation was made for ``scope`` (not necessarily the permit's)."""
    path = db_path(tmp_path)
    store = SqliteAttemptStore(path, governed=True)
    store.create_attempt(ATTEMPT, GRANT, RESERVATION)
    store.propose(PROPOSAL, scope, NOW)
    store.reserve(RESERVATION, PROPOSAL, scope, LIVE_UNTIL, NOW)
    return Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())


@pytest.mark.parametrize("field", ["operation_digest", "artifact_identity"])
def test_a_reservation_made_for_another_operation_or_artifact_cannot_authorize_the_permit(
    tmp_path: Path, field: str
) -> None:
    """A reservation for another operation or artifact cannot authorize the vector permit."""
    other = replace(SCOPE, **{field: "9" * 64})
    h = reserved_for(tmp_path, other)
    ready(h, vector_flow())
    before = snapshot(h.path)
    with pytest.raises(ReservationRefused) as excinfo:
        authorize(h, other)  # the caller presents the reserved scope, but the permit is for another
    assert excinfo.value.reason == "scope_not_bound_to_permit"
    assert snapshot(h.path) == before
    unused = sqlite3.connect(h.path).execute("SELECT consumed_attempt_id FROM reservations").fetchone()
    assert unused == (None,)


def test_the_mapping_is_operation_digest_to_request_digest_and_artifact_identity_to_artifact_digest(
    h: Harness,
) -> None:
    """The two cross-repository digest mappings are explicit and consumed atomically."""
    permit = vector_flow().permit
    assert (SCOPE.operation_digest, SCOPE.artifact_identity) == (
        permit["request_digest"], permit["artifact_digest"],
    )
    authorized(h)
    row = sqlite3.connect(h.path).execute("SELECT consumed_attempt_id FROM reservations").fetchone()
    assert row == (ATTEMPT,)
