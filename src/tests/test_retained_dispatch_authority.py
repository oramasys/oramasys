"""Retained signed dispatch authority remains an inert audit prerequisite."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import AuthorizationRefused, SqliteAttemptStore
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
    vector_flow,
)


def _authorize(tmp_path: Path) -> tuple[SqliteAttemptStore, FakeVerifier, dict[str, object], dict[str, object]]:
    """Authorize one complete vector flow through the normal dispatch transaction."""
    store = SqliteAttemptStore(tmp_path / "attempts.sqlite")
    verifier = FakeVerifier()
    flow = vector_flow()
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    store.ingest_events(ISSUER, flow.chain[: flow.permit["revocation_version"]], verifier)
    store.authorize_dispatch(
        ATTEMPT,
        flow.permit,
        flow.fin,
        NOW,
        verifier=verifier,
        gates=FakeGates(),
        revocations=FakeRevocations(),
        issuer_id=ISSUER,
        expected=EXPECTED,
    )
    return store, verifier, flow.permit, flow.fin


def test_authorization_atomically_retains_reverifiable_signed_wires(tmp_path: Path) -> None:
    """A committed authorization retains its exact signed permit and finalization wires."""
    store, verifier, permit, fin = _authorize(tmp_path)
    try:
        retained = store.retained_dispatch_authority(ATTEMPT)
        assert retained is not None
        assert retained.issuer_id == ISSUER
        assert retained.grant_id == permit["grant_id"]
        assert retained.permit == permit
        assert retained.finalization == fin
        assert retained.reverify(verifier) is True
    finally:
        store.close()


def test_refused_authorization_retains_no_partial_authority(tmp_path: Path) -> None:
    """A failed authorization cannot leave signed evidence that looks committed."""
    store = SqliteAttemptStore(tmp_path / "attempts.sqlite")
    flow = vector_flow()
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    try:
        with pytest.raises(AuthorizationRefused):
            store.authorize_dispatch(
                ATTEMPT,
                flow.permit,
                flow.fin,
                NOW,
                verifier=FakeVerifier(),
                gates=FakeGates(),
                revocations=FakeRevocations(),
                issuer_id=ISSUER,
                expected=EXPECTED,
            )
        assert store.retained_dispatch_authority(ATTEMPT) is None
    finally:
        store.close()


def test_retained_authority_survives_reopen_as_read_only_evidence(tmp_path: Path) -> None:
    """A restart preserves signed evidence without exposing mutable stored mappings."""
    store, verifier, _permit, _fin = _authorize(tmp_path)
    path = tmp_path / "attempts.sqlite"
    store.close()
    reopened = SqliteAttemptStore(path)
    try:
        retained = reopened.retained_dispatch_authority(ATTEMPT)
        assert retained is not None
        assert retained.reverify(verifier) is True
        with pytest.raises(TypeError):
            retained.permit["grant_id"] = "replacement"  # type: ignore[index]
    finally:
        reopened.close()


_REPLACE_FORMS = (
    "INSERT OR REPLACE INTO retained_dispatch_authority "
    "(attempt_id, issuer_id, permit_wire, finalization_wire) VALUES (?, 'evil', x'00', x'00')",
    "REPLACE INTO retained_dispatch_authority "
    "(attempt_id, issuer_id, permit_wire, finalization_wire) VALUES (?, 'evil', x'00', x'00')",
    "INSERT INTO retained_dispatch_authority (attempt_id, issuer_id, permit_wire, finalization_wire) "
    "VALUES (?, 'evil', x'00', x'00') ON CONFLICT(attempt_id) DO UPDATE SET issuer_id = 'evil'",
    "INSERT INTO retained_dispatch_authority (attempt_id, issuer_id, permit_wire, finalization_wire) "
    "VALUES (?, 'evil', x'00', x'00')",
)


@pytest.mark.parametrize("statement", _REPLACE_FORMS)
def test_retained_authority_cannot_be_replaced_by_any_insert_form(tmp_path: Path, statement: str) -> None:
    """REPLACE and upsert forms skip the DELETE/UPDATE triggers, so a BEFORE INSERT guard must stop them."""
    store, verifier, permit, fin = _authorize(tmp_path)
    path = tmp_path / "attempts.sqlite"
    store.close()
    raw = sqlite3.connect(path)
    try:
        before = raw.execute("SELECT * FROM retained_dispatch_authority").fetchall()
        with pytest.raises(sqlite3.DatabaseError, match="append-only|UNIQUE"):
            raw.execute(statement, (ATTEMPT,))
        raw.rollback()
        assert raw.execute("SELECT * FROM retained_dispatch_authority").fetchall() == before
    finally:
        raw.close()
    reopened = SqliteAttemptStore(path)
    try:
        retained = reopened.retained_dispatch_authority(ATTEMPT)
        assert retained is not None
        assert retained.permit == permit and retained.finalization == fin
        assert retained.reverify(verifier) is True
    finally:
        reopened.close()


def test_replace_guard_is_added_to_an_existing_database_on_open(tmp_path: Path) -> None:
    """A database created before the guard existed gets it when the store opens it."""
    store, _verifier, _permit, _fin = _authorize(tmp_path)
    path = tmp_path / "attempts.sqlite"
    store.close()
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER retained_dispatch_authority_no_replace")
    raw.commit()
    raw.close()
    SqliteAttemptStore(path).close()
    raw = sqlite3.connect(path)
    try:
        names = {row[0] for row in raw.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        assert "retained_dispatch_authority_no_replace" in names
    finally:
        raw.close()
