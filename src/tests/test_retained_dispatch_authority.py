"""Retained signed dispatch authority remains an inert audit prerequisite."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import AuthorizationRefused, SqliteAttemptStore
from orama.graph.dispatch_consumer_wire import canonical_bytes, permit_body, permit_payload_digest
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
        assert store._db.execute(
            "SELECT permit_wire, finalization_wire FROM retained_dispatch_authority"
        ).fetchone() == (canonical_bytes(permit), canonical_bytes(fin))
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


def test_retained_constructor_snapshots_caller_mappings(tmp_path: Path) -> None:
    store, verifier, permit, fin = _authorize(tmp_path)
    try:
        retained = replace(store.retained_dispatch_authority(ATTEMPT), permit=permit, finalization=fin)
        permit["grant_id"] = "replacement"
        fin["reservation_id"] = "replacement"
        assert retained.grant_id == GRANT
        assert retained.reverify(verifier) is True
        with pytest.raises(TypeError):
            retained.finalization["reservation_id"] = "replacement"
    finally:
        store.close()


@pytest.mark.parametrize("change", ["digest", "reservation_id", "ledger_store_id", "authority_epoch"])
def test_reverify_refuses_broken_immutable_linkage(tmp_path: Path, change: str) -> None:
    store, verifier, permit, fin = _authorize(tmp_path)
    try:
        if change == "digest":
            permit["payload_digest"] = fin["permit_digest"] = "0" * 64
        else:
            fin[change] = 999 if change == "authority_epoch" else "replacement"
        retained = replace(store.retained_dispatch_authority(ATTEMPT), permit=permit, finalization=fin)
        assert retained.reverify(verifier) is False
    finally:
        store.close()


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "INSERT OR REPLACE", "REPLACE"])
def test_retention_is_append_only(tmp_path: Path, operation: str) -> None:
    store, _verifier, _permit, _fin = _authorize(tmp_path)
    try:
        before = store._db.execute("SELECT * FROM retained_dispatch_authority").fetchone()
        sql = {
            "UPDATE": "UPDATE retained_dispatch_authority SET issuer_id = 'replacement'",
            "DELETE": "DELETE FROM retained_dispatch_authority",
        }.get(operation, f"{operation} INTO retained_dispatch_authority VALUES (?, ?, ?, ?)")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._db.execute(sql, () if operation in {"UPDATE", "DELETE"} else before)
        assert store._db.execute("SELECT * FROM retained_dispatch_authority").fetchone() == before
    finally:
        store.close()


@pytest.mark.parametrize("table, assignment", [
    ("dispatch_attempts", "grant_id = 'replacement'"),
    ("dispatch_attempts", "reservation_id = 'replacement'"),
    ("dispatch_attempts", "permit_digest = 'replacement'"),
    ("dispatch_attempts", "finalization_digest = 'replacement'"),
    ("dispatch_intents", "permit_id = 'replacement'"),
    ("outbox", "finalization_digest = 'replacement'"),
    ("send_authority", "issuer_id = 'replacement'"),
])
def test_read_requires_matching_committed_authorization(tmp_path: Path, table: str, assignment: str) -> None:
    store, _verifier, _permit, _fin = _authorize(tmp_path)
    try:
        store._db.execute(f"UPDATE {table} SET {assignment} WHERE attempt_id = ?", (ATTEMPT,))
        assert store.retained_dispatch_authority(ATTEMPT) is None
    finally:
        store.close()


@pytest.mark.parametrize("column", ["permit_wire", "finalization_wire"])
@pytest.mark.parametrize("damage", ["digest", "substitution", "noncanonical", "invalid_utf8", "surrogate", "deep", "text", "integer"])
def test_malformed_or_substituted_retention_is_unavailable(tmp_path: Path, damage: str, column: str) -> None:
    store, _verifier, permit, fin = _authorize(tmp_path)
    try:
        store._db.execute("DROP TRIGGER retained_dispatch_authority_no_update")
        if damage == "digest":
            permit["payload_digest"] = fin["permit_digest"] = "0" * 64
        if damage == "substitution":
            permit["grant_id"] = "replacement"
            permit["payload_digest"] = permit_payload_digest(permit_body(permit))
            fin["permit_digest"] = permit["payload_digest"]
        target = permit if column == "permit_wire" else fin
        wire = {
            "noncanonical": json.dumps(target).encode(),
            "invalid_utf8": b'"\xff"',
            "surrogate": json.dumps({**target, "reservation_id": "\ud800"}).encode(),
            "deep": b"[" * 2000 + b"]" * 2000,
            "text": json.dumps(target),
            "integer": 100,
        }.get(damage, canonical_bytes(target))
        wires = {"permit_wire": canonical_bytes(permit), "finalization_wire": canonical_bytes(fin)}
        wires[column] = wire
        store._db.execute(
            "UPDATE retained_dispatch_authority SET permit_wire = ?, finalization_wire = ?",
            (wires["permit_wire"], wires["finalization_wire"]),
        )
        assert store.retained_dispatch_authority(ATTEMPT) is None
    finally:
        store.close()


def test_retention_insert_failure_rolls_back_authorization(tmp_path: Path) -> None:
    store = SqliteAttemptStore(tmp_path / "attempts.sqlite")
    flow = vector_flow()
    verifier = FakeVerifier()
    try:
        store._create_attempt(ATTEMPT, GRANT, RESERVATION)
        store.ingest_events(ISSUER, flow.chain[: flow.permit["revocation_version"]], verifier)
        store._db.execute("CREATE TRIGGER fail_retention BEFORE INSERT ON retained_dispatch_authority "
                          "BEGIN SELECT RAISE(ABORT, 'injected retention failure'); END")
        before = store._db.execute("SELECT * FROM dispatch_attempts").fetchall()
        with pytest.raises(sqlite3.IntegrityError, match="injected retention failure"):
            store.authorize_dispatch(ATTEMPT, flow.permit, flow.fin, NOW, verifier=verifier,
                                     gates=FakeGates(), revocations=FakeRevocations(),
                                     issuer_id=ISSUER, expected=EXPECTED)
        assert store._db.execute("SELECT * FROM dispatch_attempts").fetchall() == before
        for table in ("grant_use", "dispatch_intents", "outbox", "send_authority", "retained_dispatch_authority"):
            assert store._db.execute(f"SELECT * FROM {table}").fetchall() == []
    finally:
        store.close()


def test_legacy_migration_never_reconstructs_evidence(tmp_path: Path) -> None:
    store, _verifier, _permit, _fin = _authorize(tmp_path)
    store._db.execute("DROP TABLE retained_dispatch_authority")
    store.close()
    for _ in range(3):
        reopened = SqliteAttemptStore(tmp_path / "attempts.sqlite")
        try:
            assert reopened.outbox_row(ATTEMPT) is not None
            assert reopened.retained_dispatch_authority(ATTEMPT) is None
            assert reopened._db.execute("SELECT count(*) FROM retained_dispatch_authority").fetchone() == (0,)
        finally:
            reopened.close()


@pytest.mark.parametrize("port", ["permit_ok", "finalization_ok"])
def test_reverify_requires_both_verifier_decisions(tmp_path: Path, port: str) -> None:
    store, verifier, permit, _fin = _authorize(tmp_path)
    try:
        retained = store.retained_dispatch_authority(ATTEMPT)
        verifier.calls.clear()
        setattr(verifier, port, False)
        assert retained.reverify(verifier) is False
        assert verifier.calls[0] == f'permit:{permit["issuer_key_id"]}'
        if port == "finalization_ok":
            assert verifier.calls[1] == f'finalization:{permit["issuer_key_id"]}'
    finally:
        store.close()
