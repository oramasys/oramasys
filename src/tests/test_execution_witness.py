"""Execution witnesses: closed encoding, content-addressed identity, authenticated read-back."""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from orama.graph import execution_witness
from orama.graph.dispatch_consumer_wire import canonical_bytes
from orama.graph.execution_witness import (
    GENESIS_WITNESS_ID,
    SqliteWitnessLog,
    WitnessRefused,
    WitnessUnavailable,
    affected_attempts,
    object_name,
    publish_pending,
    read_verified,
    validate_body,
    validate_wire,
)

NOW = datetime(2026, 11, 2, 4, 0, 0, tzinfo=UTC)


def tag(key: str, witness_id: str) -> str:
    """Return a deterministic test signature (the production adapter lives outside src/orama)."""
    return "sig-" + hashlib.sha256(f"{key}|{witness_id}".encode()).hexdigest()


class Signer:
    """Test signer port."""

    def __init__(self, key: str = "wk-1") -> None:
        """Choose the key id."""
        self.key = key

    def key_id(self) -> str:
        """Return the key id."""
        return self.key

    def sign_witness(self, key_id: str, witness_id: str) -> str:
        """Return the test signature."""
        return tag(key_id, witness_id)


class Verifier:
    """Test verifier port trusting one key."""

    def verify_witness(self, key_id: str, witness_id: str, signature: str) -> bool:
        """Accept only the matching test signature from the trusted key."""
        return key_id == "wk-1" and signature == tag(key_id, witness_id)


class Medium:
    """In-memory medium with injectable faults."""

    def __init__(self) -> None:
        """Start empty and healthy."""
        self.objects: dict[str, bytes] = {}
        self.drop_reads = False
        self.fail_puts = False
        self.corrupt = False

    def put(self, name: str, data: bytes) -> None:
        """Store or fail."""
        if self.fail_puts:
            raise OSError("medium down")
        self.objects[name] = data

    def get(self, name: str) -> bytes | None:
        """Read, drop or corrupt."""
        if self.drop_reads:
            return None
        data = self.objects.get(name)
        return None if data is None else (data[:-1] + b"X" if self.corrupt else data)


@pytest.fixture
def log(tmp_path: Path) -> SqliteWitnessLog:
    """Return a fresh witness log."""
    return SqliteWitnessLog(
        tmp_path / "w.db", consumer_id="consumer-1", retention_owner="ops-archive", signer=Signer())


def rec(log, attempt: str, outcome: str, grant: str = "g1"):
    """Record one witness."""
    return log.record(
        run_id="run-1", attempt_id=attempt, grant_id=grant, permit_id="permit-" + attempt,
        ledger_store_id="ledger-1", outcome=outcome, revocation_version=4, recorded_at=NOW)


def test_witness_identity_is_content_addressed_and_chained(log) -> None:
    """The id is the digest of the canonical unsigned body; each witness links to the previous."""
    first, second = rec(log, "a1", "started"), rec(log, "a1", "committed")
    body = {k: v for k, v in first.items() if k not in ("witness_id", "signature")}
    assert first["witness_id"] == hashlib.sha256(canonical_bytes(body)).hexdigest()
    assert (first["sequence"], first["previous_witness_id"]) == (1, GENESIS_WITNESS_ID)
    assert (second["sequence"], second["previous_witness_id"]) == (2, first["witness_id"])
    assert first["retention_owner"] == "ops-archive" and first["consumer_id"] == "consumer-1"


def test_record_is_idempotent_per_attempt_and_outcome(log) -> None:
    """A retry returns the identical witness and never forks the chain."""
    assert rec(log, "a1", "started") == rec(log, "a1", "started")
    assert log.head() == 1


def test_log_is_immutable_and_append_only(log) -> None:
    """Rows cannot be edited or deleted in place."""
    rec(log, "a1", "started")
    with closing(sqlite3.connect(log.path)) as db:
        for sql in ("UPDATE execution_witnesses SET outcome='aborted'", "DELETE FROM execution_witnesses",
                    "UPDATE execution_witnesses SET wire='{}'"):
            with pytest.raises(sqlite3.DatabaseError):
                db.execute(sql)


def test_body_validation_is_closed(log) -> None:
    """Missing, extra, mistyped or out-of-vocabulary fields are malformed; genesis pairing is enforced."""
    wire = rec(log, "a1", "started")
    body = {k: v for k, v in wire.items() if k not in ("witness_id", "signature")}
    validate_body(body)
    bad_cases = [
        {**body, "extra": 1}, {k: v for k, v in body.items() if k != "run_id"},
        {**body, "outcome": "done"}, {**body, "sequence": 0}, {**body, "sequence": True},
        {**body, "attempt_id": "has space"}, {**body, "recorded_at": "yesterday"},
        {**body, "previous_witness_id": "zz"}, {**body, "revocation_version": -1},
    ]
    for bad in bad_cases:
        with pytest.raises(WitnessRefused):
            validate_body(bad)
    with pytest.raises(WitnessRefused) as chain:
        validate_body({**body, "previous_witness_id": "a" * 64})
    assert chain.value.code == "witness.chain"


def test_publish_reads_back_and_read_verified_returns_every_witness(log) -> None:
    """Publishing confirms each object; the verified read returns the full logged range."""
    medium = Medium()
    rec(log, "a1", "started")
    rec(log, "a1", "committed")
    assert publish_pending(log, medium, Verifier()) == 2 and log.unpublished() == []
    assert publish_pending(log, medium, Verifier()) == 0
    assert [w["sequence"] for w in read_verified(log, medium, Verifier())] == [1, 2]
    assert set(medium.objects) == {object_name(1), object_name(2)}


@pytest.mark.parametrize("fault,code", [
    ("drop_reads", "witness.unavailable"), ("fail_puts", "witness.unavailable"),
    ("corrupt", "witness.readback_mismatch"),
])
def test_publication_faults_are_unavailable_and_leave_the_witness_unpublished(log, fault, code) -> None:
    """A medium that drops, fails or corrupts is unavailable; the witness stays queued for retry."""
    medium = Medium()
    setattr(medium, fault, True)
    rec(log, "a1", "started")
    with pytest.raises(WitnessUnavailable) as caught:
        publish_pending(log, medium, Verifier())
    assert caught.value.code == code and log.unpublished() == [1]
    setattr(medium, fault, False)
    assert publish_pending(log, medium, Verifier()) == 1


def test_read_verified_refuses_missing_unpublished_forged_and_swapped_records(log) -> None:
    """Every defect is unavailable; a short list is never returned."""
    medium = Medium()
    rec(log, "a1", "started")
    rec(log, "a2", "started")
    with pytest.raises(WitnessUnavailable):  # nothing published yet
        read_verified(log, medium, Verifier())
    publish_pending(log, medium, Verifier())
    good = dict(medium.objects)
    medium.objects.pop(object_name(2))
    with pytest.raises(WitnessUnavailable) as missing:
        read_verified(log, medium, Verifier())
    assert missing.value.code == "witness.unavailable"
    medium.objects = dict(good)
    forged = json.loads(good[object_name(2)])
    forged["signature"] = "sig-forged"
    medium.objects[object_name(2)] = canonical_bytes(forged)
    with pytest.raises(WitnessRefused) as bad_sig:
        read_verified(log, medium, Verifier())
    assert bad_sig.value.code == "witness.signature"
    medium.objects = dict(good)
    medium.objects[object_name(1)], medium.objects[object_name(2)] = good[object_name(2)], good[object_name(1)]
    with pytest.raises(WitnessUnavailable):
        read_verified(log, medium, Verifier())
    medium.objects = dict(good)
    medium.objects[object_name(1)] = b"not json"
    with pytest.raises(WitnessUnavailable) as junk:
        read_verified(log, medium, Verifier())
    assert junk.value.code == "witness.malformed"


def test_identity_tamper_and_foreign_key_are_refused(log) -> None:
    """Changing any field breaks the content-addressed id; an untrusted key fails the signature."""
    wire = rec(log, "a1", "started")
    with pytest.raises(WitnessRefused) as identity:
        validate_wire({**wire, "outcome": "aborted"}, Verifier())
    assert identity.value.code == "witness.identity"
    other = SqliteWitnessLog(
        log.path.parent / "o.db", consumer_id="consumer-1", retention_owner="ops", signer=Signer("wk-9"))
    foreign = rec(other, "a1", "started")
    with pytest.raises(WitnessRefused) as signature:
        validate_wire(foreign, Verifier())
    assert signature.value.code == "witness.signature"


def test_affected_attempts_excludes_safely_terminated_work(log) -> None:
    """Started/committed/unknown work under a revoked grant is affected unless aborted or fenced."""
    rec(log, "a1", "started")
    rec(log, "a2", "started")
    rec(log, "a2", "aborted")
    rec(log, "a3", "committed")
    rec(log, "a4", "unknown")
    rec(log, "a5", "fenced")
    rec(log, "a6", "started", grant="g2")
    assert affected_attempts(log.wires(), revoked_grants=frozenset({"g1"})) == ["a1", "a3", "a4"]
    assert affected_attempts(log.wires(), revoked_grants=frozenset()) == []


def test_recovery_cannot_read_an_empty_medium_as_nothing_affected(log) -> None:
    """The verified read refuses when witnesses exist locally but the medium is empty."""
    rec(log, "a1", "started")
    with pytest.raises(WitnessUnavailable):
        read_verified(log, Medium(), Verifier())
    assert SqliteWitnessLog(
        log.path.parent / "empty.db", consumer_id="c", retention_owner="o", signer=Signer(),
    ).head() == 0


def test_constructor_and_vocabulary_guards(tmp_path) -> None:
    """Non-durable paths, bad identifiers and unknown codes are rejected; no crypto is imported."""
    with pytest.raises(ValueError):
        SqliteWitnessLog(":memory:", consumer_id="c", retention_owner="o", signer=Signer())
    with pytest.raises(ValueError):
        SqliteWitnessLog(tmp_path / "x.db", consumer_id="bad id", retention_owner="o", signer=Signer())
    with pytest.raises(ValueError):
        WitnessRefused("witness.invented")
    tree = ast.parse(inspect.getsource(execution_witness))
    imported = {
        (n.module or "").split(".")[0] if isinstance(n, ast.ImportFrom) else a.name.split(".")[0]
        for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert not imported & {"nacl", "cryptography", "hmac", "socket", "urllib", "requests"}
