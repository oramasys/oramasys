"""Consumer execution witnesses with authenticated read-back (Part 3 section 4 gates 1 to 3).

A witness is a signed, hash-chained record of what the consumer observed at the effect boundary for
one dispatch attempt. After a revocation, a cascade or a lost run, the witnesses answer "which
attempts touched revoked authority" without trusting the process that may have died. Contract:
``docs/execution-witness.md``.

No clock of its own, no cryptography and no network. Signing and verification go through injected
ports; the publication medium is an injected port. Failure is always *unavailable*, never an empty
success: a witness that is missing, unreadable, forged or out of chain makes recovery refuse, because
absence of evidence is not evidence of no affected work.

* Gate 1 (field set, encoding, identity): closed 14-field body, canonical JSON, ``witness_id`` is the
  SHA-256 of the canonical unsigned body (content-addressed), per-consumer ``sequence`` and
  ``previous_witness_id`` chain.
* Gate 2 (medium, retention, durability): a local durable ``SqliteWitnessLog`` is the source of
  truth for what *must* exist; a ``WitnessMedium`` holds the published copy; the ``retention_owner``
  is a signed field of every witness, so the accountable party travels with the record.
* Gate 3 (authenticated read-back): publication reads each object back and compares bytes before it
  is marked published; ``read_verified`` re-verifies signature, identity and chain for the whole
  logged range straight from the medium.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Protocol

from orama.graph.dispatch_consumer_wire import (
    MAX_SAFE_INTEGER,
    SCHEMA_VERSION,
    WireError,
    canonical_bytes,
    is_canonical_identifier,
    parse_timestamp,
)

OUTCOMES: Final = frozenset({"started", "committed", "aborted", "fenced", "unknown"})
SAFE_OUTCOMES: Final = frozenset({"aborted", "fenced"})
GENESIS_WITNESS_ID: Final = "0" * 64
MAX_WITNESS_BYTES: Final = 16_384
WITNESS_REFUSAL_CODES: Final = frozenset({
    "witness.malformed", "witness.duplicate", "witness.signature", "witness.identity",
    "witness.chain", "witness.unavailable", "witness.readback_mismatch",
})
_BODY_FIELDS: Final = (
    "schema_version", "consumer_id", "sequence", "previous_witness_id", "run_id", "attempt_id",
    "grant_id", "permit_id", "ledger_store_id", "outcome", "revocation_version", "recorded_at",
    "retention_owner", "signer_key_id",
)
_WIRE_FIELDS: Final = frozenset({*_BODY_FIELDS, "witness_id", "signature"})
_IDENTIFIER_FIELDS: Final = (
    "consumer_id", "run_id", "attempt_id", "grant_id", "permit_id", "ledger_store_id",
    "retention_owner", "signer_key_id",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS execution_witnesses (
    sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
    witness_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    wire TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0, 1)),
    UNIQUE(attempt_id, outcome)
);
CREATE TRIGGER IF NOT EXISTS execution_witnesses_immutable
BEFORE UPDATE OF sequence, witness_id, attempt_id, outcome, wire ON execution_witnesses
BEGIN SELECT RAISE(ABORT, 'execution witnesses are immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_witnesses_no_delete BEFORE DELETE ON execution_witnesses
BEGIN SELECT RAISE(ABORT, 'execution witnesses are append-only'); END;
"""


class WitnessRefused(Exception):
    """A closed-vocabulary witness refusal; ``code`` is stable and machine-readable."""

    def __init__(self, code: str) -> None:
        """Record the code, which must belong to the witness vocabulary."""
        if code not in WITNESS_REFUSAL_CODES:
            raise ValueError(f"unknown witness refusal code: {code}")
        super().__init__(code)
        self.code = code


class WitnessUnavailable(WitnessRefused):
    """The record cannot be shown to exist and be authentic; this is never an empty success."""


class WitnessSigner(Protocol):
    """Injected port that signs a witness id with the consumer's witness key."""

    def key_id(self) -> str:
        """Return the identifier of the active witness signing key."""

    def sign_witness(self, key_id: str, witness_id: str) -> str:
        """Return the base64url signature over the domain-separated witness id."""


class WitnessVerifier(Protocol):
    """Injected port that verifies a witness signature for a known key."""

    def verify_witness(self, key_id: str, witness_id: str, signature: str) -> bool:
        """Return True only for a valid signature by a trusted witness key."""


class WitnessMedium(Protocol):
    """Injected publication medium; ``get`` returns None only for an absent name."""

    def put(self, name: str, data: bytes) -> None:
        """Durably store ``data`` under the immutable ``name``."""

    def get(self, name: str) -> bytes | None:
        """Return the stored bytes, or None when absent."""


def _identity(body: Mapping[str, Any]) -> str:
    """Return the content-addressed witness id of an unsigned body."""
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def validate_body(body: Mapping[str, Any]) -> None:
    """Require the closed unsigned body with typed, bounded fields."""
    if not isinstance(body, Mapping) or set(body) != set(_BODY_FIELDS):
        raise WitnessRefused("witness.malformed")
    try:
        if body["schema_version"] != SCHEMA_VERSION or body["outcome"] not in OUTCOMES:
            raise WitnessRefused("witness.malformed")
        for name in _IDENTIFIER_FIELDS:
            if not is_canonical_identifier(body[name]):
                raise WitnessRefused("witness.malformed")
        for name in ("sequence", "revocation_version"):
            value = body[name]
            low = 1 if name == "sequence" else 0
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= MAX_SAFE_INTEGER:
                raise WitnessRefused("witness.malformed")
        previous = body["previous_witness_id"]
        if not isinstance(previous, str) or len(previous) != 64 or any(c not in "0123456789abcdef" for c in previous):
            raise WitnessRefused("witness.malformed")
        if (body["sequence"] == 1) != (previous == GENESIS_WITNESS_ID):
            raise WitnessRefused("witness.chain")
        parse_timestamp(body["recorded_at"])
    except WireError as error:
        raise WitnessRefused("witness.malformed") from error


def validate_wire(wire: object, verifier: WitnessVerifier) -> dict[str, Any]:
    """Return a validated witness wire dict, or raise: shape, identity, then signature."""
    if not isinstance(wire, Mapping) or set(wire) != _WIRE_FIELDS:
        raise WitnessRefused("witness.malformed")
    body = {name: wire[name] for name in _BODY_FIELDS}
    validate_body(body)
    if wire["witness_id"] != _identity(body):
        raise WitnessRefused("witness.identity")
    signature = wire["signature"]
    if not isinstance(signature, str) or not verifier.verify_witness(
        str(body["signer_key_id"]), str(wire["witness_id"]), signature
    ):
        raise WitnessRefused("witness.signature")
    return dict(wire)


def wire_bytes(wire: Mapping[str, Any]) -> bytes:
    """Return the canonical publishable bytes of a witness, size-bounded."""
    data = canonical_bytes(wire)
    if len(data) > MAX_WITNESS_BYTES:
        raise WitnessRefused("witness.malformed")
    return data


def object_name(sequence: int) -> str:
    """Return the immutable medium name of the witness at ``sequence``."""
    return f"witness-{sequence:012d}.json"


class SqliteWitnessLog:
    """Local durable source of truth for which witnesses must exist and be published."""

    def __init__(
        self, path: str | Path, *, consumer_id: str, retention_owner: str, signer: WitnessSigner,
        timeout: float = 5.0,
    ) -> None:
        """Open or create the log for one consumer; a non-durable path is refused."""
        raw = str(path)
        if raw == ":memory:" or "mode=memory" in raw:
            raise ValueError("witness log requires a durable file path")
        for name, value in (("consumer_id", consumer_id), ("retention_owner", retention_owner)):
            if not is_canonical_identifier(value):
                raise ValueError(f"{name} must be a canonical identifier")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._consumer_id, self._owner, self._signer, self._timeout = (
            consumer_id, retention_owner, signer, timeout)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Open one configured connection."""
        db = sqlite3.connect(self.path, timeout=self._timeout, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous = FULL")
        return db

    def record(
        self, *, run_id: str, attempt_id: str, grant_id: str, permit_id: str, ledger_store_id: str,
        outcome: str, revocation_version: int, recorded_at: datetime,
    ) -> dict[str, Any]:
        """Append one signed witness, or return the identical one already recorded for the pair.

        Idempotent per ``(attempt_id, outcome)``: a retry after a crash returns the existing record
        and never forks the chain.
        """
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute(
                    "SELECT wire FROM execution_witnesses WHERE attempt_id = ? AND outcome = ?",
                    (attempt_id, outcome)).fetchone()
                if existing is not None:
                    db.execute("COMMIT")
                    return _load(existing["wire"])
                tip = db.execute(
                    "SELECT sequence, witness_id FROM execution_witnesses ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if tip is None else int(tip["sequence"]) + 1
                key_id = self._signer.key_id()
                body = {
                    "schema_version": SCHEMA_VERSION, "consumer_id": self._consumer_id,
                    "sequence": sequence,
                    "previous_witness_id": GENESIS_WITNESS_ID if tip is None else tip["witness_id"],
                    "run_id": run_id, "attempt_id": attempt_id, "grant_id": grant_id,
                    "permit_id": permit_id, "ledger_store_id": ledger_store_id, "outcome": outcome,
                    "revocation_version": revocation_version,
                    "recorded_at": recorded_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    "retention_owner": self._owner, "signer_key_id": key_id,
                }
                validate_body(body)
                witness_id = _identity(body)
                wire = {**body, "witness_id": witness_id,
                        "signature": self._signer.sign_witness(key_id, witness_id)}
                db.execute(
                    "INSERT INTO execution_witnesses(sequence, witness_id, attempt_id, outcome, wire)"
                    " VALUES(?,?,?,?,?)", (sequence, witness_id, attempt_id, outcome,
                                           wire_bytes(wire).decode("utf-8")))
                db.execute("COMMIT")
                return wire
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def head(self) -> int:
        """Return the highest recorded sequence (0 when nothing was recorded)."""
        with closing(self._connect()) as db:
            return int(db.execute("SELECT COALESCE(MAX(sequence), 0) FROM execution_witnesses").fetchone()[0])

    def wires(self, low: int = 1, high: int | None = None) -> list[dict[str, Any]]:
        """Return recorded witness wires in order."""
        top = self.head() if high is None else high
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT wire FROM execution_witnesses WHERE sequence BETWEEN ? AND ? ORDER BY sequence",
                (low, top)).fetchall()
        return [_load(row["wire"]) for row in rows]

    def unpublished(self) -> list[int]:
        """Return sequences recorded locally but not yet confirmed on the medium."""
        with closing(self._connect()) as db:
            rows = db.execute("SELECT sequence FROM execution_witnesses WHERE published = 0 ORDER BY sequence")
            return [int(r["sequence"]) for r in rows]

    def mark_published(self, sequence: int) -> None:
        """Record that read-back confirmed the object on the medium."""
        with closing(self._connect()) as db:
            db.execute("UPDATE execution_witnesses SET published = 1 WHERE sequence = ?", (sequence,))


def _load(text: str) -> dict[str, Any]:
    """Decode a stored canonical wire."""
    return dict(json.loads(text))


def publish_pending(log: SqliteWitnessLog, medium: WitnessMedium, verifier: WitnessVerifier) -> int:
    """Publish every unpublished witness in order, reading each back before marking it published.

    Returns the count published. Any medium fault, missing read-back or byte difference raises
    ``WitnessUnavailable``; the witness stays unpublished so a later call retries from there.
    """
    published = 0
    for sequence in log.unpublished():
        wire = log.wires(sequence, sequence)[0]
        data = wire_bytes(validate_wire(wire, verifier))
        name = object_name(sequence)
        try:
            medium.put(name, data)
            stored = medium.get(name)
        except OSError as error:
            raise WitnessUnavailable("witness.unavailable") from error
        if stored is None:
            raise WitnessUnavailable("witness.unavailable")
        if stored != data:
            raise WitnessUnavailable("witness.readback_mismatch")
        log.mark_published(sequence)
        published += 1
    return published


def read_verified(
    log: SqliteWitnessLog, medium: WitnessMedium, verifier: WitnessVerifier
) -> list[dict[str, Any]]:
    """Return every logged witness as read back from the medium, verified end to end.

    Refuses (never returns a short list) if any logged witness is unpublished, absent, unreadable,
    differs from the local record, fails identity or signature, or breaks the chain.
    """
    out: list[dict[str, Any]] = []
    previous = GENESIS_WITNESS_ID
    for expected in log.wires():
        sequence = int(expected["sequence"])
        try:
            raw = medium.get(object_name(sequence))
        except OSError as error:
            raise WitnessUnavailable("witness.unavailable") from error
        if raw is None:
            raise WitnessUnavailable("witness.unavailable")
        try:
            wire = validate_wire(json.loads(raw.decode("utf-8")), verifier)
        except (UnicodeDecodeError, ValueError) as error:
            raise WitnessUnavailable("witness.malformed") from error
        if wire_bytes(wire) != raw:
            raise WitnessUnavailable("witness.malformed")
        if wire != expected:
            raise WitnessUnavailable("witness.readback_mismatch")
        if wire["previous_witness_id"] != previous or wire["sequence"] != len(out) + 1:
            raise WitnessUnavailable("witness.chain")
        previous = str(wire["witness_id"])
        out.append(wire)
    return out


def affected_attempts(
    witnesses: Sequence[Mapping[str, Any]], *, revoked_grants: frozenset[str]
) -> list[str]:
    """Return attempts under a revoked grant that have no safe terminal witness, in order.

    An attempt is *affected* if any witness shows it ``started``, ``committed`` or ``unknown`` and no
    witness shows it ``aborted`` or ``fenced``. The input must come from :func:`read_verified`; this
    function never treats an empty list from an unverified source as "nothing affected".
    """
    seen: dict[str, set[str]] = {}
    order: list[str] = []
    for witness in witnesses:
        if witness["grant_id"] not in revoked_grants:
            continue
        attempt = str(witness["attempt_id"])
        if attempt not in seen:
            order.append(attempt)
        seen.setdefault(attempt, set()).add(str(witness["outcome"]))
    return [a for a in order if not seen[a] & SAFE_OUTCOMES]
