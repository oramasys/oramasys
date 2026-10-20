"""E1 "C2" consumer store: durable attempts, the fence and the step 4.3 transaction.

Oramasys owns consumer attempts, fences, grant-use consumption, intents and the
outbox. It holds NO cryptography: signatures are checked only through the injected
``SignatureVerifier`` port, and no issuer call is ever made here. ``authorize_dispatch``
checks the six rules of the spec's step 4.3 in one ``BEGIN IMMEDIATE`` transaction and
writes nothing unless every rule holds.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, TypeAlias

from orama.graph.dispatch_consumer_wire import (
    GENESIS_EVENT_DIGEST,
    _sha256_hex,
    canonical_bytes,
    SignatureVerifier,
    WireError,
    event_digest,
    finalization_body,
    finalization_digest,
    parse_timestamp,
    permit_body,
    permit_payload_digest,
    validate_event_wire,
    validate_finalization_wire,
    validate_permit_wire,
)
from orama.graph.effect_outcomes import OutcomeRefused, check_transition
from orama.graph.effect_proposals import (
    PROPOSAL_SCHEMA,
    EffectScope,
    bind_scope_to_permit,
    consume_reservation,
    record_proposal,
    reserve,
)
from orama.graph.private_store import prepare_private_store

AuthorizationRule: TypeAlias = Literal["rule1", "rule2", "rule3", "rule4", "rule5", "rule6"]

AUTHORIZATION_RULES: Final[frozenset[str]] = frozenset(
    {"rule1", "rule2", "rule3", "rule4", "rule5", "rule6"}
)
_BUSY_TIMEOUT_SECONDS: Final = 30.0
_LIVE_STATES: Final = frozenset({"created", "transmitted"})
_MAX_LIFETIME: Final = timedelta(seconds=90)
MAX_CLOCK_SKEW_TOLERANCE: Final = timedelta(minutes=5)
_DIVERGENCE_REASONS: Final = frozenset({"divergence", "event_digest_mismatch"})
_OUTBOX_REQUIRED: Final = (
    "permit_id", "permit_digest", "finalization_digest", "r_p", "r_f", "authority_pair",
    "acked_through",
)


class AuthorizationRefused(Exception):
    """Step 4.3 refusal naming the failing rule from the closed rule set."""

    def __init__(
        self,
        rule: AuthorizationRule,
        reason: str,
        fork: tuple[int, str, str] | None = None,
    ) -> None:
        """Record the failing rule (validated against the closed set), reason, fork."""
        if rule not in AUTHORIZATION_RULES:
            raise ValueError(f"invalid authorization rule {rule!r}")
        super().__init__(f"{rule}: {reason}")
        self.rule = rule
        self.reason = reason
        self.fork = fork


class OperatorAuthority(Protocol):
    """Injected port that authenticates the operator for an audited administrative action."""

    def authorize(self, operation: str, *, subject: str) -> str | None:
        """Return a non-blank operator reference, or None when the caller is not authorized."""


class OperatorRefused(Exception):
    """The operator port did not authorize the call; nothing was read or written."""


class IssuerOutcomeAuthenticator(Protocol):
    """Trusted adapter bound to the expected issuer and its authenticated response evidence."""

    def verify(self, outcome: str, record: Mapping[str, str]) -> bool:
        """Authenticate the exact outcome and complete record against issuer response evidence.

        Matching identifiers alone is insufficient. Implementations must verify a signed response
        or bind these values to a response obtained over an authenticated issuer channel.
        """
        ...


class IssuerOutcomeRefused(Exception):
    """Issuer response authentication failed; no abandonment or release was recorded."""


class ClockQuarantined(Exception):
    """Dispatch is quarantined because the consumer clock stepped backward; ``reason`` is a code."""

    def __init__(self, reason: str) -> None:
        """Record the stable machine-readable refusal reason."""
        super().__init__(reason)
        self.reason = reason


class AttemptStateError(Exception):
    """An attempt transition is not allowed in the attempt's current state."""


class AttemptAlreadyCommitted(AttemptStateError):
    """The attempt already committed at step 4.3, so it can no longer be fenced."""


class EventRefused(Exception):
    """An issuer event was refused; ``reason`` is ``divergence`` when a fork was flagged."""

    def __init__(self, reason: str) -> None:
        """Record why the event batch was refused."""
        super().__init__(reason)
        self.reason = reason


class RevocationPort(Protocol):
    """Consumer view of acknowledged issuer events that revoke a grant."""

    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        """Return True if any acknowledged event of any version revokes the grant.

        An implementation MUST also return True when any acknowledged event of any
        version revokes the grant's approval chain or the issuer.
        """
        ...


class GatePort(Protocol):
    """Consumer-owned gates: role revision, authority epoch, ownership, fencing, lease."""

    def check(
        self,
        *,
        attempt_id: str,
        grant_id: str,
        reservation_id: str,
        authority_pair: str,
        now: datetime,
    ) -> bool:
        """Return True only if every consumer-owned gate still holds."""
        ...


@dataclass(frozen=True, slots=True)
class ExpectedBinding:
    """Consumer-side facts a permit must be bound to (the permit's own are signed)."""

    request_digest: str
    artifact_digest: str
    configuration_policy_epoch: int
    authority_epoch: int
    ledger_store_id: str

    def authority_pair(self) -> str:
        """Return the effective authority pair as one stable string."""
        return f"{self.configuration_policy_epoch}:{self.authority_epoch}"


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """A durable dispatch attempt row."""

    attempt_id: str
    grant_id: str
    reservation_id: str
    state: str
    fenced: bool
    transmitted: bool
    permit_id: str | None


_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS dispatch_attempts ("
    " attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, reservation_id TEXT NOT NULL,"
    " state TEXT NOT NULL, fenced INTEGER NOT NULL DEFAULT 0,"
    " transmitted INTEGER NOT NULL DEFAULT 0, permit_id TEXT, permit_digest TEXT,"
    " finalization_digest TEXT, r_p INTEGER, r_f INTEGER, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS issuer_cascade_ack ("
    " issuer_id TEXT NOT NULL, version INTEGER NOT NULL, event_digest TEXT NOT NULL,"
    " applied_at TEXT NOT NULL, PRIMARY KEY (issuer_id, version))",
    "CREATE TABLE IF NOT EXISTS issuer_divergence ("
    " issuer_id TEXT PRIMARY KEY, version INTEGER NOT NULL, stored_digest TEXT NOT NULL,"
    " offered_digest TEXT NOT NULL, flagged_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS grant_use ("
    " grant_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, consumed_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_intents ("
    " attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, permit_id TEXT NOT NULL UNIQUE,"
    " permit_digest TEXT NOT NULL, finalization_digest TEXT NOT NULL UNIQUE,"
    " r_p INTEGER NOT NULL, r_f INTEGER NOT NULL, authority_pair TEXT NOT NULL,"
    " acked_through INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS outbox ("
    " attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, permit_id TEXT NOT NULL,"
    " permit_digest TEXT NOT NULL, finalization_digest TEXT NOT NULL, r_p INTEGER NOT NULL,"
    " r_f INTEGER NOT NULL, authority_pair TEXT NOT NULL, acked_through INTEGER NOT NULL,"
    " payload TEXT,"
    " outcome TEXT NOT NULL DEFAULT 'unknown' CHECK (outcome IN"
    " ('confirmed', 'failed', 'unknown')),"
    " outcome_evidence TEXT,"
    " send_started INTEGER NOT NULL DEFAULT 0 CHECK (send_started IN (0, 1)))",
    *PROPOSAL_SCHEMA,
    "CREATE TABLE IF NOT EXISTS clock_high_water ("
    " id INTEGER PRIMARY KEY CHECK (id = 1), utc TEXT NOT NULL,"
    " quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1)))",
    "CREATE TABLE IF NOT EXISTS clock_reconciliations ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT, reconciled_by TEXT NOT NULL,"
    " trusted_time_evidence TEXT NOT NULL, previous_utc TEXT NOT NULL, accepted_utc TEXT NOT NULL,"
    " expired_reservations INTEGER NOT NULL, recorded_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS abandon_attestations ("
    " attempt_id TEXT PRIMARY KEY, permit_id TEXT NOT NULL, attestation_digest TEXT NOT NULL,"
    " attestation TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS abandon_outcomes ("
    " attempt_id TEXT PRIMARY KEY, permit_id TEXT NOT NULL, outcome TEXT NOT NULL,"
    " attestation_digest TEXT NOT NULL, disposition_ref TEXT NOT NULL,"
    " issuer_recorded_at TEXT NOT NULL, release_authorized INTEGER NOT NULL DEFAULT 1"
    " CHECK (release_authorized = 1), recorded_at TEXT NOT NULL)",
)
_ABANDON_CAUSES: Final = frozenset({"transient_delay", "cancellation", "loss"})
_ABANDON_OUTCOMES: Final = frozenset({"abandon.recorded", "abandon.already_abandoned"})
_OUTBOX_T3_COLUMNS: Final = (
    ("outcome", "TEXT NOT NULL DEFAULT 'unknown' CHECK (outcome IN"
     " ('confirmed', 'failed', 'unknown'))"),
    ("outcome_evidence", "TEXT"),
    ("send_started", "INTEGER NOT NULL DEFAULT 0 CHECK (send_started IN (0, 1))"),
)


def _now_text(now: datetime) -> str:
    """Return the instant as UTC ISO text."""
    return now.astimezone(UTC).isoformat()


def _require_aware(now: datetime) -> None:
    """Fail closed on a naive clock reading."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be an aware datetime")


def _require_text(name: str, value: object) -> None:
    """Fail closed on blank or non-text identifiers."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")


def _acked_through(db: sqlite3.Connection, issuer_id: str) -> int:
    """Return the contiguous acknowledged high-water mark for an issuer."""
    mark = 0
    for (version,) in db.execute(
        "SELECT version FROM issuer_cascade_ack WHERE issuer_id = ? ORDER BY version",
        (issuer_id,),
    ):
        if version != mark + 1:
            break
        mark = version
    return mark


def _stored_digest(db: sqlite3.Connection, issuer_id: str, version: int) -> str | None:
    """Return the stored event digest at ``version`` or None."""
    row = db.execute(
        "SELECT event_digest FROM issuer_cascade_ack WHERE issuer_id = ? AND version = ?",
        (issuer_id, version),
    ).fetchone()
    return None if row is None else row[0]


def _diverged(db: sqlite3.Connection, issuer_id: str) -> bool:
    """Return True if a divergence is recorded for the issuer."""
    row = db.execute(
        "SELECT 1 FROM issuer_divergence WHERE issuer_id = ?", (issuer_id,)
    ).fetchone()
    return row is not None


def _require_unexpired(rule: AuthorizationRule, expires_at: str, now: datetime) -> None:
    """Refuse strictly: a permit or finalization is dead when ``now >= expires_at``."""
    if now >= parse_timestamp(expires_at):
        raise AuthorizationRefused(rule, "expired")


def _require_lifetime(rule: AuthorizationRule, issued_at: str, expires_at: str) -> None:
    """Refuse a lifetime that is not positive or exceeds the 90 second cap."""
    lifetime = parse_timestamp(expires_at) - parse_timestamp(issued_at)
    if lifetime <= timedelta(0) or lifetime > _MAX_LIFETIME:
        raise AuthorizationRefused(rule, "lifetime_exceeds_cap")


def _load_attempt(db: sqlite3.Connection, attempt_id: str) -> AttemptRecord:
    """Load an attempt row or fail closed on an unknown attempt."""
    row = db.execute(
        "SELECT attempt_id, grant_id, reservation_id, state, fenced, transmitted, permit_id"
        " FROM dispatch_attempts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown attempt_id {attempt_id!r}")
    return AttemptRecord(row[0], row[1], row[2], row[3], bool(row[4]), bool(row[5]), row[6])


def _check_rule1(
    db: sqlite3.Connection,
    attempt: AttemptRecord,
    permit: Mapping[str, Any],
    now: datetime,
    verifier: SignatureVerifier,
    expected: ExpectedBinding,
) -> None:
    """Rule 1: permit authentic, bound, strictly unexpired and not already recorded."""
    body = permit_body(permit)
    if not verifier.verify_permit(permit["issuer_key_id"], body, permit["issuer_signature"]):
        raise AuthorizationRefused("rule1", "permit_signature")
    if permit_payload_digest(body) != permit["payload_digest"]:
        raise AuthorizationRefused("rule1", "permit_digest")
    bound = (
        permit["grant_id"] == attempt.grant_id
        and permit["attempt_id"] == attempt.attempt_id
        and permit["reservation_id"] == attempt.reservation_id
        and permit["ledger_store_id"] == expected.ledger_store_id
        and permit["request_digest"] == expected.request_digest
        and permit["artifact_digest"] == expected.artifact_digest
        and (permit["configuration_policy_epoch"], permit["authority_epoch"])
        == (expected.configuration_policy_epoch, expected.authority_epoch)
    )
    if not bound:
        raise AuthorizationRefused("rule1", "permit_binding")
    _require_lifetime("rule1", permit["issued_at"], permit["expires_at"])
    _require_unexpired("rule1", permit["expires_at"], now)
    seen = db.execute(
        "SELECT 1 FROM dispatch_intents WHERE permit_id = ?", (permit["permit_id"],)
    ).fetchone()
    if seen is not None:
        raise AuthorizationRefused("rule1", "permit_already_recorded")


def _check_acks(
    db: sqlite3.Connection, issuer_id: str, permit: Mapping[str, Any]
) -> None:
    """Rules 2 and 3: acknowledgement covers R_p, and R_p covers the permit's ack."""
    if _acked_through(db, issuer_id) < permit["revocation_version"]:
        raise AuthorizationRefused("rule2", "acked_through_below_r_p")
    if permit["revocation_version"] < permit["consumer_acked_through"]:
        raise AuthorizationRefused("rule3", "r_p_below_permit_acked_through")


def _check_finalization(
    db: sqlite3.Connection,
    attempt: AttemptRecord,
    permit: Mapping[str, Any],
    fin: Mapping[str, Any],
    now: datetime,
    verifier: SignatureVerifier,
    issuer_id: str,
    expected: ExpectedBinding,
) -> None:
    """Rule 5 binding, freshness and ordering checks (before the event is built)."""
    if not verifier.verify_finalization(
        permit["issuer_key_id"], finalization_body(fin), fin["issuer_signature"]
    ):
        raise AuthorizationRefused("rule5", "finalization_signature")
    bound = (
        fin["permit_id"] == permit["permit_id"]
        and fin["permit_digest"] == permit["payload_digest"]
        and fin["attempt_id"] == attempt.attempt_id
        and fin["reservation_id"] == attempt.reservation_id
        and fin["ledger_store_id"] == permit["ledger_store_id"]
        and fin["ledger_store_id"] == expected.ledger_store_id
        and fin["authority_epoch"] == permit["authority_epoch"]
    )
    if not bound:
        raise AuthorizationRefused("rule5", "finalization_binding")
    _require_lifetime("rule5", fin["issued_at"], fin["expires_at"])
    if parse_timestamp(fin["expires_at"]) > parse_timestamp(permit["expires_at"]):
        raise AuthorizationRefused("rule5", "finalization_outlives_permit")
    _require_unexpired("rule5", fin["expires_at"], now)
    digest = _fin_digest(fin)
    if db.execute(
        "SELECT 1 FROM dispatch_intents WHERE finalization_digest = ?", (digest,)
    ).fetchone():
        raise AuthorizationRefused("rule5", "finalization_already_recorded")
    r_f = fin["revocation_version"]
    if r_f <= permit["revocation_version"] or r_f <= fin["consumer_acked_through"]:
        raise AuthorizationRefused("rule5", "r_f_not_above_floors")
    if _acked_through(db, issuer_id) < r_f - 1:
        raise AuthorizationRefused("rule5", "acked_through_below_r_f_minus_1")


def _fin_digest(fin: Mapping[str, Any]) -> str:
    """Return the finalization digest recorded in the intent and outbox."""
    return finalization_digest(finalization_body(fin))


def _check_event(
    db: sqlite3.Connection, fin: Mapping[str, Any], issuer_id: str, now: datetime
) -> None:
    """Rule 5 event step: rebuild the wrapper, compare, refuse forks, then record R_f."""
    r_f = fin["revocation_version"]
    previous = GENESIS_EVENT_DIGEST if r_f == 1 else _stored_digest(db, issuer_id, r_f - 1)
    if previous is None or _diverged(db, issuer_id):
        raise AuthorizationRefused("rule5", "divergence_or_gap")
    body = {"finalization_id": fin["finalization_id"]}
    computed = event_digest(r_f, "finalization", body, previous)
    if computed != fin["revocation_event_digest"]:
        raise AuthorizationRefused(
            "rule5", "event_digest_mismatch", (r_f, computed, fin["revocation_event_digest"])
        )
    stored = _stored_digest(db, issuer_id, r_f)
    if stored is not None and stored != computed:
        raise AuthorizationRefused("rule5", "divergence", (r_f, stored, computed))
    if stored is None:
        db.execute(
            "INSERT INTO issuer_cascade_ack (issuer_id, version, event_digest, applied_at)"
            " VALUES (?, ?, ?, ?)",
            (issuer_id, r_f, computed, _now_text(now)),
        )


def _record_fork(
    db: sqlite3.Connection, issuer_id: str, fork: tuple[int, str, str], now: datetime
) -> None:
    """Record an issuer divergence flag (idempotent per issuer)."""
    db.execute(
        "INSERT OR IGNORE INTO issuer_divergence (issuer_id, version,"
        " stored_digest, offered_digest, flagged_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, *fork, _now_text(now)),
    )


def _check_rule6(
    db: sqlite3.Connection,
    attempt: AttemptRecord,
    gates: GatePort,
    authority_pair: str,
    now: datetime,
) -> None:
    """Rule 6: consumer gates hold, the attempt is not fenced, the use is unconsumed."""
    if attempt.state not in _LIVE_STATES:
        raise AuthorizationRefused("rule6", "attempt_not_live")
    if not gates.check(
        attempt_id=attempt.attempt_id,
        grant_id=attempt.grant_id,
        reservation_id=attempt.reservation_id,
        authority_pair=authority_pair,
        now=now,
    ):
        raise AuthorizationRefused("rule6", "gate_failed")
    if attempt.fenced:
        raise AuthorizationRefused("rule6", "attempt_fenced")
    used = db.execute(
        "SELECT 1 FROM grant_use WHERE grant_id = ?", (attempt.grant_id,)
    ).fetchone()
    if used is not None:
        raise AuthorizationRefused("rule6", "grant_use_consumed")


def _write_authorization(
    db: sqlite3.Connection,
    attempt: AttemptRecord,
    permit: Mapping[str, Any],
    fin: Mapping[str, Any],
    issuer_id: str,
    authority_pair: str,
    now: datetime,
) -> None:
    """Consume the use and write the intent and the complete outbox item."""
    values = {
        "permit_id": permit["permit_id"],
        "permit_digest": permit["payload_digest"],
        "finalization_digest": _fin_digest(fin),
        "r_p": permit["revocation_version"],
        "r_f": fin["revocation_version"],
        "authority_pair": authority_pair,
        "acked_through": _acked_through(db, issuer_id),
    }
    db.execute(
        "INSERT INTO grant_use (grant_id, attempt_id, consumed_at) VALUES (?, ?, ?)",
        (attempt.grant_id, attempt.attempt_id, _now_text(now)),
    )
    columns = ", ".join(_OUTBOX_REQUIRED)
    marks = ", ".join("?" for _ in _OUTBOX_REQUIRED)
    row = (attempt.attempt_id, attempt.grant_id, *(values[c] for c in _OUTBOX_REQUIRED))
    db.execute(
        f"INSERT INTO dispatch_intents (attempt_id, grant_id, {columns}) VALUES (?, ?, {marks})",
        row,
    )
    db.execute(
        f"INSERT INTO outbox (attempt_id, grant_id, {columns}) VALUES (?, ?, {marks})", row
    )
    db.execute(
        "UPDATE dispatch_attempts SET state = 'authorized', permit_id = ?, permit_digest = ?,"
        " finalization_digest = ?, r_p = ?, r_f = ? WHERE attempt_id = ?",
        (
            values["permit_id"], values["permit_digest"], values["finalization_digest"],
            values["r_p"], values["r_f"], attempt.attempt_id,
        ),
    )


class SqliteAttemptStore:
    """Durable consumer attempt store; every write is one ``BEGIN IMMEDIATE`` transaction."""

    def __init__(
        self,
        path: Path | str,
        *,
        governed: bool = False,
        clock_skew_tolerance: timedelta = timedelta(0),
        abandon_authenticator: IssuerOutcomeAuthenticator | None = None,
    ) -> None:
        """Open (creating privately) the WAL-mode store and its schema.

        ``governed`` makes ``authorize_dispatch`` require a matching, live, unused reservation
        for the attempt's reservation id. It defaults to False only so slice-1 callers keep
        working; any serving path must construct the store with ``governed=True``.

        ``clock_skew_tolerance`` is the signed-policy skew a backward clock step may stay within
        before dispatch is quarantined. The specification leaves the value to signed policy, so the
        default is zero (any backward step quarantines); a value above ``MAX_CLOCK_SKEW_TOLERANCE``
        is refused as a misconfiguration guard. A tolerated step never lowers the high-water mark.

        ``abandon_authenticator`` must bind responses to the expected issuer and verify their
        complete contents. Without it, abandonment outcomes are refused before any write.
        """
        if (
            not isinstance(clock_skew_tolerance, timedelta)
            or clock_skew_tolerance < timedelta(0)
            or clock_skew_tolerance > MAX_CLOCK_SKEW_TOLERANCE
        ):
            raise ValueError("clock_skew_tolerance must be a timedelta from zero to five minutes")
        self._clock_skew = clock_skew_tolerance
        self._abandon_authenticator = abandon_authenticator
        prepared = prepare_private_store(path)
        self._governed = governed
        self._lock = threading.Lock()
        self._db = sqlite3.connect(
            str(prepared),
            isolation_level=None,
            check_same_thread=False,
            timeout=_BUSY_TIMEOUT_SECONDS,
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        for statement in _SCHEMA:
            self._db.execute(statement)
        self._migrate_outbox()

    def _migrate_outbox(self) -> None:
        """Add the T3 outcome columns to an outbox created before they existed."""
        present = {row[1] for row in self._db.execute("PRAGMA table_info(outbox)")}
        for name, definition in _OUTBOX_T3_COLUMNS:
            if name not in present:
                self._db.execute(f"ALTER TABLE outbox ADD COLUMN {name} {definition}")

    def close(self) -> None:
        """Close the underlying connection."""
        self._db.close()

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        """Run a ``BEGIN IMMEDIATE`` transaction, committing or rolling back."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def create_attempt(self, attempt_id: str, grant_id: str, reservation_id: str) -> None:
        """Durably record the attempt BEFORE any issuer call (idempotent when identical)."""
        for name, value in (
            ("attempt_id", attempt_id), ("grant_id", grant_id), ("reservation_id", reservation_id),
        ):
            _require_text(name, value)
        with self._immediate() as db:
            row = db.execute(
                "SELECT grant_id, reservation_id FROM dispatch_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is not None:
                if tuple(row) != (grant_id, reservation_id):
                    raise AttemptStateError("attempt_id already exists with a different binding")
                return
            db.execute(
                "INSERT INTO dispatch_attempts (attempt_id, grant_id, reservation_id, state,"
                " created_at) VALUES (?, ?, ?, 'created', ?)",
                (attempt_id, grant_id, reservation_id, _now_text(datetime.now(UTC))),
            )

    def get_attempt(self, attempt_id: str) -> AttemptRecord | None:
        """Return the attempt row, or None if it does not exist."""
        with self._lock:
            try:
                return _load_attempt(self._db, attempt_id)
            except ValueError:
                return None

    def mark_transmitted(self, attempt_id: str) -> None:
        """Record that the first issuer call may have started (durable, never undone)."""
        with self._immediate() as db:
            attempt = _load_attempt(db, attempt_id)
            state = "transmitted" if attempt.state == "created" else attempt.state
            db.execute(
                "UPDATE dispatch_attempts SET transmitted = 1, state = ? WHERE attempt_id = ?",
                (state, attempt_id),
            )

    def record_unavailable(self, attempt_id: str) -> None:
        """End the attempt as unavailable; the reservation stays HELD, nothing is released."""
        with self._immediate() as db:
            attempt = _load_attempt(db, attempt_id)
            if attempt.state == "authorized":
                raise AttemptAlreadyCommitted(attempt_id)
            db.execute(
                "UPDATE dispatch_attempts SET state = 'unavailable' WHERE attempt_id = ?",
                (attempt_id,),
            )

    def fence(self, attempt_id: str) -> None:
        """Set the terminal fence unless the attempt already committed at step 4.3."""
        with self._immediate() as db:
            attempt = _load_attempt(db, attempt_id)
            committed = db.execute(
                "SELECT 1 FROM grant_use WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt.state == "authorized" or committed is not None:
                raise AttemptAlreadyCommitted(attempt_id)
            db.execute(
                "UPDATE dispatch_attempts SET fenced = 1 WHERE attempt_id = ?", (attempt_id,)
            )

    def acked_through(self, issuer_id: str) -> int:
        """Return the contiguous acknowledged issuer version high-water mark."""
        with self._lock:
            return _acked_through(self._db, issuer_id)

    def is_diverged(self, issuer_id: str) -> bool:
        """Return True if a divergence is recorded for the issuer."""
        with self._lock:
            return _diverged(self._db, issuer_id)

    def ingest_events(
        self,
        issuer_id: str,
        events: Sequence[Mapping[str, Any]],
        verifier: SignatureVerifier,
    ) -> None:
        """Verify and record contiguous issuer events; a fork is flagged and refused."""
        _require_text("issuer_id", issuer_id)
        fork: tuple[int, str, str] | None = None
        now = datetime.now(UTC)
        with self._immediate() as db:
            for raw in events:
                try:
                    event = validate_event_wire(raw)
                except WireError as error:
                    raise EventRefused("malformed") from error
                fork = self._ingest_one(db, issuer_id, event, verifier, now)
                if fork is not None:
                    _record_fork(db, issuer_id, fork, now)
                    break
        if fork is not None:
            raise EventRefused("divergence")

    @staticmethod
    def _ingest_one(
        db: sqlite3.Connection,
        issuer_id: str,
        event: Mapping[str, Any],
        verifier: SignatureVerifier,
        now: datetime,
    ) -> tuple[int, str, str] | None:
        """Ingest one event; return fork details on divergence, raise on other refusals."""
        version = event["version"]
        signed = verifier.verify_event(
            event["issuer_key_id"], event["event_digest"], event["signature"]
        )
        if not signed:
            raise EventRefused("event_signature")
        claimed_previous = event["previous_event_digest"]
        computed = event_digest(version, event["kind"], event["body"], claimed_previous)
        if computed != event["event_digest"]:
            raise EventRefused("event_digest")
        stored = _stored_digest(db, issuer_id, version)
        if stored is not None:
            return None if stored == computed else (version, stored, computed)
        previous = GENESIS_EVENT_DIGEST
        if version > 1:
            previous = _stored_digest(db, issuer_id, version - 1)
        if previous is None:
            raise EventRefused("gap")
        if previous != claimed_previous:
            return (version - 1, previous, claimed_previous)
        db.execute(
            "INSERT INTO issuer_cascade_ack (issuer_id, version, event_digest, applied_at)"
            " VALUES (?, ?, ?, ?)",
            (issuer_id, version, computed, _now_text(now)),
        )
        return None

    def authorize_dispatch(
        self,
        attempt_id: str,
        permit_wire: Mapping[str, Any],
        finalization_wire: Mapping[str, Any],
        now: datetime,
        *,
        verifier: SignatureVerifier,
        gates: GatePort,
        revocations: RevocationPort,
        issuer_id: str,
        expected: ExpectedBinding,
        scope: EffectScope | None = None,
    ) -> None:
        """Step 4.3: check the six rules and write intent, use and outbox atomically.

        A governed store also consumes the attempt's reservation in the same transaction.
        """
        _require_aware(now)
        _require_text("issuer_id", issuer_id)
        if self._governed:
            self.observe_clock(now)
        try:
            self._authorize_in_transaction(
                attempt_id, permit_wire, finalization_wire, now,
                verifier, gates, revocations, issuer_id, expected, scope,
            )
        except AuthorizationRefused as refusal:
            if (
                refusal.rule == "rule5"
                and refusal.reason in _DIVERGENCE_REASONS
                and refusal.fork is not None
            ):
                with self._immediate() as db:
                    _record_fork(db, issuer_id, refusal.fork, now)
            raise

    def _authorize_in_transaction(
        self,
        attempt_id: str,
        permit_wire: Mapping[str, Any],
        finalization_wire: Mapping[str, Any],
        now: datetime,
        verifier: SignatureVerifier,
        gates: GatePort,
        revocations: RevocationPort,
        issuer_id: str,
        expected: ExpectedBinding,
        scope: EffectScope | None,
    ) -> None:
        """Run the six rules inside one rolled-back-on-refusal transaction."""
        with self._immediate() as db:
            attempt = _load_attempt(db, attempt_id)
            if self._governed:
                clock = db.execute(
                    "SELECT quarantined FROM clock_high_water WHERE id = 1"
                ).fetchone()
                if clock is None or clock[0]:
                    raise ClockQuarantined("clock_quarantined")
                consume_reservation(db, attempt.reservation_id, attempt_id, scope, now)
            try:
                permit = validate_permit_wire(permit_wire)
                fin = validate_finalization_wire(finalization_wire)
            except WireError as error:
                raise AuthorizationRefused("rule1", "malformed_wire") from error
            _check_rule1(db, attempt, permit, now, verifier, expected)
            if self._governed:
                bind_scope_to_permit(scope, permit)
            _check_acks(db, issuer_id, permit)
            if revocations.revoked(grant_id=attempt.grant_id, issuer_id=issuer_id):
                raise AuthorizationRefused("rule4", "grant_revoked")
            _check_finalization(db, attempt, permit, fin, now, verifier, issuer_id, expected)
            _check_event(db, fin, issuer_id, now)
            pair = expected.authority_pair()
            _check_rule6(db, attempt, gates, pair, now)
            _write_authorization(db, attempt, permit, fin, issuer_id, pair, now)

    def observe_clock(self, now: datetime) -> None:
        """Advance the durable UTC high-water mark; a backward step quarantines dispatch.

        The mark survives restarts. Once quarantined, every call refuses until
        ``clear_clock_quarantine`` records an authenticated operator reconciliation.
        """
        _require_aware(now)
        stamp = _now_text(now)
        regressed = False
        with self._immediate() as db:
            row = db.execute("SELECT utc, quarantined FROM clock_high_water WHERE id = 1").fetchone()
            if row is None:
                db.execute("INSERT INTO clock_high_water (id, utc) VALUES (1, ?)", (stamp,))
            elif row[1]:
                raise ClockQuarantined("clock_quarantined")
            else:
                mark = datetime.fromisoformat(row[0])
                if now < mark - self._clock_skew:
                    db.execute("UPDATE clock_high_water SET quarantined = 1 WHERE id = 1")
                    regressed = True
                elif now > mark:
                    db.execute("UPDATE clock_high_water SET utc = ? WHERE id = 1", (stamp,))
        if regressed:
            raise ClockQuarantined("clock_regressed")

    def clear_clock_quarantine(
        self,
        *,
        operator: OperatorAuthority,
        trusted_time_evidence: str,
        accepted_at: datetime,
        now: datetime,
    ) -> None:
        """Recover from a backward-clock alarm as an audited administrative action.

        Per the approved clock policy it needs an authenticated operator and trusted-time evidence,
        records the previous and the accepted timestamps in an append-only log, and revalidates every
        pending reservation: one that had already expired at the previous mark is marked expired for
        good, so the accepted (possibly earlier) time cannot revive it. Consumed, revoked and uncertain
        authority is never revived because nothing here un-consumes or un-revokes anything.
        """
        reference = operator.authorize("clear_clock_quarantine", subject="clock")
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to clear a clock quarantine")
        _require_text("trusted_time_evidence", trusted_time_evidence)
        _require_aware(accepted_at)
        _require_aware(now)
        with self._immediate() as db:
            row = db.execute("SELECT utc, quarantined FROM clock_high_water WHERE id = 1").fetchone()
            if row is None or not row[1]:
                raise AttemptStateError("no clock quarantine to clear")
            previous = datetime.fromisoformat(row[0])
            expired = 0
            pending = db.execute(
                "SELECT reservation_id, expires_at FROM reservations WHERE consumed_attempt_id IS NULL"
            ).fetchall()
            for reservation_id, expires_at in pending:
                if datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC) <= previous:
                    db.execute(
                        "UPDATE reservations SET consumed_attempt_id = ? WHERE reservation_id = ?",
                        (f"expired:{reservation_id}", reservation_id),
                    )
                    expired += 1
            db.execute(
                "INSERT INTO clock_reconciliations (reconciled_by, trusted_time_evidence, previous_utc,"
                " accepted_utc, expired_reservations, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    reference, trusted_time_evidence, _now_text(previous), _now_text(accepted_at),
                    expired, _now_text(now),
                ),
            )
            db.execute(
                "UPDATE clock_high_water SET utc = ?, quarantined = 0 WHERE id = 1",
                (_now_text(accepted_at),),
            )

    def build_abandon_attestation(
        self, attempt_id: str, permit_id: str, cause: str, fencing_epoch: int, now: datetime
    ) -> dict[str, Any]:
        """Build (and durably keep) the abandon attestation for a fenced, uncommitted attempt.

        The fence must already be committed and step 4.3 must not have committed. The attestation is
        the consumer's own statement; the issuer records it as audit evidence and does not verify it.
        """
        _require_text("permit_id", permit_id)
        _require_aware(now)
        if cause not in _ABANDON_CAUSES:
            raise AttemptStateError("cause must be transient_delay, cancellation or loss")
        if isinstance(fencing_epoch, bool) or not isinstance(fencing_epoch, int) or fencing_epoch < 1:
            raise AttemptStateError("fencing_epoch must be an integer of at least 1")
        with self._immediate() as db:
            attempt = _load_attempt(db, attempt_id)
            committed = db.execute(
                "SELECT 1 FROM grant_use WHERE attempt_id = ? UNION ALL"
                " SELECT 1 FROM dispatch_intents WHERE attempt_id = ?",
                (attempt_id, attempt_id),
            ).fetchone()
            if not attempt.fenced:
                raise AttemptStateError("the fence must be committed before attesting")
            if committed is not None or attempt.state == "authorized":
                raise AttemptStateError("step 4.3 committed for the attempt; it cannot be abandoned")
            stored = db.execute(
                "SELECT permit_id, attestation_digest, attestation FROM abandon_attestations"
                " WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if stored is not None:
                try:
                    kept = json.loads(stored[2])
                except json.JSONDecodeError as error:
                    raise AttemptStateError("stored abandon attestation is invalid") from error
                if not isinstance(kept, dict) or _sha256_hex(canonical_bytes(kept)) != stored[1]:
                    raise AttemptStateError("stored abandon attestation is invalid")
                if (
                    stored[0] != permit_id
                    or kept.get("cause") != cause
                    or kept.get("consumer_fencing_epoch") != fencing_epoch
                ):
                    raise AttemptStateError("a different attestation already exists for the attempt")
                return kept
            body = {
                "attempt_id": attempt_id, "permit_id": permit_id, "cause": cause,
                "consumer_fencing_epoch": fencing_epoch,
                "fence_evidence": f"fence committed for attempt {attempt_id} in state {attempt.state}",
                "non_commit_evidence": "no grant_use row and no dispatch_intents row for the attempt",
                "release_pending_record": f"reservation {attempt.reservation_id} release pending",
                "no_intent_exists": True,
            }
            digest = _sha256_hex(canonical_bytes(body))
            db.execute(
                "INSERT INTO abandon_attestations (attempt_id, permit_id, attestation_digest,"
                " attestation, created_at) VALUES (?, ?, ?, ?, ?)",
                (attempt_id, permit_id, digest, canonical_bytes(body).decode("utf-8"), _now_text(now)),
            )
            return body

    def record_abandon_outcome(
        self, attempt_id: str, outcome: str, record: Mapping[str, Any], now: datetime
    ) -> None:
        """Durably record the authenticated issuer abandon outcome and end the attempt.

        The record must name this attempt and permit and carry the digest of the attestation this
        store built. The outcome authorizes the reservation release (``release_authorized``);
        performing the release belongs to the reservation owner and reads this record. Idempotent
        for the same immutable disposition, including Phylax's ``abandon.already_abandoned``
        retry response. The injected authenticator must authenticate every response, including retries.
        """
        _require_aware(now)
        if outcome not in _ABANDON_OUTCOMES:
            raise AttemptStateError("unknown abandon outcome")
        fields = {"attempt_id", "permit_id", "attestation_digest", "disposition_ref", "recorded_at"}
        authenticated_record = dict(record)
        if set(authenticated_record) != fields:
            raise AttemptStateError("the abandon record has invalid fields")
        for name, value in authenticated_record.items():
            _require_text(name, value)
        if self._abandon_authenticator is None or self._abandon_authenticator.verify(
            outcome, MappingProxyType(authenticated_record)
        ) is not True:
            raise IssuerOutcomeRefused("issuer abandon outcome is not authenticated")
        record = authenticated_record
        with self._immediate() as db:
            sent = db.execute(
                "SELECT permit_id, attestation_digest FROM abandon_attestations WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if sent is None:
                raise AttemptStateError("no attestation was built for the attempt")
            if (
                record.get("attempt_id") != attempt_id
                or record.get("permit_id") != sent[0]
                or record.get("attestation_digest") != sent[1]
            ):
                raise AttemptStateError("the abandon record does not match the attestation sent")
            reference = record.get("disposition_ref")
            issuer_at = record.get("recorded_at")
            _require_text("disposition_ref", reference)
            _require_text("recorded_at", issuer_at)
            existing = db.execute(
                "SELECT permit_id, attestation_digest, disposition_ref, issuer_recorded_at"
                " FROM abandon_outcomes WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if existing is not None:
                # Both success labels refer to the same immutable Phylax disposition.
                if tuple(existing) != (sent[0], sent[1], reference, issuer_at):
                    raise AttemptStateError("a different abandon outcome is already recorded")
                return
            db.execute(
                "INSERT INTO abandon_outcomes (attempt_id, permit_id, outcome, attestation_digest,"
                " disposition_ref, issuer_recorded_at, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (attempt_id, sent[0], outcome, sent[1], reference, issuer_at, _now_text(now)),
            )
            db.execute(
                "UPDATE dispatch_attempts SET state = 'abandoned' WHERE attempt_id = ?", (attempt_id,)
            )

    def abandon_outcome(self, attempt_id: str) -> dict[str, Any] | None:
        """Return the recorded abandon outcome for the attempt, or None."""
        with self._lock:
            cursor = self._db.execute("SELECT * FROM abandon_outcomes WHERE attempt_id = ?", (attempt_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(zip((c[0] for c in cursor.description), row, strict=True))

    def propose(self, proposal_id: str, scope: EffectScope, now: datetime) -> None:
        """Durably record a proposal; it carries no authorization state."""
        _require_text("proposal_id", proposal_id)
        _require_aware(now)
        with self._immediate() as db:
            record_proposal(db, proposal_id, scope, now)

    def reserve(
        self,
        reservation_id: str,
        proposal_id: str,
        scope: EffectScope,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        """Bind the proposal's scope to a single-use, expiring reservation."""
        _require_text("reservation_id", reservation_id)
        _require_aware(now)
        _require_aware(expires_at)
        with self._immediate() as db:
            reserve(db, reservation_id, proposal_id, scope, expires_at, now)

    def begin_send(self, attempt_id: str) -> None:
        """Durably mark the one allowed send as started; a second send is always refused."""
        with self._immediate() as db:
            row = db.execute(
                "SELECT send_started FROM outbox WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise AttemptStateError("no authorized outbox row for the attempt")
            attempt = _load_attempt(db, attempt_id)
            complete = db.execute(
                "SELECT " + " AND ".join(f"{c} IS NOT NULL AND {c} != ''" for c in _OUTBOX_REQUIRED)
                + " FROM outbox WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if attempt.fenced or attempt.state != "authorized" or not complete[0]:
                raise OutcomeRefused("send_precondition_failed")
            if row[0]:
                raise OutcomeRefused("send_already_started")
            db.execute("UPDATE outbox SET send_started = 1 WHERE attempt_id = ?", (attempt_id,))

    def record_outcome(
        self, attempt_id: str, outcome: str, evidence_ref: str | None = None
    ) -> None:
        """Settle ``unknown`` to ``confirmed`` or ``failed`` with an evidence reference."""
        with self._immediate() as db:
            row = db.execute(
                "SELECT outcome, send_started FROM outbox WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise AttemptStateError("no authorized outbox row for the attempt")
            current, started = row
            if not started:
                raise OutcomeRefused("send_not_started")
            check_transition(current, outcome, evidence_ref)
            db.execute(
                "UPDATE outbox SET outcome = ?, outcome_evidence = ? WHERE attempt_id = ?",
                (outcome, evidence_ref, attempt_id),
            )

    def outbox_row(self, attempt_id: str) -> dict[str, Any] | None:
        """Return the outbox row for the attempt as a dict, or None."""
        with self._lock:
            cursor = self._db.execute("SELECT * FROM outbox WHERE attempt_id = ?", (attempt_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(zip((c[0] for c in cursor.description), row, strict=True))


def sender_precondition(store: SqliteAttemptStore, attempt_id: str) -> bool:
    """Return True only if the attempt has a complete outbox row (no missing required field)."""
    row = store.outbox_row(attempt_id)
    if row is None:
        return False
    return all(row.get(name) not in (None, "") for name in _OUTBOX_REQUIRED)
