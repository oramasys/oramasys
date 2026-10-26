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
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, TypeAlias

from orama.graph import dispatch_anchor, dispatch_revocations
from orama.graph.dispatch_anchor import ANCHOR_SCHEMA, TrustedIssuerKeys
from orama.graph.dispatch_consumer_wire import (
    GENESIS_EVENT_DIGEST,
    _sha256_hex,
    canonical_bytes,
    SignatureVerifier,
    WireError,
    event_digest,
    finalization_body,
    finalization_digest,
    is_canonical_identifier,
    parse_timestamp,
    permit_body,
    permit_payload_digest,
    validate_event_wire,
    validate_finalization_wire,
    validate_permit_wire,
)
from orama.graph import effect_fencing
from orama.graph.effect_fencing import FENCING_SCHEMA, FencingRefused, StoredRefusal
from orama.graph.effect_outcomes import OutcomeRefused, check_transition
from orama.graph.effect_proposals import (
    PROPOSAL_SCHEMA,
    EffectScope,
    ReservationRefused,
    bind_scope_to_permit,
    consume_reservation,
    record_proposal,
    reserve,
)
from orama.graph import effect_approvals, effect_reconciliation, effect_receipts
from orama.graph.effect_approvals import APPROVAL_SCHEMA
from orama.graph.effect_reconciliation import RECONCILIATION_SCHEMA
from orama.graph.effect_receipts import RECEIPT_SCHEMA, RedactedReceipt, StoredReceipt
from orama.graph.final_boundary import (
    FinalBoundaryBinding,
    FinalBoundaryRefused,
    StoredBinding,
    check_store_facts,
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
    second_approval_ref: str | None = None
    """The grant's approval binding: None undeclared, "" single approval, else the approval id."""


@dataclass(frozen=True, slots=True)
class VerifiedDispatchGrant:
    """Dispatch-grant facts produced by the future verified-v2 composition boundary.

    This is intentionally distinct from adjustment-grant verification.  The
    consumer accepts these facts only after a trusted adapter has verified the
    v2 dispatch grant; the store then copies the approval binding durably before
    any issuer call. This is a plain value object: the store checks its type and
    canonical identifiers, not where the facts came from. That provenance is
    held by the composition adapter that builds it, which is outside this slice.
    """

    grant_id: str
    second_approval_ref: str = ""

    def __post_init__(self) -> None:
        """Refuse malformed dispatch-grant facts before persistence."""
        _require_text("grant_id", self.grant_id)
        if self.second_approval_ref and not is_canonical_identifier(self.second_approval_ref):
            raise ValueError("second_approval_ref must be empty or a canonical identifier")


_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS effect_grant_bindings ("
    " attempt_id TEXT PRIMARY KEY, grant_wire BLOB NOT NULL, context TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS send_authority ("
    " attempt_id TEXT PRIMARY KEY, issuer_id TEXT NOT NULL, expires_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dispatch_attempts ("
    " attempt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, reservation_id TEXT NOT NULL,"
    " state TEXT NOT NULL, fenced INTEGER NOT NULL DEFAULT 0,"
    " transmitted INTEGER NOT NULL DEFAULT 0, permit_id TEXT, permit_digest TEXT,"
    " finalization_digest TEXT, r_p INTEGER, r_f INTEGER, created_at TEXT NOT NULL,"
    " second_approval_ref TEXT)",
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
    *FENCING_SCHEMA,
    *RECEIPT_SCHEMA,
    *APPROVAL_SCHEMA,
    *RECONCILIATION_SCHEMA,
    *ANCHOR_SCHEMA,
    *dispatch_revocations.REVOCATION_SCHEMA,
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
    """Return the contiguous acknowledged high-water mark for an issuer.

    With a persisted anchor base N the sequence is checkpoint-aware: it starts at N and never
    claims acknowledgements below N. Without one it starts at version 1.
    """
    base = dispatch_anchor.base_version(db, issuer_id)
    mark = 0 if base is None else base - 1
    for (version,) in db.execute(
        "SELECT version FROM issuer_cascade_ack WHERE issuer_id = ? AND version > ?"
        " ORDER BY version",
        (issuer_id, mark),
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
        "SELECT attempt_id, grant_id, reservation_id, state, fenced, transmitted, permit_id,"
        " second_approval_ref FROM dispatch_attempts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown attempt_id {attempt_id!r}")
    return AttemptRecord(
        row[0], row[1], row[2], row[3], bool(row[4]), bool(row[5]), row[6], row[7]
    )


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
        self._migrate_attempts()
        self._migrate_fencing()

    def _migrate_outbox(self) -> None:
        """Add the T3 outcome columns to an outbox created before they existed."""
        present = {row[1] for row in self._db.execute("PRAGMA table_info(outbox)")}
        for name, definition in _OUTBOX_T3_COLUMNS:
            if name not in present:
                self._db.execute(f"ALTER TABLE outbox ADD COLUMN {name} {definition}")

    def _migrate_attempts(self) -> None:
        """Add the approval binding column to an attempts table created before it existed.

        Existing rows get NULL, which Rule 4 treats as undeclared and so fails closed whenever
        the issuer has revoked any approval.
        """
        present = {row[1] for row in self._db.execute("PRAGMA table_info(dispatch_attempts)")}
        if "second_approval_ref" not in present:
            self._db.execute("ALTER TABLE dispatch_attempts ADD COLUMN second_approval_ref TEXT")

    def _migrate_fencing(self) -> None:
        """Add the explicit integer fencing epoch to an attempts table created before it existed.

        Existing rows get NULL: an attempt that was never stamped has no epoch and so can never
        pass a final-boundary epoch check.
        """
        present = {row[1] for row in self._db.execute("PRAGMA table_info(dispatch_attempts)")}
        if "fencing_epoch" not in present:
            self._db.execute("ALTER TABLE dispatch_attempts ADD COLUMN fencing_epoch INTEGER")

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

    def create_attempt(
        self,
        attempt_id: str,
        verified_grant: VerifiedDispatchGrant,
        reservation_id: str,
    ) -> None:
        """Persist a verified dispatch grant's binding before any issuer contact.

        The composition adapter must verify the v2 dispatch grant before it
        builds ``VerifiedDispatchGrant``.  The store copies that object into
        durable attempt state and exposes no authorizing-caller approval
        parameter on this public boundary.
        """
        if not isinstance(verified_grant, VerifiedDispatchGrant):
            raise TypeError("verified_grant must be a VerifiedDispatchGrant")
        self._create_attempt(
            attempt_id,
            verified_grant.grant_id,
            reservation_id,
            second_approval_ref=verified_grant.second_approval_ref,
        )

    def _create_attempt(
        self,
        attempt_id: str,
        grant_id: str,
        reservation_id: str,
        *,
        second_approval_ref: str | None = None,
    ) -> None:
        """Persist a fixture or migration attempt binding (idempotent when identical).

        This private primitive exists only for fixture construction (tests and the
        interop probes). It is not the migration path: attempts that predate the
        binding column are migrated in place by ``_migrate_attempts``, which leaves
        them NULL. Production composition must use ``create_attempt``. A ``None``
        binding records an undeclared attempt, which Rule 4 refuses whenever the
        issuer has revoked any approval. The leading underscore is a convention, not
        enforcement.
        """
        for name, value in (
            ("attempt_id", attempt_id), ("grant_id", grant_id), ("reservation_id", reservation_id),
        ):
            _require_text(name, value)
        if second_approval_ref not in (None, "") and not is_canonical_identifier(
            second_approval_ref
        ):
            raise ValueError("second_approval_ref must be empty or a canonical identifier")
        with self._immediate() as db:
            row = db.execute(
                "SELECT grant_id, reservation_id, second_approval_ref FROM dispatch_attempts"
                " WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is not None:
                if tuple(row) != (grant_id, reservation_id, second_approval_ref):
                    raise AttemptStateError("attempt_id already exists with a different binding")
                return
            db.execute(
                "INSERT INTO dispatch_attempts (attempt_id, grant_id, reservation_id, state,"
                " created_at, second_approval_ref) VALUES (?, ?, ?, 'created', ?, ?)",
                (
                    attempt_id, grant_id, reservation_id, _now_text(datetime.now(UTC)),
                    second_approval_ref,
                ),
            )

    def get_attempt(self, attempt_id: str) -> AttemptRecord | None:
        """Return the attempt row, or None if it does not exist."""
        with self._lock:
            try:
                return _load_attempt(self._db, attempt_id)
            except ValueError:
                return None

    def bind_effect_grant(self, attempt_id: str, wire: bytes, context: Mapping[str, Any]) -> None:
        """Persist immutable verified request facts; a partially prepared attempt cannot send."""
        encoded = json.dumps(dict(context), sort_keys=True, separators=(",", ":"))
        with self._immediate() as db:
            _load_attempt(db, attempt_id)
            prior = db.execute("SELECT grant_wire, context FROM effect_grant_bindings WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if prior is not None:
                if tuple(prior) != (wire, encoded):
                    raise AttemptStateError("effect grant binding conflict")
                return
            db.execute("INSERT INTO effect_grant_bindings VALUES (?, ?, ?)", (attempt_id, wire, encoded))

    def effect_grant_binding(self, attempt_id: str) -> tuple[bytes, dict[str, Any]]:
        """Return the immutable authority context required by the trusted sender."""
        with self._lock:
            row = self._db.execute("SELECT grant_wire, context FROM effect_grant_bindings WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise OutcomeRefused("effect_grant_binding_missing")
            return bytes(row[0]), json.loads(row[1])

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
        """Ingest one event; return fork details on divergence, raise on other refusals.

        An anchor establishes a monotonic epoch floor. Events below it are
        rejected rather than backfilled; an audited recovery protocol would be
        a separate operation, not a normal ingest exception.
        """
        version = event["version"]
        base = dispatch_anchor.base_version(db, issuer_id)
        if base is not None and version < base:
            raise EventRefused("below_anchor")
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
        dispatch_revocations.record(db, issuer_id, event)
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
        Rule 4 reads the approval binding persisted by ``create_attempt``; the authorizing
        caller cannot supply or omit it.
        """
        _require_aware(now)
        _require_text("issuer_id", issuer_id)
        if self._governed:
            self.observe_clock(now)
        try:
            clock_refusal = self._authorize_in_transaction(
                attempt_id, permit_wire, finalization_wire, now,
                verifier, gates, revocations, issuer_id, expected, scope,
            )
            if clock_refusal is not None:
                raise ClockQuarantined(clock_refusal)
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
    ) -> str | None:
        """Check clock and authorization atomically; commit a clock latch before refusing."""
        with self._immediate() as db:
            attempt = _load_attempt(db, attempt_id)
            kept = effect_fencing.stored_refusal(db, attempt_id)
            if kept is not None:
                # A saved terminal refusal wins; it is decided under the same lock as the authorization.
                raise _raise_stored(kept)
            dispatch_anchor.assert_not_quarantined(db, issuer_id)
            if self._governed:
                clock = db.execute(
                    "SELECT utc, quarantined FROM clock_high_water WHERE id = 1"
                ).fetchone()
                if clock is None or clock[1]:
                    raise ClockQuarantined("clock_quarantined")
                if now < datetime.fromisoformat(clock[0]) - self._clock_skew:
                    # Return before any authority mutation so the context commits the
                    # quarantine latch; the public boundary raises after that commit.
                    db.execute("UPDATE clock_high_water SET quarantined = 1 WHERE id = 1")
                    return "clock_regressed"
                consume_reservation(db, attempt.reservation_id, attempt_id, scope, now)
            try:
                permit = validate_permit_wire(permit_wire)
                fin = validate_finalization_wire(finalization_wire)
            except WireError as error:
                raise AuthorizationRefused("rule1", "malformed_wire") from error
            _check_rule1(db, attempt, permit, now, verifier, expected)
            binding = db.execute("SELECT context FROM effect_grant_bindings WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if binding is not None:
                context = json.loads(binding[0])
                if scope is None or scope.principal != context["principal"]:
                    raise AuthorizationRefused("rule1", "effect_grant_principal")
                if (permit["grant_payload_digest"], permit["operation_id"], permit["request_digest"], permit["ledger_store_id"]) != (
                    context["payload_digest"], context["operation_id"], context["request_digest"], context["ledger_store_id"],
                ):
                    raise AuthorizationRefused("rule1", "effect_grant_binding")
            if self._governed:
                bind_scope_to_permit(scope, permit)
            dispatch_anchor.assert_permit_at_or_above_floor(
                db, issuer_id, permit["revocation_version"]
            )
            _check_acks(db, issuer_id, permit)
            if revocations.revoked(grant_id=attempt.grant_id, issuer_id=issuer_id):
                raise AuthorizationRefused("rule4", "grant_revoked")
            fact = dispatch_revocations.refusal_reason(
                db, issuer_id, attempt.grant_id, attempt.second_approval_ref
            )
            if fact is not None:
                raise AuthorizationRefused("rule4", fact)
            _check_finalization(db, attempt, permit, fin, now, verifier, issuer_id, expected)
            _check_event(db, fin, issuer_id, now)
            pair = expected.authority_pair()
            _check_rule6(db, attempt, gates, pair, now)
            try:
                effect_fencing.admit_epoch(db, expected.authority_epoch)
            except FencingRefused as refused:
                raise AuthorizationRefused("rule6", refused.reason) from refused
            _write_authorization(db, attempt, permit, fin, issuer_id, pair, now)
            effect_fencing.stamp_attempt(db, attempt_id, expected.authority_epoch)
            db.execute(
                "INSERT INTO send_authority VALUES (?, ?, ?)",
                (attempt_id, issuer_id, min(permit["expires_at"], fin["expires_at"])),
            )

    def fencing_epoch(self, attempt_id: str) -> int | None:
        """Return the integer fencing epoch the attempt was authorized under, or None."""
        with self._lock:
            return effect_fencing.attempt_epoch(self._db, attempt_id)

    def current_fencing_epoch(self) -> int | None:
        """Return the store's current fencing epoch, or None before any authorization."""
        with self._lock:
            return effect_fencing.current_epoch(self._db)

    def advance_fencing_epoch(
        self, epoch: int, *, operator: OperatorAuthority, now: datetime
    ) -> None:
        """Raise the current fencing epoch strictly, as an authenticated and logged operator action.

        Every attempt authorized under a lower epoch is thereafter stale at the final boundary.
        """
        reference = operator.authorize("advance_fencing_epoch", subject="fencing")
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to advance the fencing epoch")
        _require_aware(now)
        with self._immediate() as db:
            try:
                effect_fencing.advance_epoch(db, epoch, reference, now)
            except FencingRefused as refused:
                raise AttemptStateError(refused.reason) from refused

    def attempt_binding(self, attempt_id: str) -> StoredBinding | None:
        """Return what the store durably recorded for the attempt's final-boundary tuple, or None.

        Principal, operation digest and target come from the scope the reservation consumed for this
        attempt; the expiry is that reservation's expiry; the epoch is the one stamped in the
        authorization transaction. Read-only.
        """
        with self._lock:
            return _binding_in(self._db, attempt_id)

    def revocation_refusal(self, attempt_id: str, issuer_id: str) -> str | None:
        """Return the locally recorded Rule 4 revocation reason for the attempt, or None."""
        _require_text("issuer_id", issuer_id)
        with self._lock:
            attempt = _load_attempt(self._db, attempt_id)
            return dispatch_revocations.refusal_reason(
                self._db, issuer_id, attempt.grant_id, attempt.second_approval_ref
            )

    def terminal_refusal(self, attempt_id: str) -> StoredRefusal | None:
        """Return the terminal pre-dispatch refusal recorded for the attempt identity, or None."""
        with self._lock:
            return effect_fencing.stored_refusal(self._db, attempt_id)

    def record_terminal_refusal(
        self, attempt_id: str, kind: str, rule: str | None, reason: str, now: datetime
    ) -> StoredRefusal:
        """Record a pre-dispatch refusal as terminal for the attempt; the first one wins.

        An attempt that already holds a durable authorization intent can only be refused by the
        final boundary (``kind == "final_boundary"``): an earlier-stage refusal is never written
        over an authorization that committed.
        """
        _require_aware(now)
        if kind not in effect_fencing.REFUSAL_KINDS:
            raise ValueError(f"unknown refusal kind {kind!r}")
        with self._immediate() as db:
            _load_attempt(db, attempt_id)
            committed = db.execute(
                "SELECT 1 FROM dispatch_intents WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            kept = effect_fencing.stored_refusal(db, attempt_id)
            if kept is not None:
                return kept
            if committed is not None and kind != "final_boundary":
                raise AttemptStateError("attempt already authorized; it cannot be refused at that stage")
            return effect_fencing.record_refusal(db, attempt_id, kind, rule, reason, now)

    def authorize_dispatch_terminal(
        self,
        attempt_id: str,
        permit_wire: Mapping[str, Any],
        finalization_wire: Mapping[str, Any],
        now: datetime,
        **ports: Any,
    ) -> None:
        """Step 4.3 where a refusal is terminal for the attempt identity (CONTRACT section 4).

        A replay with the same identity returns the stored refusal without re-evaluating anything,
        and a refusal is never recorded over an attempt that already authorized. Clock quarantine is
        operational, not a decision about the attempt, so it is not recorded. Accepts the same
        keyword ports as ``authorize_dispatch``.
        """
        stored = self.terminal_refusal(attempt_id)
        if stored is not None:
            raise _raise_stored(stored)
        try:
            self.authorize_dispatch(attempt_id, permit_wire, finalization_wire, now, **ports)
        except AuthorizationRefused as refusal:
            self._record_if_unauthorized(attempt_id, "authorization", refusal.rule, refusal.reason, now)
            raise
        except ReservationRefused as refusal:
            self._record_if_unauthorized(attempt_id, "reservation", None, refusal.reason, now)
            raise

    def _record_if_unauthorized(
        self, attempt_id: str, kind: str, rule: str | None, reason: str, now: datetime
    ) -> None:
        """Record the refusal unless the attempt already authorized (a replayed authorize)."""
        try:
            self.record_terminal_refusal(attempt_id, kind, rule, reason, now)
        except AttemptStateError:
            pass

    def bootstrap_anchor(
        self,
        issuer_id: str,
        anchor_event: Mapping[str, Any],
        verifier: SignatureVerifier,
        *,
        trusted_keys: TrustedIssuerKeys,
        now: datetime,
    ) -> None:
        """Part 3 section 3.3 item 1: bootstrap from a pruned anchor as one local transaction.

        Recomputes the digest, resolves the key only through ``trusted_keys``, verifies the
        signature, then atomically persists identity, key, version, digest, floor and the
        acknowledgement base. An identical repeat is a no-op; any difference refuses and
        retains anchor quarantine. Consumer-local: no wire refusal code is added.
        """
        _require_text("issuer_id", issuer_id)
        _require_aware(now)
        event = dispatch_anchor.verified_anchor(issuer_id, anchor_event, verifier, trusted_keys)
        with self._immediate() as db:
            conflicted = dispatch_anchor.install_or_quarantine(db, issuer_id, event, now)
            if not conflicted:
                dispatch_revocations.record(db, issuer_id, event)
        if conflicted:
            raise dispatch_anchor.AnchorConflict("conflicting_anchor")

    def authority_facts(self, issuer_id: str) -> dict[str, list[tuple[Any, ...]]]:
        """Read-only view of the recorded revocation and cascade facts for an issuer."""
        with self._lock:
            return dispatch_revocations.facts(self._db, issuer_id)

    def anchor_record(self, issuer_id: str) -> dict[str, Any] | None:
        """Read-only view of the persisted anchor record (works under quarantine)."""
        with self._lock:
            return dispatch_anchor.record(self._db, issuer_id)

    def clear_anchor_quarantine(
        self,
        issuer_id: str,
        *,
        operator: OperatorAuthority,
        trusted_evidence: str,
        now: datetime,
    ) -> None:
        """Clear an anchor quarantine as an audited operator action; never lowers a floor."""
        _require_text("issuer_id", issuer_id)
        reference = operator.authorize("clear_anchor_quarantine", subject=issuer_id)
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to clear an anchor quarantine")
        _require_text("trusted_evidence", trusted_evidence)
        _require_aware(now)
        with self._immediate() as db:
            if not dispatch_anchor.clear(
                db, issuer_id, operator_reference=reference,
                trusted_evidence=trusted_evidence, now=now,
            ):
                raise AttemptStateError("no anchor quarantine to clear")

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

    def begin_send(self, attempt_id: str, *, inert_only: bool = False, now: datetime | None = None) -> None:
        """Durably mark the one allowed send as started; a second send is always refused.

        When ``now`` is given (and always for ``inert_only``, which defaults it to the wall clock)
        the durable send authority is re-checked inside the send transaction.
        """
        if inert_only and now is None:
            now = datetime.now(UTC)
        with self._immediate() as db:
            self._begin_send_in(db, attempt_id, inert_only, now)

    def begin_bound_send(
        self,
        binding: FinalBoundaryBinding,
        now: datetime,
        *,
        issuer_id: str,
        clock: Callable[[], datetime] | None = None,
        envelope_digest: str | None = None,
        authority_check: Callable[[], None] | None = None,
    ) -> None:
        """Start the one inert send only if the durable tuple still equals ``binding``.

        The final-boundary store facts are checked again inside the same ``BEGIN IMMEDIATE``
        transaction that sets ``send_started``, so an epoch that advanced, an expiry that passed, a
        revocation recorded locally or a terminal refusal recorded after the pre-check still stops
        the send. When ``clock`` is given it is read again inside the transaction and that fresh time
        (never earlier than ``now``) decides expiry, so a slow verifier cannot start an expired
        attempt. The single-use human approval for exactly this tuple is consumed in that same
        transaction: no approval, no send, and no consumed approval without a send marker. When
        ``envelope_digest`` is given it is stored with the send marker so a later reconciliation can
        write the receipt. The inert-scope guard of ``begin_send`` applies, and so does the shared
        send-authority re-check (``_recheck_send_authority``: clock quarantine, missing or expired
        send authority, acknowledged revocation, divergence and anchor quarantine), unconditionally.
        ``authority_check`` (the composer's signed-grant re-verification) is called last, after the
        send marker is written but before the transaction commits; if it raises, the transaction
        rolls back, so no send marker, consumed approval or envelope record survives. It must not
        call back into this store.
        """
        _require_aware(now)
        _require_text("issuer_id", issuer_id)
        with self._immediate() as db:
            at = now
            if clock is not None:
                fresh = clock()
                _require_aware(fresh)
                at = max(now, fresh)
            check_store_facts(_binding_in(db, binding.attempt_id), binding, at)
            attempt = _load_attempt(db, binding.attempt_id)
            revoked = dispatch_revocations.refusal_reason(
                db, issuer_id, attempt.grant_id, attempt.second_approval_ref
            )
            if revoked is not None:
                raise FinalBoundaryRefused(revoked, terminal=True)
            effect_approvals.consume_approval(db, binding, at)
            self._begin_send_in(db, binding.attempt_id, True, at)
            if envelope_digest is not None:
                effect_receipts.record_send_envelope(db, binding.attempt_id, envelope_digest, at)
            if authority_check is not None:
                authority_check()

    def grant_effect_approval(
        self, binding: FinalBoundaryBinding, *, approver: OperatorAuthority, now: datetime
    ) -> str:
        """Record a single-use human approval for exactly ``binding``; return its opaque id.

        The approver is authenticated through the injected ``OperatorAuthority``. The binding must
        equal the attempt's durable authorized tuple right now, so an approval cannot be created for
        a refused, unauthorized, stale or altered attempt. A repeat for the same unconsumed tuple
        returns the same id; a different tuple or a consumed approval is refused.
        """
        reference = approver.authorize("approve_effect", subject=binding.attempt_id)
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to approve this effect")
        _require_aware(now)
        with self._immediate() as db:
            check_store_facts(_binding_in(db, binding.attempt_id), binding, now)
            return effect_approvals.create_approval(
                db, "approval-" + uuid.uuid4().hex, binding, reference, now
            )

    def approval_state(self, attempt_id: str) -> str | None:
        """Return ``granted``, ``consumed`` or None for the attempt's approval."""
        with self._lock:
            return effect_approvals.approval_state(self._db, attempt_id)

    def open_reconciliation(
        self, attempt_id: str, *, operator: OperatorAuthority, ttl: timedelta, now: datetime
    ) -> str:
        """Open an expiring single-use reconciliation ticket scoped to one in-doubt attempt.

        Needs an authenticated operator. Only an attempt whose send started with an unproven outcome
        qualifies, and the ticket lives at most fifteen minutes.
        """
        reference = operator.authorize("open_reconciliation", subject=attempt_id)
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to open a reconciliation")
        _require_aware(now)
        with self._immediate() as db:
            return effect_reconciliation.open_ticket(
                db, "ticket-" + uuid.uuid4().hex, attempt_id, reference, ttl, now
            )

    def reconcile_unknown(
        self, ticket_id: str, attempt_id: str, outcome: str, evidence_ref: str, *,
        operator: OperatorAuthority, now: datetime,
    ) -> None:
        """Spend the ticket once to settle an ``unknown`` outcome by hand, with evidence.

        The operator is authenticated again at spend time, the ticket must be for this attempt,
        unexpired and unspent, and the transition is the ordinary ``unknown`` to final one. Nothing
        else can rewrite an unknown outcome.
        """
        reference = operator.authorize("reconcile_unknown", subject=attempt_id)
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to reconcile this attempt")
        _require_aware(now)
        with self._immediate() as db:
            effect_reconciliation.spend_ticket(
                db, ticket_id, attempt_id, outcome, evidence_ref, reference, now
            )

    def unknown_outbox_attempts(self) -> list[str]:
        """Return attempt ids whose send started and whose outcome is still unproven (read-only)."""
        with self._lock:
            return effect_reconciliation.unknown_attempts(self._db)

    def unsent_outbox_count(self) -> int:
        """Return how many authorized outbox rows have not started their send (read-only)."""
        with self._lock:
            return effect_reconciliation.unsent_count(self._db)

    def _begin_send_in(
        self,
        db: sqlite3.Connection,
        attempt_id: str,
        inert_only: bool,
        now: datetime | None = None,
    ) -> None:
        """Run the send preconditions and set ``send_started`` inside the caller's transaction.

        A saved terminal refusal is checked first. Then, whenever ``now`` is given (and always for
        an inert send, which reads the wall clock when no time was passed), the durable send
        authority is re-checked by ``_recheck_send_authority`` in this same transaction.
        """
        row = db.execute(
            "SELECT send_started FROM outbox WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise AttemptStateError("no authorized outbox row for the attempt")
        attempt = _load_attempt(db, attempt_id)
        if effect_fencing.stored_refusal(db, attempt_id) is not None:
            raise OutcomeRefused("attempt_refused")
        if inert_only and now is None:
            now = datetime.now(UTC)
        if now is not None:
            _recheck_send_authority(db, attempt_id, now)
        if inert_only:
            scope = db.execute(
                "SELECT p.destination FROM effect_proposals p JOIN reservations r"
                " ON r.proposal_id = p.proposal_id WHERE r.reservation_id = ?"
                " AND r.consumed_attempt_id = ?",
                (attempt.reservation_id, attempt_id),
            ).fetchone()
            if not self._governed or scope != ("inert://simulation",):
                raise OutcomeRefused("inert_scope_required")
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

    def settle_with_receipt(
        self, attempt_id: str, outcome: str, evidence_ref: str | None, envelope_digest: str,
        now: datetime,
    ) -> RedactedReceipt:
        """Settle ``unknown`` to a final outcome and write its redacted receipt in one transaction.

        The receipt exists exactly when the settlement does. The transition rules of
        ``record_outcome`` apply, so an unproven outcome stays ``unknown`` and a settled one is final.
        """
        _require_aware(now)
        _require_text("envelope_digest", envelope_digest)
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
            return effect_receipts.insert_receipt(db, attempt_id, outcome, envelope_digest, now)

    def receipt(self, attempt_id: str) -> StoredReceipt | None:
        """Return the stored receipt for the attempt identity, or None."""
        with self._lock:
            return effect_receipts.get_receipt(self._db, attempt_id)

    def mark_receipt_published(self, attempt_id: str, now: datetime) -> bool:
        """Stamp the receipt as delivered to its observer; True only for the first stamp."""
        _require_aware(now)
        with self._immediate() as db:
            return effect_receipts.mark_published(db, attempt_id, now)

    def unpublished_receipts(self, limit: int = 100) -> list[StoredReceipt]:
        """Return up to ``limit`` receipts whose publication never completed, oldest first."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000")
        with self._lock:
            return effect_receipts.unpublished(self._db, limit)

    def outbox_row(self, attempt_id: str) -> dict[str, Any] | None:
        """Return the outbox row for the attempt as a dict, or None."""
        with self._lock:
            cursor = self._db.execute("SELECT * FROM outbox WHERE attempt_id = ?", (attempt_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(zip((c[0] for c in cursor.description), row, strict=True))


def _recheck_send_authority(db: sqlite3.Connection, attempt_id: str, now: datetime) -> None:
    """Re-check the durable send authority inside the caller's send transaction.

    One shared helper for every send path (``begin_send`` with a time, inert sends, and
    ``begin_bound_send``). It refuses with ``OutcomeRefused`` when the clock is quarantined, the
    attempt has no recorded send authority (a legacy row never gets authority invented for it) or
    that authority expired, an acknowledged revocation or issuer divergence applies, or the issuer's
    anchor is quarantined.
    """
    _require_aware(now)
    attempt = _load_attempt(db, attempt_id)
    clock = db.execute("SELECT quarantined FROM clock_high_water WHERE id = 1").fetchone()
    if clock is not None and clock[0]:
        raise OutcomeRefused("send_clock_quarantined")
    authority = db.execute(
        "SELECT issuer_id, expires_at FROM send_authority WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if authority is None or now >= parse_timestamp(authority[1]):
        raise OutcomeRefused("send_authority_expired_or_missing")
    fact = dispatch_revocations.refusal_reason(
        db, authority[0], attempt.grant_id, attempt.second_approval_ref
    )
    if fact is not None or _diverged(db, authority[0]):
        raise OutcomeRefused("send_authority_revoked")
    dispatch_anchor.assert_not_quarantined(db, authority[0])


def _binding_in(db: sqlite3.Connection, attempt_id: str) -> StoredBinding | None:
    """Read the durable final-boundary tuple for an attempt on an open connection."""
    row = db.execute(
        "SELECT a.state, a.grant_id, p.principal, p.operation_digest, p.destination,"
        " r.expires_at, a.fencing_epoch, o.send_started, o.outcome"
        " FROM dispatch_attempts a"
        " LEFT JOIN reservations r ON r.reservation_id = a.reservation_id"
        "  AND r.consumed_attempt_id = a.attempt_id"
        " LEFT JOIN effect_proposals p ON p.proposal_id = r.proposal_id"
        " LEFT JOIN outbox o ON o.attempt_id = a.attempt_id"
        " WHERE a.attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        return None
    state, grant_id, principal, digest, target, expires, epoch, started, outcome = row
    return StoredBinding(
        attempt_id=attempt_id, state=state, grant_id=grant_id, principal=principal,
        operation_digest=digest, target=target,
        expires_at=None if expires is None else datetime.strptime(
            expires, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=UTC),
        epoch=epoch, current_epoch=effect_fencing.current_epoch(db),
        send_started=bool(started), outcome=outcome,
        refusal=effect_fencing.stored_refusal(db, attempt_id),
    )


def _raise_stored(stored: StoredRefusal) -> Exception:
    """Rebuild the exact refusal that was recorded as terminal for an attempt identity."""
    if stored.kind == "reservation":
        return ReservationRefused(stored.reason)
    if stored.kind == "authorization" and stored.rule in AUTHORIZATION_RULES:
        return AuthorizationRefused(stored.rule, stored.reason)  # type: ignore[arg-type]
    return OutcomeRefused(stored.reason)


def sender_precondition(store: SqliteAttemptStore, attempt_id: str) -> bool:
    """Return True only if the attempt has a complete outbox row (no missing required field)."""
    row = store.outbox_row(attempt_id)
    if row is None:
        return False
    return all(row.get(name) not in (None, "") for name in _OUTBOX_REQUIRED)
