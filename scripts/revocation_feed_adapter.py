"""Caller-fed authenticated revocation catch-up; no transport or serving activation.

Each instance starts unavailable and needs an explicit successful ``refresh``. Keep its
dedicated cache with the same attempt store across restarts; neither database may be
restored independently to an older backup. The cache is not an effect/approval authority.
Refreshes serialize across processes with BEGIN IMMEDIATE. Store acknowledgements commit
before cache freshness: interruption can leave denials ahead, never freshness ahead.

Lookups reuse an earlier full verification only while the exact cached bytes (SHA-256 and
length of both the signed state and the feed) and the current trusted public key for every
key identifier that signed them are unchanged. The reuse record lives only in this process's
memory: a restart, a failed refresh or any byte change forces a full signature and chain
replay. A detected trust change refuses the current operation; later operations reverify.
Freshness and the clock high-water mark are still checked per lookup.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import hashlib
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.final_boundary import RevocationUnavailable
from phylax import dispatch_wire as wire
from phylax.dispatch_retention import verify_chain
from phylax.revocation_publication import (
    DEFAULT_MAX_STATE_AGE_SECONDS,
    MAX_STATE_BYTES,
    CombinedRevocationLookup,
    PublicationRefused,
    VerifiedState,
    verify_state,
    verify_state_against_chain,
)

_LOG = logging.getLogger(__name__)


class _IssuerKeys:
    """Bind producer verification primitives to one trusted issuer namespace."""

    def __init__(self, issuer_id: str, public_key_for: Callable[[str, str], bytes | None]) -> None:
        """Retain only the caller's scoped resolver, never keys from input."""
        self.issuer_id, self._public_key_for = issuer_id, public_key_for

    def public_key(self, key_id: str) -> bytes | None:
        """Resolve a correctly sized public key in the configured issuer scope."""
        key = self._public_key_for(self.issuer_id, key_id)
        return key if isinstance(key, bytes) and len(key) == 32 else None

    def verify_event(self, key_id: str, digest: str, signature: str) -> bool:
        """Verify the producer event domain for the existing store ingestion API."""
        key = self.public_key(key_id)
        return key is not None and wire.verify_event(key, digest, signature)


class _SnapshotMemo:
    """One instance's record that exact cached bytes fully verified under exact trust.

    ``trust`` pairs every signing key identifier of the snapshot with the public key the
    trusted resolver returned for it, sampled both before and after the full verification.
    A plain slotted class (not a dataclass) so the adapter also loads from a file spec.
    """

    __slots__ = ("raw_sha256", "raw_length", "feed_sha256", "feed_length", "trust", "state")

    def __init__(
        self, raw: bytes, feed: bytes, trust: tuple[tuple[str, bytes], ...], state: VerifiedState,
    ) -> None:
        """Bind the digest and length of both byte strings to the trust and verified state."""
        self.raw_sha256, self.raw_length = hashlib.sha256(raw).digest(), len(raw)
        self.feed_sha256, self.feed_length = hashlib.sha256(feed).digest(), len(feed)
        self.trust, self.state = trust, state

    def matches(self, raw: bytes, feed: bytes) -> bool:
        """Return True only for byte-identical cached state and feed."""
        return (len(raw) == self.raw_length and len(feed) == self.feed_length
                and hashlib.sha256(raw).digest() == self.raw_sha256
                and hashlib.sha256(feed).digest() == self.feed_sha256)


class RevocationFeedAdapter:
    """Explicit bounded full-feed refresh and retryable-unavailable RevocationLookup.

    ``approval_ref_for(grant_id, issuer_id)`` must be a quick trusted read, not an
    approval-consumption callback or an attempt-store call. None means undeclared;
    only the trusted callback can assert the empty single-approval reference.
    All verification/IO errors propagate from ``refresh``. ``revoked`` returns True only for a
    confirmed revocation or undeclared approval; a transient refresh or trusted-read failure raises
    ``RevocationUnavailable`` so the final boundary can deny this call without terminally burning
    an otherwise authorized attempt.
    """

    def __init__(
        self, cache_path: str | Path, *, store: SqliteAttemptStore, issuer_id: str,
        public_key_for: Callable[[str, str], bytes | None], clock: Callable[[], datetime],
        approval_ref_for: Callable[[str, str], str | None] | None = None,
        max_events: int = 4096, max_feed_bytes: int = 8 * 1024 * 1024,
        max_age_seconds: int = DEFAULT_MAX_STATE_AGE_SECONDS,
    ) -> None:
        """Open the dedicated durable cache without refreshing or activating it."""
        wire.validate_identifier("issuer_id", issuer_id)
        if not callable(public_key_for) or not callable(clock):
            raise ValueError("trusted issuer resolver and clock required")
        if approval_ref_for is not None and not callable(approval_ref_for):
            raise ValueError("approval reference must be a trusted callback")
        for limit in (max_events, max_feed_bytes, max_age_seconds):
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                raise ValueError("limits must be positive integers")
        if max_age_seconds > DEFAULT_MAX_STATE_AGE_SECONDS:
            raise ValueError("state age exceeds producer ceiling")
        if str(cache_path) == ":memory:" or "mode=memory" in str(cache_path):
            raise ValueError("cache requires a durable dedicated file")
        self.cache_path = Path(cache_path)
        self._store, self._issuer, self._clock = store, issuer_id, clock
        self._keys = _IssuerKeys(issuer_id, public_key_for)
        self._approval = approval_ref_for
        self._max_events, self._max_bytes, self._max_age = max_events, max_feed_bytes, max_age_seconds
        self._ready = False
        self._snapshot_memo: _SnapshotMemo | None = None
        self._prewarm_lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        with closing(self._connect()) as db:
            db.execute("CREATE TABLE IF NOT EXISTS verified_snapshot ("
                       "issuer_id TEXT PRIMARY KEY, raw_state BLOB NOT NULL, feed BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS observed_clock ("
                       "singleton INTEGER PRIMARY KEY CHECK(singleton=1), at TEXT NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        """Open a fully synchronous connection with a bounded lock wait."""
        # A lookup may run with the store lock held. Bound cache lock waits so a
        # simultaneous refresh (cache -> store) fails closed instead of deadlocking.
        db = sqlite3.connect(self.cache_path, timeout=0.1, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize cache writers and always roll back interrupted work."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def _observe_time(self) -> datetime:
        """Durably observe time even when subsequent verification refuses stale input."""
        with self._transaction() as db:
            now = self._clock()
            stamp = wire.timestamp(now)
            self._check_time(db, now)
            db.execute("INSERT INTO observed_clock VALUES (1, ?) "
                       "ON CONFLICT(singleton) DO UPDATE SET at=excluded.at", (stamp,))
        return now

    @staticmethod
    def _check_time(db: sqlite3.Connection, now: datetime) -> None:
        """Reject a clock reading below the durable observation high-water mark."""
        row = db.execute("SELECT at FROM observed_clock WHERE singleton=1").fetchone()
        if row and now < wire.parse_timestamp(row[0]):
            raise ValueError("clock rollback")

    def _copy_feed(self, events: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], bytes]:
        """Bound and detach caller-owned events using the producer canonical encoder."""
        if not isinstance(events, Sequence) or len(events) > self._max_events:
            raise ValueError("complete feed exceeds event bound")
        chunks, size = [], 2
        if size > self._max_bytes:
            raise ValueError("complete feed exceeds byte bound")
        for event in events:
            chunk = wire.canonical_bytes(event)
            if len(chunk) > wire.MAX_WIRE_BYTES:
                raise ValueError("event exceeds wire bound")
            size += len(chunk) + bool(chunks)
            if size > self._max_bytes:
                raise ValueError("complete feed exceeds byte bound")
            chunks.append(chunk)
        raw = b"[" + b",".join(chunks) + b"]"
        return json.loads(raw), raw

    def _verify(self, raw: bytes, events: list[dict[str, Any]], now: datetime) -> VerifiedState:
        """Verify issuer signature, freshness, complete head and replayed summary."""
        state = verify_state(raw, resolver=self._keys, issuer_id=self._issuer,
                             now=now, max_age_seconds=self._max_age)
        # Explicit genesis checks also support the producer's original R3 main API.
        if state.head_version != len(events) or (events and events[0].get("version") != 1):
            raise ValueError("feed must be complete from genesis")
        tip = verify_chain(events, previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=self._keys)
        if tip != state.head_event_digest:
            raise ValueError("state head mismatch")
        verify_state_against_chain(state, events, resolver=self._keys)
        return state

    def _trust(self, key_ids: Sequence[str]) -> tuple[tuple[str, bytes], ...] | None:
        """Sample current trusted keys for ``key_ids``; None if any is no longer trusted."""
        sampled = []
        for key_id in key_ids:
            key = self._keys.public_key(key_id)
            if key is None:
                return None
            sampled.append((key_id, key))
        return tuple(sampled)

    def _verify_and_remember(
        self, raw: bytes, feed: bytes, events: list[dict[str, Any]], at: datetime,
    ) -> tuple[VerifiedState, _SnapshotMemo | None]:
        """Fully verify, returning a reuse record only if trust was stable throughout."""
        try:
            key_ids = sorted({str(json.loads(raw)["issuer_key_id"])}
                             | {str(event.get("issuer_key_id")) for event in events})
        except (ValueError, KeyError, TypeError):
            # Malformed input: let the producer verifier raise its own refusal.
            return self._verify(raw, events, at), None
        before = self._trust(key_ids)
        state = self._verify(raw, events, at)
        after = self._trust(key_ids)
        if before is None or before != after:
            raise RevocationUnavailable("unstable or untrusted key trust during verification")
        return state, _SnapshotMemo(raw, feed, after, state)

    def _require_fresh(self, state: VerifiedState, at: datetime) -> None:
        """Apply the producer freshness rule verify_state applies; raise when stale or future."""
        CombinedRevocationLookup(state, clock=lambda: at, max_age_seconds=self._max_age).reason("", None)

    def _cached(self, db: sqlite3.Connection, *, now: datetime | None = None) -> VerifiedState | None:
        """Return the cached snapshot, reverifying unless exact bytes and trust are unchanged.

        Historical signature verification (``now`` None) is ONLY for antirollback comparison.
        Every allow lookup and new refresh separately verifies freshness with current time.
        """
        row = db.execute("SELECT raw_state, feed FROM verified_snapshot WHERE issuer_id=?",
                         (self._issuer,)).fetchone()
        if row is None:
            return None
        raw, feed = row
        if not isinstance(raw, bytes) or not isinstance(feed, bytes):
            raise ValueError("cache holds non-byte values")
        if len(raw) > MAX_STATE_BYTES or len(feed) > self._max_bytes:
            raise ValueError("cache exceeds bounds")
        memo = self._snapshot_memo
        if memo is not None and memo.matches(raw, feed):
            if self._trust([key_id for key_id, _ in memo.trust]) != memo.trust:
                self._snapshot_memo = None
                raise RevocationUnavailable("issuer key trust changed")
            if now is not None:
                self._require_fresh(memo.state, now)
            return memo.state
        self._snapshot_memo = None
        events, canonical = self._copy_feed(json.loads(feed))
        if canonical != feed:
            raise ValueError("noncanonical cached feed")
        at = now if now is not None else wire.parse_timestamp(json.loads(raw)["body"]["generated_at"])
        state, memo = self._verify_and_remember(raw, feed, events, at)
        self._snapshot_memo = memo
        return state

    def _prewarm(self, now: datetime) -> None:
        """Fully verify a changed cached snapshot before taking the cache write lock.

        Only an optimization: it installs a reuse record bound to the exact bytes and trust it
        verified, and the locked lookup still rechecks bytes, trust, clock and freshness. Any
        failures other than detected unstable trust are left to the locked path.
        Concurrent lookups of one instance share a single replay (single flight): the others
        wait for it and then find a matching record.
        """
        with self._prewarm_lock:
            self._prewarm_locked(now)

    def _prewarm_locked(self, now: datetime) -> None:
        """Run one prewarm while holding the per-instance single-flight lock."""
        try:
            with closing(self._connect()) as db:
                row = db.execute("SELECT raw_state, feed FROM verified_snapshot WHERE issuer_id=?",
                                 (self._issuer,)).fetchone()
            if row is None or not isinstance(row[0], bytes) or not isinstance(row[1], bytes):
                return
            raw, feed = row
            memo = self._snapshot_memo
            if memo is not None and memo.matches(raw, feed):
                return
            if len(raw) > MAX_STATE_BYTES or len(feed) > self._max_bytes:
                return
            events, canonical = self._copy_feed(json.loads(feed))
            if canonical != feed:
                return
            _, memo = self._verify_and_remember(raw, feed, events, now)
            if memo is not None:
                self._snapshot_memo = memo
        except RevocationUnavailable:
            self._snapshot_memo = None
            raise
        except Exception:  # noqa: BLE001 - the locked path decides and fails closed
            return

    def _final_time(
        self, db: sqlite3.Connection, started: datetime, state: VerifiedState,
    ) -> datetime | None:
        """Recheck time after verification and retain forward observations on refusal."""
        now = self._clock()
        stamp = wire.timestamp(now)
        if now < started:
            return None
        self._check_time(db, now)
        db.execute("UPDATE observed_clock SET at=? WHERE singleton=1", (stamp,))
        try:
            CombinedRevocationLookup(state, clock=lambda: now, max_age_seconds=self._max_age).reason("", None)
        except PublicationRefused:
            return None
        return now

    def refresh(self, raw_state: bytes, events: Sequence[Mapping[str, object]]) -> None:
        """Verify a complete signed snapshot, catch up store acks, then publish freshness.

        Call outside any attempt-store transaction. Replays use ingest_events' existing
        ack/digest authority, not a second cursor. Failed refresh makes this instance
        unavailable until another complete successful refresh.
        """
        with self._refresh_lock:
            self._ready = False
            try:
                self._refresh_locked(raw_state, events)
            except BaseException:
                self._snapshot_memo = None
                raise
            self._ready = True

    def _refresh_locked(self, raw_state: bytes, events: Sequence[Mapping[str, object]]) -> None:
        """Run one refresh under the instance refresh lock; the caller publishes readiness."""
        now = self._observe_time()
        if not isinstance(raw_state, (bytes, bytearray)) or len(raw_state) > MAX_STATE_BYTES:
            raise ValueError("state exceeds byte bound or is not bytes")
        raw = bytes(raw_state)
        chain, feed = self._copy_feed(events)
        # Full replay of the caller's input happens before the cache write lock; trust is
        # resampled under the lock and any detected change refuses the refresh.
        state, memo = self._verify_and_remember(raw, feed, chain, now)
        with self._transaction() as db:
            locked_now = self._clock()
            wire.timestamp(locked_now)
            if locked_now < now:
                raise ValueError("clock rollback during refresh")
            now = locked_now
            self._check_time(db, now)
            if memo is None:
                state, memo = self._verify_and_remember(raw, feed, chain, now)
            elif self._trust([key_id for key_id, _ in memo.trust]) != memo.trust:
                raise RevocationUnavailable("issuer key trust changed")
            self._require_fresh(state, now)
            old = self._cached(db)
            if old:
                if state.head_version < old.head_version or state.generated_at < old.generated_at:
                    raise ValueError("state rollback")
                prefix = chain[old.head_version - 1]["event_digest"] if old.head_version else wire.GENESIS_EVENT_DIGEST
                if prefix != old.head_event_digest:
                    raise ValueError("state fork")
            if self._store.is_diverged(self._issuer):
                raise ValueError("attempt store diverged")
            if self._store.acked_through(self._issuer) > state.head_version:
                raise ValueError("snapshot behind acknowledged events")
            self._store.ingest_events(self._issuer, chain, self._keys)
            if (self._store.acked_through(self._issuer) != state.head_version
                    or self._store.is_diverged(self._issuer)):
                raise ValueError("event acknowledgement incomplete")
            fresh = self._final_time(db, now, state) is not None
            if fresh:
                # This commit must be last. On failure existing store denials survive.
                db.execute("INSERT INTO verified_snapshot VALUES (?, ?, ?) "
                           "ON CONFLICT(issuer_id) DO UPDATE SET "
                           "raw_state=excluded.raw_state, feed=excluded.feed",
                           (self._issuer, raw, feed))
        if not fresh:
            # Commit the clock observation, but never an expired snapshot.
            raise ValueError("state expired or clock regressed during refresh")
        # Installed only after the snapshot commit; reuse still rechecks bytes and trust.
        self._snapshot_memo = memo

    def revoked(self, grant_id: str, issuer_id: str) -> bool:
        """Return a confirmed decision or raise ``RevocationUnavailable`` for an unsafe read."""
        try:
            if issuer_id != self._issuer:
                return True
            if not self._ready:
                raise RevocationUnavailable("revocation feed has not completed a fresh refresh")
            wire.validate_identifier("grant_id", grant_id)
            self._prewarm(self._clock())
            now = self._observe_time()
            unavailable: str | None = None
            decision: bool | None = None
            with self._transaction() as db:
                locked_now = self._clock()
                if locked_now < now:
                    raise ValueError("clock rollback during lookup")
                now = locked_now
                self._check_time(db, now)
                cached = self._cached(db, now=now)
                if cached is None or not self._ready:
                    unavailable = "revocation feed is unavailable during refresh"
                else:
                    approval = self._approval(grant_id, issuer_id) if self._approval else None
                    if approval is not None and not isinstance(approval, str):
                        unavailable = "trusted approval reference is unavailable"
                    else:
                        if approval:
                            wire.validate_identifier("approval_id", approval)
                        final = self._final_time(db, now, cached)
                        if final is None:
                            unavailable = "revocation feed became stale during lookup"
                        else:
                            lookup = CombinedRevocationLookup(
                                cached, clock=lambda: final, max_age_seconds=self._max_age,
                            )
                            decision = lookup.reason(grant_id, approval) is not None
            if unavailable is not None:
                raise RevocationUnavailable(unavailable)
            if decision is None:
                raise RevocationUnavailable("revocation feed returned no decision")
            return decision
        except RevocationUnavailable:
            raise
        except Exception as error:  # noqa: BLE001 - fail closed on any unsafe read
            _LOG.warning("revocation lookup failed closed: %s", type(error).__name__)
            raise RevocationUnavailable("revocation feed lookup failed") from None
