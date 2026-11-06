"""Real producer signatures exercise the explicitly refreshed, non-serving adapter."""
from __future__ import annotations

import importlib.util
import json
import logging
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from orama.graph.dispatch_attempts import SqliteAttemptStore
from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import SqliteDispatchPermitStore
from phylax.dispatch_retention import RetainedEventFeed, RetentionLedger
from phylax.revocation_publication import build_state, sign_state_body

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("r3_feed_adapter", ROOT / "scripts/revocation_feed_adapter.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE

NOW = datetime(2026, 11, 2, 4, tzinfo=UTC)
ISSUER = "issuer-1"
SEED = b"1" * 32
PUBLIC = crypto_sign_seed_keypair(SEED)[0]
SignedFeed = tuple[bytes, list[dict[str, Any]]]
World = tuple[
    SqliteDispatchPermitStore, SqliteAttemptStore, list[datetime],
    dict[tuple[str, str], bytes], Callable[..., Any], Callable[..., SignedFeed],
]


class Signer:
    """Produce real domain-separated signatures with a deterministic test seed."""

    def active_key_id(self) -> str:
        """Return the issuer's test key identifier."""
        return "key-1"

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event through the producer public primitive."""
        return wire.sign_event(SEED, digest)

    def sign_state(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign a summary through the producer public primitive."""
        return sign_state_body(SEED, body)


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    """Compose real stores with mutable trusted time and issuer-scoped keys."""
    SPEC.loader.exec_module(MODULE)
    producer = SqliteDispatchPermitStore(tmp_path / "producer.db")
    feed = RetainedEventFeed(producer, RetentionLedger(tmp_path / "retention.db"))
    store = SqliteAttemptStore(tmp_path / "attempts.db")
    time = [NOW]
    keys = {(ISSUER, "key-1"): PUBLIC}

    def adapter(**kwargs: Any) -> Any:
        """Open an unavailable instance over the world's durable cache."""
        return MODULE.RevocationFeedAdapter(
            tmp_path / "cache.db", store=store, issuer_id=ISSUER,
            public_key_for=lambda issuer, key: keys.get((issuer, key)),
            clock=lambda: time[0], **kwargs,
        )

    def signed(at: datetime | None = None, head: int | None = None) -> SignedFeed:
        """Build a real producer state and complete feed at a selected head."""
        head = producer.current_counter() if head is None else head
        return (build_state(feed, issuer_id=ISSUER, head_version=head,
                            signer=Signer(), now=at or time[0]),
                feed.events(1, head) if head else [])

    yield producer, store, time, keys, adapter, signed
    store.close()


def resign(raw: bytes, **changes: Any) -> bytes:
    """Create an issuer-signed but potentially inconsistent adversarial summary."""
    doc = json.loads(raw)
    doc["body"].update(changes)
    doc["signature"] = sign_state_body(SEED, doc["body"])
    return wire.canonical_bytes(doc)


def unavailable(lookup: Any, grant_id: str = "safe", issuer_id: str = ISSUER) -> None:
    """Assert that a lookup denies safely without claiming a revocation was confirmed."""
    with pytest.raises(MODULE.RevocationUnavailable):
        lookup.revoked(grant_id, issuer_id)


def test_observation_samples_clock_after_acquiring_the_write_lock(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A waiting observer records lock-time time rather than a stale pre-lock sample."""
    from contextlib import contextmanager

    _, _, time, _, adapter, _ = world
    lookup = adapter()
    transaction = lookup._transaction

    @contextmanager
    def delayed_transaction() -> Iterator[sqlite3.Connection]:
        """Model waiting for an earlier writer before obtaining this writer's lock."""
        time[0] += timedelta(seconds=1)
        with transaction() as database:
            database.execute("INSERT INTO observed_clock VALUES (1, ?)",
                             (wire.timestamp(time[0]),))
            yield database

    monkeypatch.setattr(lookup, "_transaction", delayed_transaction)
    assert lookup._observe_time() == NOW + timedelta(seconds=1)


@pytest.mark.parametrize("concurrent_observation", [True, False])
def test_refresh_resamples_clock_after_copy_before_cache_lock(
    world: World, monkeypatch: pytest.MonkeyPatch, concurrent_observation: bool,
) -> None:
    """A later writer is accepted, while a real within-refresh rollback is refused."""
    _, _, time, _, adapter, signed = world
    lookup, observer = adapter(), adapter()
    raw, events = signed()
    copy_feed = lookup._copy_feed

    def interleaved_copy(value: Any) -> tuple[list[dict[str, Any]], bytes]:
        """Move time after the first observation and optionally record it elsewhere."""
        result = copy_feed(value)
        time[0] += timedelta(seconds=1 if concurrent_observation else -1)
        if concurrent_observation:
            observer._observe_time()
        monkeypatch.setattr(lookup, "_copy_feed", copy_feed)
        return result

    monkeypatch.setattr(lookup, "_copy_feed", interleaved_copy)
    if concurrent_observation:
        lookup.refresh(raw, events)
        assert lookup.revoked("safe", ISSUER) is False
    else:
        with pytest.raises(ValueError, match="clock rollback"):
            lookup.refresh(raw, events)
        unavailable(lookup)


def test_explicit_refresh_restart_and_existing_store_ack(world: World) -> None:
    """Require explicit refresh on restart while reusing existing store facts."""
    producer, store, _, _, adapter, signed = world
    a = adapter()
    unavailable(a)
    producer.append_revocation("grant", "bad", signer=Signer())
    assert a.refresh(*signed()) is None
    assert store.acked_through(ISSUER) == 1
    assert store.authority_facts(ISSUER)["revocations"] == [(1, "grant", "bad")]
    assert a.revoked("safe", ISSUER) is False
    assert a.revoked(grant_id="bad", issuer_id=ISSUER) is True
    restarted = adapter()
    unavailable(restarted)
    restarted.refresh(*signed())
    assert restarted.revoked("safe", ISSUER) is False


@pytest.mark.parametrize("damage", ["gap", "head", "summary", "state_signature", "event_signature", "event_body", "genesis"])
def test_verify_everything_before_ingestion(world: World, damage: str) -> None:
    """Refuse incomplete or tampered input before any acknowledgement."""
    producer, store, _, _, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    producer.append_revocation("grant", "worse", signer=Signer())
    raw, events = signed()
    if damage == "gap":
        events = events[1:]
    elif damage == "head":
        events = events[:1]
    elif damage == "summary":
        raw = resign(raw, revoked_grants=[])
    elif damage == "state_signature":
        doc = json.loads(raw)
        doc["body"]["revoked_grants"] = []
        raw = wire.canonical_bytes(doc)
    elif damage == "event_signature":
        events[-1]["signature"] = wire.sign_event(b"2" * 32, events[-1]["event_digest"])
    elif damage == "event_body":
        events[-1]["body"]["subject_id"] = "tampered"
    else:
        raw = resign(raw, head_version=0, revoked_grants=[])
        events = []
    a = adapter()
    with pytest.raises(Exception):
        a.refresh(raw, events)
    assert store.acked_through(ISSUER) == 0
    unavailable(a)


@pytest.mark.parametrize("kind", ["head_rollback", "same_head_fork", "extension_fork", "time_rollback"])
def test_durable_antirollback_after_restart(world: World, kind: str) -> None:
    """Reject signed head/time rollback and both fork shapes after restart."""
    producer, store, time, _, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    old = signed()
    time[0] += timedelta(seconds=2)
    producer.append_revocation("grant", "worse", signer=Signer())
    current = signed()
    adapter().refresh(*current)
    if kind == "head_rollback":
        candidate = old
    elif kind == "time_rollback":
        candidate = signed(at=NOW)
    else:
        events = deepcopy(current[1])
        events[0]["body"]["subject_id"] = "forked"
        if kind == "extension_fork":
            producer.append_revocation("grant", "third", signer=Signer())
            events.append(signed()[1][-1])
        previous = wire.GENESIS_EVENT_DIGEST
        for e in events:
            e["previous_event_digest"] = previous
            e["event_digest"] = wire.event_digest(e["version"], e["kind"], e["body"], previous)
            e["signature"] = wire.sign_event(SEED, e["event_digest"])
            previous = e["event_digest"]
        raw = resign(current[0], head_version=len(events), head_event_digest=previous,
                     revoked_grants=sorted(e["body"]["subject_id"] for e in events))
        candidate = raw, events
    a = adapter()
    with pytest.raises(Exception):
        a.refresh(*candidate)
    assert store.acked_through(ISSUER) == 2
    unavailable(a)


def test_stale_reread_restart_and_clock_rollback(world: World) -> None:
    """Never revive expired state by rereading, restarting or reversing time."""
    _, _, time, _, adapter, signed = world
    original = signed()
    a = adapter()
    a.refresh(*original)
    assert a.revoked("safe", ISSUER) is False
    time[0] += timedelta(seconds=61)
    unavailable(a)
    with pytest.raises(Exception):
        adapter().refresh(*original)
    time[0] = NOW
    with pytest.raises(Exception):
        adapter().refresh(*original)
    unavailable(a)


def test_issuer_scope_and_trust_rechecked(world: World) -> None:
    """Scope colliding key identifiers and recheck current trust on lookup."""
    _, store, _, keys, adapter, signed = world
    a = adapter()
    raw, events = signed()
    # A key authorized only for another issuer is not this issuer's authority.
    keys.clear()
    keys[("issuer-2", "key-1")] = PUBLIC
    with pytest.raises(Exception):
        a.refresh(raw, events)
    assert store.acked_through(ISSUER) == 0
    keys[(ISSUER, "key-1")] = PUBLIC
    a.refresh(raw, events)
    assert a.revoked("safe", "issuer-2") is True
    assert a.revoked("safe", ISSUER) is False
    keys.pop((ISSUER, "key-1"))
    unavailable(a)


@pytest.mark.parametrize("approval,expected", [(None, True), ("revoked-approval", True), ("other", False), ("", False)])
def test_only_trusted_callback_supplies_approval(
    world: World, approval: str | None, expected: bool,
) -> None:
    """Use only explicit trusted references and keep None undeclared."""
    producer, _, _, _, adapter, signed = world
    producer.append_revocation("approval", "revoked-approval", signer=Signer())
    seen: list[tuple[str, str]] = []

    def trusted(grant: str, issuer: str) -> str | None:
        """Return the caller's trusted approval binding."""
        seen.append((grant, issuer))
        return approval

    a = adapter(approval_ref_for=trusted)
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is expected
    assert seen == [("safe", ISSUER)]
    undeclared = adapter()
    undeclared.refresh(*signed())
    assert undeclared.revoked("safe", ISSUER) is True


def test_cascade_and_issuer_revocation(world: World) -> None:
    """Apply producer cascade and issuer-denial semantics without new authority."""
    producer, _, _, _, adapter, signed = world
    producer.append_cascade("approval-1", ["listed"], 1, signer=Signer())
    a = adapter()
    a.refresh(*signed())
    assert a.revoked("listed", ISSUER) is True
    assert a.revoked("safe", ISSUER) is False
    producer.append_revocation("issuer", ISSUER, signer=Signer())
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is True


@pytest.mark.parametrize("after_ack", [False, True])
def test_ingestion_failure_never_publishes_freshness(
    world: World, monkeypatch: pytest.MonkeyPatch, after_ack: bool,
) -> None:
    """Fail closed on either side of the store acknowledgement commit."""
    producer, store, _, _, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    original = store.ingest_events

    def fail(*args: Any) -> None:
        """Inject failure before or after the real acknowledgement."""
        if after_ack:
            original(*args)
        raise OSError("simulated crash around acknowledgement")

    a = adapter()
    monkeypatch.setattr(store, "ingest_events", fail)
    with pytest.raises(OSError):
        a.refresh(*signed())
    assert store.acked_through(ISSUER) == int(after_ack)
    unavailable(a)
    unavailable(adapter())
    monkeypatch.setattr(store, "ingest_events", original)
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is False


def test_cache_commit_failure_leaves_only_ack_ahead(world: World) -> None:
    """Preserve store denials when a SQLite trigger aborts cache publication."""
    producer, store, _, _, adapter, signed = world
    a = adapter()
    producer.append_revocation("grant", "bad", signer=Signer())
    with sqlite3.connect(a.cache_path) as db:
        db.execute("CREATE TRIGGER fail_cache BEFORE INSERT ON verified_snapshot "
                   "BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
    with pytest.raises(sqlite3.DatabaseError):
        a.refresh(*signed())
    assert store.acked_through(ISSUER) == 1
    unavailable(a)
    with sqlite3.connect(a.cache_path) as db:
        assert db.execute("SELECT COUNT(*) FROM verified_snapshot").fetchone()[0] == 0
        db.execute("DROP TRIGGER fail_cache")
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is False


def test_bounds_and_cache_tamper_fail_closed(world: World) -> None:
    """Bound both feed dimensions and refuse corrupted cached state."""
    producer, store, _, _, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    producer.append_revocation("grant", "worse", signer=Signer())
    a = adapter(max_events=1)
    with pytest.raises(ValueError):
        a.refresh(*signed())
    assert store.acked_through(ISSUER) == 0
    a = adapter(max_feed_bytes=10)
    with pytest.raises(ValueError):
        a.refresh(*signed())
    a = adapter()
    a.refresh(*signed())
    with sqlite3.connect(a.cache_path) as db:
        db.execute("UPDATE verified_snapshot SET raw_state = ?", (b"{}",))
    unavailable(a)
    with pytest.raises(Exception):
        adapter().refresh(*signed())


def test_lookup_logs_only_the_failure_class_for_an_unsafe_cache(
    world: World, caplog: pytest.LogCaptureFixture,
) -> None:
    """Operators can distinguish cache failures without logging grant-bearing error text."""
    _, _, _, _, adapter, signed = world
    a = adapter()
    a.refresh(*signed())
    with sqlite3.connect(a.cache_path) as db:
        db.execute("UPDATE verified_snapshot SET raw_state = ?", (b"not-json secret-grant-id",))
    with caplog.at_level(logging.WARNING, logger=MODULE.__name__):
        unavailable(a)
    messages = [record.getMessage() for record in caplog.records]
    assert any("PublicationRefused" in message for message in messages)
    assert all("secret-grant-id" not in message for message in messages)


def test_lookup_is_safe_inside_attempt_store_lock(world: World) -> None:
    """Read revocations without recursively acquiring the store lock."""
    _, store, _, _, adapter, signed = world
    a = adapter()
    a.refresh(*signed())
    with store._lock:
        assert a.revoked("safe", ISSUER) is False


def test_empty_feed_still_obeys_byte_bound(world: World) -> None:
    """Count JSON container bytes even for a genesis snapshot."""
    _, store, _, _, adapter, signed = world
    with pytest.raises(ValueError):
        adapter(max_feed_bytes=1).refresh(*signed())
    assert store.acked_through(ISSUER) == 0


def test_read_lock_contention_and_serialized_refreshes(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Serialize writers and bound read contention inside a store transaction."""
    producer, store, _, _, adapter, signed = world
    first, second, reader = adapter(), adapter(), adapter()
    initial = signed()
    first.refresh(*initial)
    reader.refresh(*initial)
    producer.append_revocation("grant", "bad", signer=Signer())
    advanced = signed()
    entered, release = threading.Event(), threading.Event()
    original = store.ingest_events
    errors: list[BaseException] = []

    def paused(*args: Any) -> None:
        """Hold refresh between verification and acknowledgement."""
        entered.set()
        assert release.wait(3)
        original(*args)

    def refresh() -> None:
        """Capture background test-thread failures for the main assertion."""
        try:
            first.refresh(*advanced)
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(store, "ingest_events", paused)
    thread = threading.Thread(target=refresh)
    thread.start()
    try:
        assert entered.wait(3)
        # Competing refresh cannot publish its old head over an in-flight newer one.
        with pytest.raises(sqlite3.OperationalError):
            second.refresh(*initial)
        unavailable(first)
        with store._lock:
            unavailable(reader)
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive()
    assert not errors
    monkeypatch.setattr(store, "ingest_events", original)
    with pytest.raises(ValueError):
        second.refresh(*initial)
    assert store.acked_through(ISSUER) == 1
    assert first.revoked("safe", ISSUER) is False


def test_hard_process_exit_after_ack_before_cache_commit(world: World) -> None:
    """Recover durable denials but not freshness after a hard process exit."""
    producer, store, _, _, adapter, signed = world
    a = adapter()
    initial = signed()
    producer.append_revocation("grant", "bad", signer=Signer())
    raw, events = signed()
    child = r'''
import importlib.util, json, os, sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from orama.graph.dispatch_attempts import SqliteAttemptStore
from phylax import dispatch_wire as wire
from nacl.bindings import crypto_sign_seed_keypair
spec = importlib.util.spec_from_file_location("child_adapter", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
cache = Path(sys.argv[2])
store = SqliteAttemptStore(cache.parent / "attempts.db")
ingest = store.ingest_events
def crash(*args: Any) -> None:
    """Terminate without stack unwinding immediately after event acknowledgement."""
    ingest(*args)
    os._exit(73)
store.ingest_events = crash
a = module.RevocationFeedAdapter(cache, store=store, issuer_id="issuer-1",
    public_key_for=lambda issuer, key: crypto_sign_seed_keypair(b"1" * 32)[0],
    clock=lambda: datetime(2026, 11, 2, 4, tzinfo=UTC))
document, events = json.load(sys.stdin)
a.refresh(wire.canonical_bytes(document), events)
'''
    result = subprocess.run(
        [sys.executable, "-c", child, str(SPEC.origin), str(a.cache_path)],
        input=json.dumps([json.loads(raw), events]), text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 73, result.stderr
    assert store.acked_through(ISSUER) == 1
    assert store.authority_facts(ISSUER)["revocations"] == [(1, "grant", "bad")]
    restarted = adapter()
    unavailable(restarted)
    with pytest.raises(ValueError):
        restarted.refresh(*initial)
    restarted.refresh(raw, events)
    assert restarted.revoked("safe", ISSUER) is False


def test_callback_error_and_missing_ack_are_unavailable(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deny on failed trusted reads or an ingestion that fails to advance ack."""
    producer, store, _, _, adapter, signed = world

    def broken(*args: Any) -> None:
        """Simulate an unavailable trusted approval view."""
        raise OSError("trusted view unavailable")

    a = adapter(approval_ref_for=broken)
    a.refresh(*signed())
    unavailable(a)
    producer.append_revocation("grant", "bad", signer=Signer())
    monkeypatch.setattr(store, "ingest_events", lambda *args: None)
    with pytest.raises(ValueError):
        a.refresh(*signed())
    unavailable(a)
    assert store.acked_through(ISSUER) == 0


@pytest.mark.parametrize("ref", [" ", "bad ref", "\t", "x" * (wire.MAX_IDENTIFIER_BYTES + 1)])
def test_malformed_trusted_approval_reference_denies(world: World, ref: str) -> None:
    """Reject nonempty approval references outside the producer identifier contract."""
    _, _, _, _, adapter, signed = world
    a = adapter(approval_ref_for=lambda *_: ref)
    a.refresh(*signed())
    unavailable(a)


@pytest.mark.parametrize("seconds", [-1, 61])
def test_refresh_rechecks_clock_after_ingestion(
    world: World, monkeypatch: pytest.MonkeyPatch, seconds: int,
) -> None:
    """Refuse refresh if verification spans a clock regression or expiration."""
    _, store, time, _, adapter, signed = world
    a = adapter()
    original = store.ingest_events

    def move_clock(*args: Any) -> None:
        """Move trusted time after real event acknowledgement."""
        original(*args)
        time[0] += timedelta(seconds=seconds)

    monkeypatch.setattr(store, "ingest_events", move_clock)
    with pytest.raises(ValueError):
        a.refresh(*signed())
    unavailable(a)
    with sqlite3.connect(a.cache_path) as db:
        assert db.execute("SELECT COUNT(*) FROM verified_snapshot").fetchone()[0] == 0
    if seconds > 0:
        time[0] = NOW
        monkeypatch.setattr(store, "ingest_events", original)
        with pytest.raises(ValueError):
            adapter().refresh(*signed())


@pytest.mark.parametrize("seconds", [-1, 61])
def test_lookup_rechecks_clock_after_trusted_callback(world: World, seconds: int) -> None:
    """Recheck time after the approval callback and persist observed expiry."""
    _, _, time, _, adapter, signed = world

    def move_clock(*args: Any) -> str:
        """Move time while supplying an otherwise valid approval reference."""
        time[0] += timedelta(seconds=seconds)
        return ""

    a = adapter(approval_ref_for=move_clock)
    original = signed()
    a.refresh(*original)
    unavailable(a)
    if seconds > 0:
        time[0] = NOW
        with pytest.raises(ValueError):
            adapter().refresh(*original)


# ---------------------------------------------------------------------------
# C6: trust-and-byte-aware verified-snapshot reuse (2026-11-06)
# ---------------------------------------------------------------------------


def counted(lookup: Any, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count full signature/chain replays performed by one adapter instance."""
    calls: list[int] = []
    original = lookup._verify

    def verify(*args: Any) -> Any:
        """Record a full replay before delegating to the real verification."""
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(lookup, "_verify", verify)
    return calls


def test_unchanged_bytes_and_trust_reuse_verification_without_replay(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical cached bytes under identical current trust skip the full chain replay."""
    producer, _, _, _, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    a = adapter()
    a.refresh(*signed())
    replays = counted(a, monkeypatch)
    for _ in range(3):
        assert a.revoked("safe", ISSUER) is False
        assert a.revoked("bad", ISSUER) is True
    assert replays == []


@pytest.mark.parametrize("change", ["retired", "replaced", "resolver_error"])
def test_key_retirement_after_snapshot_write_invalidates_reuse(
    world: World, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Trust removal or replacement without any byte change must not revive the snapshot."""
    _, _, _, keys, adapter, signed = world
    a = adapter()
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is False
    if change == "retired":
        keys.pop((ISSUER, "key-1"))
    elif change == "replaced":
        keys[(ISSUER, "key-1")] = crypto_sign_seed_keypair(b"2" * 32)[0]
    else:
        def broken(issuer: str, key: str) -> bytes | None:
            """Simulate an unavailable trusted key registry."""
            raise OSError("registry unavailable")

        monkeypatch.setattr(a._keys, "_public_key_for", broken)
    unavailable(a)
    unavailable(a)
    if change != "resolver_error":
        keys[(ISSUER, "key-1")] = PUBLIC
        # Restored trust reverifies the unchanged bytes rather than trusting a memo.
        assert a.revoked("safe", ISSUER) is False


def test_retired_key_snapshot_is_not_revived_by_restart(world: World) -> None:
    """A restarted instance cannot reload or refresh a snapshot signed by a retired key."""
    _, store, _, keys, adapter, signed = world
    original = signed()
    adapter().refresh(*original)
    keys.pop((ISSUER, "key-1"))
    restarted = adapter()
    unavailable(restarted)
    with pytest.raises(Exception):
        restarted.refresh(*original)
    unavailable(restarted)
    assert store.acked_through(ISSUER) == 0


@pytest.mark.parametrize("damage", [
    "state_truncated", "state_extended", "state_byte_flip", "feed_truncated",
    "feed_extended", "feed_byte_flip", "state_other_head", "feed_other_head", "state_resigned_digest",
])
def test_cached_byte_tamper_after_warm_lookup_fails_closed(
    world: World, damage: str,
) -> None:
    """Any change to cached bytes, length, digest or head is reverified and refused."""
    producer, _, _, _, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    shorter = signed()
    producer.append_revocation("grant", "worse", signer=Signer())
    raw, events = signed()
    a = adapter()
    a.refresh(raw, events)
    assert a.revoked("safe", ISSUER) is False
    with sqlite3.connect(a.cache_path) as db:
        state, feed = db.execute("SELECT raw_state, feed FROM verified_snapshot").fetchone()
        if damage == "state_truncated":
            state = state[:-1]
        elif damage == "state_extended":
            state = state + b" "
        elif damage == "state_byte_flip":
            index = state.index(b'"worse"') + 1
            state = state[:index] + b"W" + state[index + 1:]
        elif damage == "feed_truncated":
            feed = feed[:-1]
        elif damage == "feed_extended":
            feed = feed + b" "
        elif damage == "feed_byte_flip":
            index = feed.index(b'"worse"') + 1
            feed = feed[:index] + b"W" + feed[index + 1:]
        elif damage == "state_other_head":
            state = shorter[0]
        elif damage == "feed_other_head":
            feed = b"[" + b",".join(wire.canonical_bytes(e) for e in shorter[1]) + b"]"
        else:
            state = resign(state, head_event_digest="sha256:" + "0" * 64)
        db.execute("UPDATE verified_snapshot SET raw_state = ?, feed = ?", (state, feed))
    unavailable(a)
    unavailable(a, "bad")


def test_cross_process_writer_replaces_reused_snapshot(world: World) -> None:
    """A newer snapshot written by another instance is read, never the reused older one."""
    producer, _, _, _, adapter, signed = world
    reader, writer = adapter(), adapter()
    reader.refresh(*signed())
    assert reader.revoked("late", ISSUER) is False
    producer.append_revocation("grant", "late", signer=Signer())
    writer.refresh(*signed())
    assert reader.revoked("late", ISSUER) is True


@pytest.mark.parametrize("seconds", [-1, 61])
def test_reused_snapshot_still_obeys_clock_rollback_and_expiry(world: World, seconds: int) -> None:
    """Reuse never skips the per-lookup clock high-water mark or freshness window."""
    _, _, time, _, adapter, _ = world
    a = adapter()
    a.refresh(*world[5]())
    assert a.revoked("safe", ISSUER) is False
    time[0] += timedelta(seconds=seconds)
    unavailable(a)
    time[0] = NOW + timedelta(seconds=1)
    if seconds < 0:
        assert a.revoked("safe", ISSUER) is False
    else:
        unavailable(a)


def test_restart_reverifies_and_failed_refresh_drops_reuse(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reuse is per-instance memory: restart reverifies, and a failed refresh discards it."""
    producer, _, _, _, adapter, signed = world
    a = adapter()
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is False
    restarted = adapter()
    restarted.refresh(*signed())
    replays = counted(restarted, monkeypatch)
    assert restarted.revoked("safe", ISSUER) is False
    assert replays == []
    with pytest.raises(Exception):
        restarted.refresh(b"{}", [])
    unavailable(restarted)
    assert restarted._snapshot_memo is None


def test_lookup_replays_a_changed_snapshot_outside_the_cache_write_lock(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full replay after another writer's refresh must not block other cache writers."""
    producer, _, _, _, adapter, signed = world
    reader, writer = adapter(), adapter()
    reader.refresh(*signed())
    producer.append_revocation("grant", "late", signer=Signer())
    writer.refresh(*signed())
    lock_free = lock_probe(reader, monkeypatch)
    assert reader.revoked("late", ISSUER) is True
    assert lock_free == [True]
    # The locked decision reused the outside-lock verification of the same bytes.
    assert reader.revoked("safe", ISSUER) is False
    assert lock_free == [True]


def lock_probe(lookup: Any, monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Record, per full replay, whether another connection could take the cache write lock."""
    original = lookup._verify
    lock_free: list[bool] = []

    def probe(*args: Any) -> Any:
        """Try a zero-wait write lock from a second connection, then replay for real."""
        with closing(sqlite3.connect(lookup.cache_path, timeout=0, isolation_level=None)) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("ROLLBACK")
                lock_free.append(True)
            except sqlite3.OperationalError:
                lock_free.append(False)
        return original(*args)

    monkeypatch.setattr(lookup, "_verify", probe)
    return lock_free


def test_refresh_replays_new_input_once_and_outside_the_cache_write_lock(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refresh verifies its input before locking and reuses its own previous snapshot record."""
    producer, _, _, _, adapter, signed = world
    a = adapter()
    a.refresh(*signed())
    producer.append_revocation("grant", "late", signer=Signer())
    lock_free = lock_probe(a, monkeypatch)
    a.refresh(*signed())
    assert lock_free == [True]
    assert a.revoked("late", ISSUER) is True
    assert lock_free == [True]


def test_refresh_rechecks_trust_after_taking_the_cache_write_lock(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Key retirement between outside-lock verification and the locked commit is refused."""
    from contextlib import contextmanager

    producer, store, _, keys, adapter, signed = world
    producer.append_revocation("grant", "bad", signer=Signer())
    a = adapter()
    raw, events = signed()
    transaction = a._transaction
    entered: list[int] = []

    @contextmanager
    def retire_on_second_lock() -> Iterator[sqlite3.Connection]:
        """Retire the key just as the refresh's main write transaction begins."""
        entered.append(1)
        if len(entered) == 2:
            keys.pop((ISSUER, "key-1"))
        with transaction() as database:
            yield database

    monkeypatch.setattr(a, "_transaction", retire_on_second_lock)
    with pytest.raises(Exception):
        a.refresh(raw, events)
    assert len(entered) >= 2
    assert store.acked_through(ISSUER) == 0
    with sqlite3.connect(a.cache_path) as db:
        assert db.execute("SELECT COUNT(*) FROM verified_snapshot").fetchone()[0] == 0
    unavailable(a)


def test_concurrent_lookups_replay_a_changed_snapshot_once(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Threads that find the same changed snapshot share one full replay, not one each."""
    import time as wall

    producer, _, _, _, adapter, signed = world
    reader, writer = adapter(), adapter()
    reader.refresh(*signed())
    producer.append_revocation("grant", "late", signer=Signer())
    writer.refresh(*signed())
    original = reader._verify
    replays: list[int] = []

    def slow(*args: Any) -> Any:
        """Widen the replay window so concurrent lookups overlap it."""
        replays.append(1)
        wall.sleep(0.2)
        return original(*args)

    monkeypatch.setattr(reader, "_verify", slow)
    start = threading.Barrier(4)
    answers: list[bool | str] = []

    def lookup() -> None:
        """Start together, then record the decision or the unavailability."""
        start.wait()
        try:
            answers.append(reader.revoked("late", ISSUER))
        except MODULE.RevocationUnavailable:
            answers.append("unavailable")

    threads = [threading.Thread(target=lookup) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert replays == [1]
    assert answers == [True] * 4


@pytest.mark.parametrize("change", ["retired", "replaced"])
def test_key_retirement_or_replacement_during_lookup_verification_fails_closed(
    world: World, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """O2: Trust retiring or replacing while _verify runs must fail closed and never return allow."""
    _, _, _, keys, adapter, signed = world
    a = adapter()
    a.refresh(*signed())
    assert a.revoked("safe", ISSUER) is False

    a._snapshot_memo = None
    original_verify = a._verify

    def verify_and_change_trust(raw: bytes, events: list[dict[str, Any]], now: datetime) -> Any:
        """Change issuer trust immediately after signature verification."""
        state = original_verify(raw, events, now)
        if change == "retired":
            keys.pop((ISSUER, "key-1"))
        else:
            keys[(ISSUER, "key-1")] = crypto_sign_seed_keypair(b"9" * 32)[0]
        return state

    monkeypatch.setattr(a, "_verify", verify_and_change_trust)
    unavailable(a)


@pytest.mark.parametrize("change", ["retired", "replaced"])
def test_key_retirement_or_replacement_during_refresh_verification_fails_closed(
    world: World, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """O2: Trust retiring or replacing while refresh verifies must fail closed."""
    _, store, _, keys, adapter, signed = world
    a = adapter()
    raw, events = signed()
    original_verify = a._verify

    def verify_and_change_trust(raw_bytes: bytes, evts: list[dict[str, Any]], now: datetime) -> Any:
        """Change issuer trust immediately after signature verification."""
        state = original_verify(raw_bytes, evts, now)
        if change == "retired":
            keys.pop((ISSUER, "key-1"))
        else:
            keys[(ISSUER, "key-1")] = crypto_sign_seed_keypair(b"9" * 32)[0]
        return state

    monkeypatch.setattr(a, "_verify", verify_and_change_trust)
    with pytest.raises(MODULE.RevocationUnavailable):
        a.refresh(raw, events)
    unavailable(a)
    assert store.acked_through(ISSUER) == 0


def test_transient_trust_change_during_prewarm_refuses_lookup(
    world: World, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A detected trust change cannot be hidden by a later successful replay."""
    _, _, _, keys, adapter, signed = world
    lookup = adapter()
    lookup.refresh(*signed())
    lookup._snapshot_memo = None
    original = lookup._trust
    calls = 0

    def transient_trust(key_ids: Any) -> Any:
        """Remove trust for the post-verification sample, then restore it."""
        nonlocal calls
        calls += 1
        if calls == 2:
            return None
        return original(key_ids)

    monkeypatch.setattr(lookup, "_trust", transient_trust)
    unavailable(lookup)
    assert keys[(ISSUER, "key-1")] == PUBLIC


@pytest.mark.parametrize("operation", ["lookup", "refresh"])
def test_detected_transient_trust_change_refuses_without_retry(
    world: World, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    """A changed locked trust sample refuses even when trust immediately recovers."""
    _, _, _, _, adapter, signed = world
    lookup = adapter()
    snapshot = signed()
    lookup.refresh(*snapshot)
    original = lookup._trust
    calls = 0
    changed_call = 1 if operation == "lookup" else 3

    def transient_trust(key_ids: Any) -> Any:
        """Return a changed key for the locked trust sample only."""
        nonlocal calls
        calls += 1
        if calls == changed_call:
            return (("key-1", b"x" * 32),)
        return original(key_ids)

    monkeypatch.setattr(lookup, "_trust", transient_trust)
    if operation == "lookup":
        unavailable(lookup)
    else:
        with pytest.raises(MODULE.RevocationUnavailable):
            lookup.refresh(*snapshot)


@pytest.mark.parametrize("operation", ["prewarm", "warm", "refresh"])
def test_once_raising_key_resolver_refuses_current_operation(
    world: World, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    """A transient resolver outage cannot turn into an allow by retrying."""
    _, _, _, _, adapter, signed = world
    lookup = adapter()
    snapshot = signed()
    lookup.refresh(*snapshot)
    if operation == "prewarm":
        lookup._snapshot_memo = None
    original = lookup._keys._public_key_for
    calls = 0

    def raises_once(issuer: str, key: str) -> bytes | None:
        """Fail the first trusted read and recover on later reads."""
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("resolver unavailable")
        return original(issuer, key)

    monkeypatch.setattr(lookup._keys, "_public_key_for", raises_once)
    if operation == "refresh":
        with pytest.raises((OSError, MODULE.RevocationUnavailable)):
            lookup.refresh(*snapshot)
    else:
        unavailable(lookup)
