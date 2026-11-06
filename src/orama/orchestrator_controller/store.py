"""Authoritative SQLite claim store: the controller's single claim-state writer (IC-1).

Every mutation runs in one ``BEGIN IMMEDIATE`` transaction that reads the idempotency row,
the task and the lease, applies compare-and-set updates, and writes the audit and outbox
rows that announce the change (IC-11, doc 68 section 4.1). A refusal rolls the mutation
back; only the controller clock high-water mark survives it, so a backward clock step can
never revive an expired lease.

This store does not authenticate. ``apply_admitted`` must be reached only through
``ControllerService``, which runs the transport and capability checks first (IC-3, IC-4).
Job-claim leases here are separate from the execution run leases in
``orama.graph.execution_guard``; the two share no table, epoch or token.
"""
from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from orama.graph.private_store import prepare_private_store
from orama.orchestrator_controller.envelope import (
    ClaimRequest,
    canonical_json,
    sha256_hex,
    validate_base_sha,
    validate_digest,
    validate_opaque_id,
    validate_source_ref,
)
from orama.orchestrator_controller.migrations import apply_migrations
from orama.orchestrator_controller.outbox import ALLOWLIST_DIGEST, OutboxEvent, build_redacted_payload
from orama.orchestrator_controller.refusals import ClaimRefused

Clock = Callable[[], datetime]
POLICY_VERSION = "controller-claim-policy-v1"
EFFECT_CLASSES: frozenset[str] = frozenset({"pure", "external"})
MIN_LEASE_TTL = timedelta(seconds=1)
MAX_LEASE_TTL = timedelta(days=1)
MAX_SWEEP_LIMIT = 10_000
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICRO = timedelta(microseconds=1)
_READABLE_TABLES = frozenset(
    {"tasks", "leases", "idempotency", "outbox", "audit", "maintenance_owner",
     "controller_meta", "schema_migrations"}
)


def to_micros(moment: datetime) -> int:
    """Convert a timezone-aware datetime to integer microseconds since the Unix epoch."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("controller clock must return timezone-aware datetimes")
    return (moment - _EPOCH) // _MICRO


def from_micros(value: int) -> datetime:
    """Convert integer microseconds since the Unix epoch back to an aware UTC datetime."""
    return _EPOCH + timedelta(microseconds=value)


@dataclass(frozen=True, slots=True)
class Admission:
    """What the service proved about a request before handing it to the store."""

    principal_id: str
    policy_version: str = POLICY_VERSION


@dataclass(frozen=True, slots=True)
class TaskView:
    """A read-only snapshot of one task row."""

    task_id: str
    state: str
    version: int
    source_ref: str
    expected_base_sha: str
    payload_digest: str
    effect_class: str
    result_digest: str | None
    failure_class: str | None


@dataclass(frozen=True, slots=True)
class ClaimReceipt:
    """The authoritative result of one committed transition (or its replay).

    ``lease_token`` is present only on a claim receipt and is excluded from ``repr``.
    """

    receipt_id: str
    operation: str
    task_id: str
    task_version: int
    task_state: str
    lease_id: str | None = None
    lease_token: str | None = field(default=None, repr=False)
    lease_expires_at: datetime | None = None
    result_digest: str | None = None
    failure_class: str | None = None
    replayed: bool = False

    def to_json(self) -> str:
        """Serialize the committed receipt for the private idempotency row."""
        body = {
            "receipt_id": self.receipt_id,
            "operation": self.operation,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "task_state": self.task_state,
            "lease_id": self.lease_id,
            "lease_token": self.lease_token,
            "lease_expires_at": None if self.lease_expires_at is None else to_micros(self.lease_expires_at),
            "result_digest": self.result_digest,
            "failure_class": self.failure_class,
        }
        return canonical_json(body)

    @classmethod
    def from_json(cls, text: str) -> ClaimReceipt:
        """Rebuild a stored receipt; the result is marked as a replay."""
        body: dict[str, Any] = json.loads(text)
        expires = body.pop("lease_expires_at")
        return cls(**body, lease_expires_at=None if expires is None else from_micros(expires), replayed=True)


@dataclass(frozen=True, slots=True)
class RecoveryReceipt:
    """The result of expiring one lease under the controller clock rule."""

    task_id: str
    lease_id: str
    task_version: int
    disposition: str
    recovered_at: datetime


class ControllerStore:
    """The controller-owned SQLite database and its atomic transitions.

    One instance holds one connection guarded by a lock; SQLite's ``BEGIN IMMEDIATE``
    serializes writers across connections and processes. WAL with ``synchronous=FULL``.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Clock,
        lease_ttl: timedelta = timedelta(minutes=5),
        busy_timeout: float = 30.0,
    ) -> None:
        """Open (creating privately) the store, apply reviewed migrations and read its identity.

        ``clock`` is the controller's only time source and must return aware datetimes.
        ``lease_ttl`` bounds every claim and renewal; it must lie between one second and one
        day. ``busy_timeout`` is how long a writer waits for SQLite's write lock before the
        request is refused ``controller.busy``.
        """
        if not isinstance(lease_ttl, timedelta) or not MIN_LEASE_TTL <= lease_ttl <= MAX_LEASE_TTL:
            raise ValueError("lease_ttl must be between one second and one day")
        if isinstance(busy_timeout, bool) or not isinstance(busy_timeout, (int, float)) or busy_timeout <= 0:
            raise ValueError("busy_timeout must be a positive number of seconds")
        self._clock = clock
        self._ttl = lease_ttl // _MICRO
        self._lock = threading.Lock()
        prepared = prepare_private_store(path)
        self._db = sqlite3.connect(
            str(prepared), isolation_level=None, check_same_thread=False, timeout=float(busy_timeout)
        )
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            apply_migrations(self._db, to_micros(clock()))
            with self._tx() as db:
                db.execute(
                    "INSERT OR IGNORE INTO controller_meta (key, value) VALUES ('store_id', ?)",
                    (f"controller-store-{secrets.token_hex(16)}",),
                )
                self._store_id = str(
                    db.execute("SELECT value FROM controller_meta WHERE key = 'store_id'").fetchone()[0]
                )
        except BaseException:
            self._db.close()
            raise

    # --- lifecycle and introspection ------------------------------------------------------

    @property
    def store_id(self) -> str:
        """Return this database's random opaque identity."""
        return self._store_id

    @property
    def lease_ttl(self) -> timedelta:
        """Return the configured lease time-to-live."""
        return timedelta(microseconds=self._ttl)

    def close(self) -> None:
        """Close the connection; uncommitted work is rolled back by SQLite."""
        with self._lock:
            self._db.close()

    def pragmas(self) -> tuple[str, int]:
        """Return the journal mode and synchronous level in force."""
        with self._lock:
            mode = self._db.execute("PRAGMA journal_mode").fetchone()[0]
            sync = self._db.execute("PRAGMA synchronous").fetchone()[0]
        return str(mode).lower(), int(sync)

    def _read_all(self, table: str) -> list[tuple[Any, ...]]:
        """Return every row of a known table in rowid order (inspection and tests only)."""
        if table not in _READABLE_TABLES:
            raise ValueError("unknown controller table")
        with self._lock:
            return [tuple(row) for row in self._db.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def task(self, task_id: str) -> TaskView | None:
        """Return a snapshot of ``task_id`` or ``None`` when it was never declared."""
        with self._lock:
            row = self._db.execute(_TASK_SELECT, (task_id,)).fetchone()
        return None if row is None else TaskView(*row)

    # --- transactions ---------------------------------------------------------------------

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Run one ``BEGIN IMMEDIATE`` transaction; a lock timeout refuses ``controller.busy``."""
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                if "locked" in str(error) or "busy" in str(error):
                    raise ClaimRefused("controller.busy") from error
                raise
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            try:
                self._db.execute("COMMIT")
            except sqlite3.OperationalError as error:
                self._db.execute("ROLLBACK")
                if "locked" in str(error) or "busy" in str(error):
                    raise ClaimRefused("controller.busy") from error
                raise

    def _now(self, db: sqlite3.Connection) -> int:
        """Return the effective controller time and persist the monotonic high-water mark."""
        observed = to_micros(self._clock())
        row = db.execute("SELECT value FROM controller_meta WHERE key = 'clock_highwater'").fetchone()
        mark = int(row[0]) if row is not None else observed
        effective = max(observed, mark)
        if row is None or effective != mark:
            db.execute(
                "INSERT INTO controller_meta (key, value) VALUES ('clock_highwater', ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (str(effective),),
            )
        return effective

    @contextmanager
    def _refusable(self, db: sqlite3.Connection) -> Iterator[None]:
        """Undo the work inside the block on ``ClaimRefused`` but keep earlier writes.

        The clock high-water mark is written before this block, so it commits even when
        the transition is refused.
        """
        db.execute("SAVEPOINT transition")
        try:
            yield
        except ClaimRefused:
            db.execute("ROLLBACK TO transition")
            db.execute("RELEASE transition")
            raise
        db.execute("RELEASE transition")

    def _commit_refusal(self, body: Callable[[sqlite3.Connection, int], ClaimReceipt]) -> ClaimReceipt:
        """Run ``body`` in a transaction; on refusal commit only the clock mark, then re-raise."""
        refusal: ClaimRefused | None = None
        receipt: ClaimReceipt | None = None
        with self._tx() as db:
            now = self._now(db)
            try:
                with self._refusable(db):
                    receipt = body(db, now)
            except ClaimRefused as error:
                refusal = error
        if refusal is not None:
            raise refusal
        assert receipt is not None
        return receipt

    # --- declaration ----------------------------------------------------------------------

    def declare_task(
        self,
        task_id: str,
        *,
        source_ref: str,
        expected_base_sha: str,
        payload_digest: str,
        effect_class: str = "pure",
    ) -> TaskView:
        """Declare a new pending task, or confirm an identical existing declaration.

        This is an in-process composition call, not a client operation. ``effect_class`` is
        ``pure`` (safe to reissue after expiry) or ``external`` (expiry holds it for
        reconciliation). Different content for an existing id is refused
        ``task.declaration_conflict``. Invalid values raise ``ValueError``.
        """
        validate_opaque_id(task_id, "task_id")
        validate_source_ref(source_ref)
        validate_base_sha(expected_base_sha)
        validate_digest(payload_digest, "payload_digest")
        if effect_class not in EFFECT_CLASSES:
            raise ValueError("effect_class must be 'pure' or 'external'")
        declared = (source_ref, expected_base_sha, payload_digest, effect_class)
        with self._tx() as db:
            now = self._now(db)
            row = db.execute(_TASK_SELECT, (task_id,)).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO tasks (task_id, state, version, source_ref, expected_base_sha,"
                    " payload_digest, effect_class, created_at, updated_at)"
                    " VALUES (?, 'pending', 1, ?, ?, ?, ?, ?, ?)",
                    (task_id, *declared, now, now),
                )
                row = db.execute(_TASK_SELECT, (task_id,)).fetchone()
        view = TaskView(*row)
        if (view.source_ref, view.expected_base_sha, view.payload_digest, view.effect_class) != declared:
            raise ClaimRefused("task.declaration_conflict")
        return view

    # --- admitted transitions -------------------------------------------------------------

    def apply_admitted(self, request: ClaimRequest, admission: Admission) -> ClaimReceipt:
        """Apply one admitted request atomically and return its receipt.

        Order inside the transaction: claim-scope idempotency (replay or
        ``idempotency.key_reused``), task existence, source line, then the operation's
        own preconditions. Only committed transitions record an idempotency row.
        """
        if admission.principal_id != request.principal:
            raise ClaimRefused("capability.principal_mismatch")
        digest = request.request_digest()

        def body(db: sqlite3.Connection, now: int) -> ClaimReceipt:
            """Decide and apply the transition inside the open transaction."""
            stored = db.execute(
                "SELECT request_digest, receipt_json FROM idempotency"
                " WHERE principal_id = ? AND operation = ? AND idempotency_key = ?",
                (request.principal, request.operation, request.idempotency_key),
            ).fetchone()
            if stored is not None:
                if stored[0] != digest:
                    raise ClaimRefused("idempotency.key_reused")
                return ClaimReceipt.from_json(str(stored[1]))
            row = db.execute(_TASK_SELECT, (request.task_id,)).fetchone()
            if row is None:
                raise ClaimRefused("task.unknown")
            task = TaskView(*row)
            if (task.source_ref, task.expected_base_sha) != (request.source_ref, request.expected_base_sha):
                raise ClaimRefused("task.source_mismatch")
            if request.operation == "claim":
                receipt = self._claim(db, request, task, now, admission)
            else:
                receipt = self._lease_operation(db, request, task, now, admission)
            db.execute(
                "INSERT INTO idempotency (principal_id, operation, idempotency_key, request_digest,"
                " receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request.principal, request.operation, request.idempotency_key, digest,
                 receipt.to_json(), now),
            )
            return receipt

        return self._commit_refusal(body)

    def _claim(
        self, db: sqlite3.Connection, request: ClaimRequest, task: TaskView, now: int, admission: Admission
    ) -> ClaimReceipt:
        """Create the one active lease for a pending task and bump its version."""
        if task.state != "pending":
            raise ClaimRefused("task.already_claimed" if task.state == "claimed" else "task.not_claimable")
        if task.version != request.expected_task_version:
            raise ClaimRefused("task.version_conflict")
        version = task.version + 1
        lease_id = f"lease-{secrets.token_hex(16)}"
        token = secrets.token_urlsafe(32)
        expires = now + self._ttl
        _exactly_one(db.execute(
            "UPDATE tasks SET state = 'claimed', version = ?, updated_at = ?"
            " WHERE task_id = ? AND version = ? AND state = 'pending'",
            (version, now, task.task_id, task.version),
        ))
        db.execute(
            "INSERT INTO leases (lease_id, task_id, principal_id, token_digest, fence, issued_at,"
            " expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')",
            (lease_id, task.task_id, request.principal, sha256_hex(token), version, now, expires),
        )
        receipt = ClaimReceipt(
            receipt_id=f"receipt-{secrets.token_hex(16)}", operation="claim", task_id=task.task_id,
            task_version=version, task_state="claimed", lease_id=lease_id, lease_token=token,
            lease_expires_at=from_micros(expires),
        )
        self._record(db, now, actor=request.principal, action="claim", outcome="claimed",
                     lineage=request.lineage_dict(), policy_version=admission.policy_version,
                     event={"kind": "claim.claimed", "task_id": task.task_id, "task_version": version,
                            "state": "claimed", "lease_id": lease_id})
        return receipt

    def _lease_operation(
        self, db: sqlite3.Connection, request: ClaimRequest, task: TaskView, now: int, admission: Admission
    ) -> ClaimReceipt:
        """Apply renew, complete, release or fail after verifying the presented lease."""
        lease = db.execute(
            "SELECT principal_id, token_digest, fence, expires_at, state FROM leases"
            " WHERE lease_id = ? AND task_id = ?",
            (request.lease_id, task.task_id),
        ).fetchone()
        if lease is None:
            raise ClaimRefused("lease.unknown")
        principal_id, token_digest, fence, expires_at, lease_state = lease
        if principal_id != request.principal:
            raise ClaimRefused("lease.principal_mismatch")
        assert request.lease_token is not None
        if not hmac.compare_digest(str(token_digest), sha256_hex(request.lease_token)):
            raise ClaimRefused("lease.token_invalid")
        if lease_state != "active":
            raise ClaimRefused("lease.not_active")
        if int(fence) != task.version or task.state != "claimed":
            raise ClaimRefused("lease.fenced")
        if now >= int(expires_at):
            raise ClaimRefused("lease.expired")
        if request.expected_task_version != task.version:
            raise ClaimRefused("task.version_conflict")
        receipt_id = f"receipt-{secrets.token_hex(16)}"
        common = {"actor": request.principal, "lineage": request.lineage_dict(),
                  "policy_version": admission.policy_version}
        if request.operation == "renew":
            expires = now + self._ttl
            _exactly_one(db.execute(
                "UPDATE leases SET expires_at = ? WHERE lease_id = ? AND state = 'active'",
                (expires, request.lease_id),
            ))
            self._record(db, now, action="renew", outcome="renewed", event=None, **common)
            return ClaimReceipt(receipt_id=receipt_id, operation="renew", task_id=task.task_id,
                                task_version=task.version, task_state="claimed",
                                lease_id=request.lease_id, lease_expires_at=from_micros(expires))
        lease_state_after, task_state_after = {
            "complete": ("completed", "completed"),
            "release": ("released", "pending"),
            "fail": ("failed", "failed"),
        }[request.operation]
        version = task.version + 1
        _exactly_one(db.execute(
            "UPDATE leases SET state = ?, ended_at = ? WHERE lease_id = ? AND state = 'active'",
            (lease_state_after, now, request.lease_id),
        ))
        _exactly_one(db.execute(
            "UPDATE tasks SET state = ?, version = ?, updated_at = ?, result_digest = ?, failure_class = ?"
            " WHERE task_id = ? AND version = ? AND state = 'claimed'",
            (task_state_after, version, now, request.result_digest, request.failure_class,
             task.task_id, task.version),
        ))
        self._record(db, now, action=request.operation, outcome=lease_state_after,
                     event={"kind": f"claim.{lease_state_after}", "task_id": task.task_id,
                            "task_version": version, "state": task_state_after,
                            "lease_id": request.lease_id, "failure_class": request.failure_class},
                     **common)
        return ClaimReceipt(receipt_id=receipt_id, operation=request.operation, task_id=task.task_id,
                            task_version=version, task_state=task_state_after, lease_id=request.lease_id,
                            result_digest=request.result_digest, failure_class=request.failure_class)

    # --- maintenance ownership and recovery (controller-only, IC-18) -----------------------

    def acquire_maintenance(self, owner_id: str, *, ttl: timedelta) -> int:
        """Become the one expiry owner for this database; return the new owner epoch.

        Refused ``worker.owner_conflict`` while another owner's row is live. A row whose
        expiry has passed (a crashed or stopped owner) is taken over with a higher epoch, which
        fences the previous owner's later sweeps.
        """
        validate_opaque_id(owner_id, "owner_id")
        ttl_us = _bounded_ttl(ttl)
        with self._tx() as db:
            now = self._now(db)
            row = db.execute(
                "SELECT owner_id, epoch, expires_at FROM maintenance_owner WHERE scope = 'expiry'"
            ).fetchone()
            if row is not None and now < int(row[2]) and row[0] != owner_id:
                conflict = True
            else:
                conflict = False
                epoch = 1 if row is None else int(row[1]) + 1
                db.execute(
                    "INSERT INTO maintenance_owner (scope, owner_id, epoch, expires_at)"
                    " VALUES ('expiry', ?, ?, ?) ON CONFLICT (scope) DO UPDATE SET"
                    " owner_id = excluded.owner_id, epoch = excluded.epoch, expires_at = excluded.expires_at",
                    (owner_id, epoch, now + ttl_us),
                )
        if conflict:
            raise ClaimRefused("worker.owner_conflict")
        return epoch

    def release_maintenance(self, owner_id: str, epoch: int) -> bool:
        """Give up ownership if ``owner_id`` at ``epoch`` still holds it; return whether it did.

        The row is kept with an expired deadline so the epoch stays monotonic.
        """
        with self._tx() as db:
            now = self._now(db)
            cursor = db.execute(
                "UPDATE maintenance_owner SET expires_at = ?"
                " WHERE scope = 'expiry' AND owner_id = ? AND epoch = ? AND expires_at > ?",
                (now, owner_id, epoch, now),
            )
            return cursor.rowcount == 1

    def recover_expired(
        self, owner_id: str, epoch: int, *, limit: int, owner_ttl: timedelta
    ) -> tuple[RecoveryReceipt, ...]:
        """Expire at most ``limit`` leases whose controller-clock expiry has passed.

        One transaction verifies that ``owner_id`` at ``epoch`` is the live maintenance owner
        (else ``worker.fenced``), extends that ownership, and for each candidate re-verifies
        with compare-and-set updates that the lease is still active and expired and that the
        task is still claimed at the lease's fence version. Rows that fail that check are left
        untouched. A ``pure`` task returns to ``pending``; an ``external`` task moves to
        ``reconcile`` because expiry cannot prove its effects did not happen (IC-16).
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SWEEP_LIMIT:
            raise ValueError(f"limit must be an integer from 1 to {MAX_SWEEP_LIMIT}")
        ttl_us = _bounded_ttl(owner_ttl)
        fenced = False
        receipts: list[RecoveryReceipt] = []
        with self._tx() as db:
            now = self._now(db)
            owned = db.execute(
                "UPDATE maintenance_owner SET expires_at = ?"
                " WHERE scope = 'expiry' AND owner_id = ? AND epoch = ? AND expires_at > ?",
                (now + ttl_us, owner_id, epoch, now),
            )
            if owned.rowcount != 1:
                fenced = True
            else:
                candidates = db.execute(
                    "SELECT l.lease_id, l.task_id, l.fence, t.effect_class FROM leases AS l"
                    " JOIN tasks AS t ON t.task_id = l.task_id"
                    " WHERE l.state = 'active' AND l.expires_at <= ?"
                    " AND t.state = 'claimed' AND t.version = l.fence"
                    " ORDER BY l.expires_at, l.lease_id LIMIT ?",
                    (now, limit),
                ).fetchall()
                for lease_id, task_id, fence, effect_class in candidates:
                    receipt = self._expire_one(db, now, str(lease_id), str(task_id), int(fence), str(effect_class))
                    if receipt is not None:
                        receipts.append(receipt)
        if fenced:
            raise ClaimRefused("worker.fenced")
        return tuple(receipts)

    def _expire_one(
        self, db: sqlite3.Connection, now: int, lease_id: str, task_id: str, fence: int, effect_class: str
    ) -> RecoveryReceipt | None:
        """Expire one lease with compare-and-set checks; return ``None`` if anything moved."""
        disposition = "pending" if effect_class == "pure" else "reconcile"
        db.execute("SAVEPOINT expire_one")
        lease = db.execute(
            "UPDATE leases SET state = 'expired', ended_at = ?"
            " WHERE lease_id = ? AND task_id = ? AND fence = ? AND state = 'active' AND expires_at <= ?",
            (now, lease_id, task_id, fence, now),
        )
        task = db.execute(
            "UPDATE tasks SET state = ?, version = ?, updated_at = ?"
            " WHERE task_id = ? AND version = ? AND state = 'claimed'",
            (disposition, fence + 1, now, task_id, fence),
        )
        if lease.rowcount != 1 or task.rowcount != 1:
            db.execute("ROLLBACK TO expire_one")
            db.execute("RELEASE expire_one")
            return None
        db.execute("RELEASE expire_one")
        self._record(db, now, actor="controller-recovery", action="recover-expired", outcome="expired",
                     lineage=None, policy_version=POLICY_VERSION,
                     event={"kind": "claim.expired", "task_id": task_id, "task_version": fence + 1,
                            "state": disposition, "lease_id": lease_id, "disposition": disposition})
        return RecoveryReceipt(task_id=task_id, lease_id=lease_id, task_version=fence + 1,
                               disposition=disposition, recovered_at=from_micros(now))

    # --- audit and outbox -----------------------------------------------------------------

    def _record(
        self,
        db: sqlite3.Connection,
        now: int,
        *,
        actor: str,
        action: str,
        outcome: str,
        lineage: dict[str, str | bool] | None,
        policy_version: str,
        event: dict[str, Any] | None,
    ) -> None:
        """Write the audit row and, when ``event`` is given, its redacted outbox row."""
        event_id = f"event-{secrets.token_hex(16)}"
        db.execute(
            "INSERT INTO audit (event_id, actor, action, outcome, lineage, policy_version, occurred_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_id, actor, action, outcome, None if lineage is None else canonical_json(lineage),
             policy_version, now),
        )
        if event is None:
            return
        fields = dict(event, event_id=event_id, occurred_at=now, lineage=lineage)
        payload, payload_digest = build_redacted_payload(fields)
        db.execute(
            "INSERT INTO outbox (event_id, kind, redacted_payload, payload_digest, allowlist_digest,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, str(event["kind"]), payload, payload_digest, ALLOWLIST_DIGEST, now),
        )

    def pending_outbox(self, limit: int) -> tuple[OutboxEvent, ...]:
        """Return up to ``limit`` unpublished events in sequence order, integrity-checked."""
        with self._lock:
            rows = self._db.execute(
                "SELECT event_id, sequence, kind, redacted_payload, payload_digest, allowlist_digest"
                " FROM outbox WHERE published_at IS NULL ORDER BY sequence LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(OutboxEvent.from_row(str(r[0]), int(r[1]), str(r[2]), str(r[3]), str(r[4]), str(r[5]))
                     for r in rows)

    def record_delivery_attempt(self, event_id: str) -> None:
        """Count one delivery attempt for ``event_id``; this touches only the outbox row."""
        with self._tx() as db:
            db.execute(
                "UPDATE outbox SET delivery_attempts = delivery_attempts + 1"
                " WHERE event_id = ? AND published_at IS NULL",
                (event_id,),
            )

    def mark_published(self, event_id: str) -> bool:
        """Mark ``event_id`` delivered once; return whether this call marked it.

        Re-marking, out-of-order marks and unknown ids are harmless: only
        ``outbox.published_at`` can change, never claim state (IC-5).
        """
        with self._tx() as db:
            now = self._now(db)
            cursor = db.execute(
                "UPDATE outbox SET published_at = ? WHERE event_id = ? AND published_at IS NULL",
                (now, event_id),
            )
            return cursor.rowcount == 1

    def record_refusal(self, operation: str, principal_hint: str | None, code: str) -> None:
        """Audit a refused request without proof material (IC-25).

        ``principal_hint`` is stored only when it is a valid opaque identifier; otherwise the
        actor is recorded as ``unknown``. A busy database drops the audit row rather than
        blocking the refusal; the refusal itself is still returned to the caller.
        """
        try:
            actor = validate_opaque_id(principal_hint, "principal")
        except ValueError:
            actor = "unknown"
        action = operation if isinstance(operation, str) and operation.isidentifier() else "unknown"
        ClaimRefused(code)  # validates the code against the closed vocabulary
        try:
            with self._tx() as db:
                now = self._now(db)
                self._record(db, now, actor=actor, action=action, outcome=f"refused:{code}",
                             lineage=None, policy_version=POLICY_VERSION, event=None)
        except ClaimRefused:
            return


_TASK_SELECT = (
    "SELECT task_id, state, version, source_ref, expected_base_sha, payload_digest, effect_class,"
    " result_digest, failure_class FROM tasks WHERE task_id = ?"
)


def _bounded_ttl(ttl: timedelta) -> int:
    """Return ``ttl`` in microseconds when it lies between one second and one day."""
    if not isinstance(ttl, timedelta) or not MIN_LEASE_TTL <= ttl <= MAX_LEASE_TTL:
        raise ValueError("ttl must be between one second and one day")
    return ttl // _MICRO


def _exactly_one(cursor: sqlite3.Cursor) -> None:
    """Assert a compare-and-set update changed exactly one row; otherwise abort the transaction."""
    if cursor.rowcount != 1:
        raise RuntimeError("compare-and-set update did not match exactly one row")


__all__ = [
    "Admission",
    "ClaimReceipt",
    "ControllerStore",
    "MAX_SWEEP_LIMIT",
    "POLICY_VERSION",
    "RecoveryReceipt",
    "TaskView",
    "from_micros",
    "to_micros",
]
