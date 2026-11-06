"""Reviewed, versioned SQLite migrations for the controller store.

Each migration is an ordered tuple of statements with a SHA-256 digest over its version,
name and statements. ``REVIEWED_MIGRATION_DIGESTS`` pins the digest each version was
reviewed at: a migration whose digest is not pinned is refused before any statement runs,
an applied migration whose recorded digest differs is refused at open, and a database that
records a newer version than this code knows is refused rather than guessed at. Changing a
migration therefore requires changing its pinned digest in the same reviewed diff.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from orama.orchestrator_controller.envelope import canonical_json, sha256_hex


class MigrationRefused(RuntimeError):
    """The database schema does not match the reviewed migrations; nothing was changed."""


@dataclass(frozen=True, slots=True)
class Migration:
    """One numbered schema step: its statements run in a single transaction."""

    version: int
    name: str
    statements: tuple[str, ...]


def migration_digest(migration: Migration) -> str:
    """Return the SHA-256 digest that review pins for ``migration``."""
    return sha256_hex(
        canonical_json(
            {"version": migration.version, "name": migration.name, "statements": list(migration.statements)}
        )
    )


_BOOTSTRAP = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    " version INTEGER PRIMARY KEY, name TEXT NOT NULL,"
    " digest TEXT NOT NULL, applied_at INTEGER NOT NULL)"
)

MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="claim_store_v1",
        statements=(
            "CREATE TABLE controller_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE tasks ("
            " task_id TEXT PRIMARY KEY,"
            " state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'completed', 'failed', 'reconcile')),"
            " version INTEGER NOT NULL CHECK (version >= 1),"
            " source_ref TEXT NOT NULL, expected_base_sha TEXT NOT NULL, payload_digest TEXT NOT NULL,"
            " effect_class TEXT NOT NULL CHECK (effect_class IN ('pure', 'external')),"
            " result_digest TEXT, failure_class TEXT,"
            " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
            "CREATE TABLE leases ("
            " lease_id TEXT PRIMARY KEY,"
            " task_id TEXT NOT NULL REFERENCES tasks (task_id),"
            " principal_id TEXT NOT NULL, token_digest TEXT NOT NULL,"
            " fence INTEGER NOT NULL CHECK (fence >= 1),"
            " issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,"
            " state TEXT NOT NULL CHECK (state IN ('active', 'completed', 'released', 'failed', 'expired')),"
            " ended_at INTEGER)",
            "CREATE UNIQUE INDEX leases_one_active_per_task ON leases (task_id) WHERE state = 'active'",
            "CREATE INDEX leases_active_expiry ON leases (expires_at) WHERE state = 'active'",
            "CREATE TABLE idempotency ("
            " principal_id TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,"
            " request_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, created_at INTEGER NOT NULL,"
            " PRIMARY KEY (principal_id, operation, idempotency_key))",
            "CREATE TABLE outbox ("
            " sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
            " event_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,"
            " redacted_payload TEXT NOT NULL, payload_digest TEXT NOT NULL,"
            " allowlist_digest TEXT NOT NULL, created_at INTEGER NOT NULL,"
            " published_at INTEGER, delivery_attempts INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE audit ("
            " sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
            " event_id TEXT NOT NULL UNIQUE, actor TEXT NOT NULL, action TEXT NOT NULL,"
            " outcome TEXT NOT NULL, lineage TEXT, policy_version TEXT NOT NULL,"
            " occurred_at INTEGER NOT NULL)",
            "CREATE TABLE maintenance_owner ("
            " scope TEXT PRIMARY KEY, owner_id TEXT NOT NULL,"
            " epoch INTEGER NOT NULL CHECK (epoch >= 1), expires_at INTEGER NOT NULL)",
        ),
    ),
)

REVIEWED_MIGRATION_DIGESTS: Mapping[int, str] = MappingProxyType({
    1: "00b385b918214207f31c5bc2edaecb0c6a11af2f5cb24f0dc6bfaf82fad29b60",
})


def apply_migrations(db: sqlite3.Connection, applied_at: int) -> int:
    """Bring ``db`` to the newest reviewed schema; return the resulting version.

    ``db`` must be in autocommit mode (``isolation_level=None``). Every check runs before the
    first statement; each migration then runs in its own ``BEGIN IMMEDIATE`` transaction and
    re-checks that a concurrent opener has not already applied it.
    """
    known = {migration.version: migration for migration in MIGRATIONS}
    for migration in known.values():
        if REVIEWED_MIGRATION_DIGESTS.get(migration.version) != migration_digest(migration):
            raise MigrationRefused(f"migration {migration.version} is not reviewed")
    db.execute(_BOOTSTRAP)
    applied = _applied(db)
    if applied and max(applied) > max(known, default=0):
        raise MigrationRefused("database records a newer schema than this code knows")
    for version, digest in applied.items():
        if version not in known or digest != migration_digest(known[version]):
            raise MigrationRefused(f"applied migration {version} digest differs from the reviewed digest")
    for version in sorted(known):
        if version in applied:
            continue
        migration = known[version]
        db.execute("BEGIN IMMEDIATE")
        try:
            if version not in _applied(db):
                for statement in migration.statements:
                    db.execute(statement)
                db.execute(
                    "INSERT INTO schema_migrations (version, name, digest, applied_at) VALUES (?, ?, ?, ?)",
                    (version, migration.name, migration_digest(migration), applied_at),
                )
        except BaseException:
            db.execute("ROLLBACK")
            raise
        db.execute("COMMIT")
    return max(known, default=0)


def _applied(db: sqlite3.Connection) -> dict[int, str]:
    """Return the applied migration versions and their recorded digests."""
    return {int(row[0]): str(row[1]) for row in db.execute("SELECT version, digest FROM schema_migrations")}
