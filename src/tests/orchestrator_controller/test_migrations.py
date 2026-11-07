"""C2a: reviewed, versioned migrations for the controller store."""
from __future__ import annotations

import sqlite3
import stat

import pytest

from orama.orchestrator_controller import migrations
from orama.orchestrator_controller.migrations import (
    MIGRATIONS,
    REVIEWED_MIGRATION_DIGESTS,
    MigrationRefused,
    migration_digest,
)

from .support import FakeClock, open_store


def test_every_migration_matches_its_reviewed_digest() -> None:
    """A migration is applied only when its statements hash to the reviewed digest."""
    assert [m.version for m in MIGRATIONS] == list(range(1, len(MIGRATIONS) + 1))
    for migration in MIGRATIONS:
        assert REVIEWED_MIGRATION_DIGESTS[migration.version] == migration_digest(migration)


def test_fresh_store_records_reviewed_versions_and_reopens(tmp_path) -> None:
    """Opening twice applies each migration once and records its digest."""
    store = open_store(tmp_path)
    store.close()
    store = open_store(tmp_path)
    rows = store._read_all("schema_migrations")
    assert [(row[0], row[2]) for row in rows] == [
        (m.version, REVIEWED_MIGRATION_DIGESTS[m.version]) for m in MIGRATIONS
    ]
    assert store.pragmas() == ("wal", 2)
    store.close()


def test_store_file_is_private(tmp_path) -> None:
    """The authoritative database is a 0600 file in a 0700 directory."""
    open_store(tmp_path).close()
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "state" / "controller.db").stat().st_mode) == 0o600


def test_tampered_recorded_digest_is_refused(tmp_path) -> None:
    """A database whose applied migration differs from the reviewed one is not opened."""
    open_store(tmp_path).close()
    db = sqlite3.connect(tmp_path / "state" / "controller.db")
    db.execute("UPDATE schema_migrations SET digest = 'x' WHERE version = 1")
    db.commit()
    db.close()
    with pytest.raises(MigrationRefused, match="digest"):
        open_store(tmp_path)


def test_newer_schema_is_refused(tmp_path) -> None:
    """Rolling code back below a recorded migration refuses instead of guessing."""
    open_store(tmp_path).close()
    db = sqlite3.connect(tmp_path / "state" / "controller.db")
    db.execute(
        "INSERT INTO schema_migrations (version, name, digest, applied_at) VALUES (99, 'future', 'd', 0)"
    )
    db.commit()
    db.close()
    with pytest.raises(MigrationRefused, match="newer"):
        open_store(tmp_path)


def test_unreviewed_migration_is_refused_before_it_runs(tmp_path, monkeypatch) -> None:
    """Changing migration SQL without updating the reviewed digest applies nothing."""
    altered = migrations.Migration(
        version=1, name=MIGRATIONS[0].name, statements=("CREATE TABLE rogue (x INTEGER)",)
    )
    monkeypatch.setattr(migrations, "MIGRATIONS", (altered,))
    with pytest.raises(MigrationRefused, match="reviewed"):
        open_store(tmp_path, FakeClock())
    db = sqlite3.connect(tmp_path / "state" / "controller.db")
    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    db.close()
    assert "rogue" not in names and "tasks" not in names


def test_refused_open_closes_its_connection(tmp_path) -> None:
    """A store that refuses to open leaves no SQLite connection behind."""
    import gc
    import warnings

    open_store(tmp_path).close()
    db = sqlite3.connect(tmp_path / "state" / "controller.db")
    db.execute("UPDATE schema_migrations SET digest = 'x' WHERE version = 1")
    db.commit()
    db.close()
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        with pytest.raises(MigrationRefused):
            open_store(tmp_path)
        gc.collect()
    assert [w for w in caught if issubclass(w.category, ResourceWarning)] == []
