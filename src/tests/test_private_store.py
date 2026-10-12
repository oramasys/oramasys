from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

from orama.graph.private_store import prepare_private_store


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_creates_private_parent_and_database_without_changing_ancestor(tmp_path: Path) -> None:
    ancestor_mode = _mode(tmp_path)
    store = tmp_path / "private" / "ledger.sqlite3"

    assert prepare_private_store(store) == store

    assert _mode(tmp_path) == ancestor_mode
    assert _mode(store.parent) == 0o700
    assert _mode(store) == 0o600
    assert store.is_file()


@pytest.mark.parametrize("mode", [0o400, 0o640, 0o666])
def test_refuses_existing_database_with_non_private_mode_without_chmod(
    tmp_path: Path, mode: int
) -> None:
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    store.chmod(mode)

    with pytest.raises(PermissionError, match="0600"):
        prepare_private_store(store)

    assert _mode(store) == mode


def test_refuses_existing_parent_with_non_private_mode_without_chmod(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o700)
    parent.chmod(0o755)

    with pytest.raises(PermissionError, match="0700"):
        prepare_private_store(parent / "ledger.sqlite3")

    assert _mode(parent) == 0o755


def test_accepts_existing_private_database(tmp_path: Path) -> None:
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)

    assert prepare_private_store(str(store)) == store
    assert _mode(store) == 0o600


def test_accepts_existing_private_wal_and_shm(tmp_path: Path) -> None:
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    wal = Path(f"{store}-wal")
    shm = Path(f"{store}-shm")
    wal.touch(mode=0o600)
    shm.touch(mode=0o600)

    assert prepare_private_store(store) == store
    assert _mode(wal) == 0o600
    assert _mode(shm) == 0o600


def test_refuses_parent_not_owned_by_current_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid + 1)

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(tmp_path / "ledger.sqlite3")


def test_refuses_database_not_owned_by_current_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    real_uid = store.stat().st_uid
    calls = iter((tmp_path.stat().st_uid, real_uid + 1))
    monkeypatch.setattr(os, "geteuid", lambda: next(calls))

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(store)


def test_refuses_symlink_database_path(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    link = tmp_path / "ledger.sqlite3"
    link.symlink_to(target)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(link)


def test_refuses_symlink_parent(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    parent = tmp_path / "linked"
    parent.symlink_to(actual, target_is_directory=True)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(parent / "ledger.sqlite3")

    assert not (actual / "ledger.sqlite3").exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_refuses_non_private_sidecar_without_chmod(tmp_path: Path, suffix: str) -> None:
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    sidecar = Path(f"{store}{suffix}")
    sidecar.touch(mode=0o600)
    sidecar.chmod(0o644)

    with pytest.raises(PermissionError, match="0600"):
        prepare_private_store(store)

    assert _mode(sidecar) == 0o644


def test_refuses_non_regular_database_and_sidecar(tmp_path: Path) -> None:
    database_directory = tmp_path / "ledger.sqlite3"
    database_directory.mkdir(mode=0o700)
    with pytest.raises(PermissionError, match="regular file"):
        prepare_private_store(database_directory)

    database_directory.rmdir()
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    sidecar_directory = Path(f"{store}-wal")
    sidecar_directory.mkdir(mode=0o700)
    with pytest.raises(PermissionError, match="regular file"):
        prepare_private_store(store)


def test_refuses_symlink_sidecar(tmp_path: Path) -> None:
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    target = tmp_path / "sidecar-target"
    target.touch(mode=0o600)
    Path(f"{store}-shm").symlink_to(target)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)


def test_does_not_create_missing_broad_ancestors(tmp_path: Path) -> None:
    store = tmp_path / "missing" / "private" / "ledger.sqlite3"

    with pytest.raises(FileNotFoundError):
        prepare_private_store(store)

    assert not (tmp_path / "missing").exists()


def test_created_database_is_not_affected_by_process_umask(tmp_path: Path) -> None:
    original_umask = os.umask(0o777)
    try:
        store = tmp_path / "ledger.sqlite3"
        prepare_private_store(store)
    finally:
        os.umask(original_umask)

    assert _mode(store) == 0o600


def test_first_open_race_validates_the_winning_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent creator is validated, not turned into a FileExistsError."""
    real_mkdir = os.mkdir

    def racing_mkdir(path: Any, mode: int = 0o777, **kwargs: Any) -> None:
        real_mkdir(path, 0o700)  # the other process wins first
        raise FileExistsError(path)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    store = prepare_private_store(tmp_path / "fresh" / "ledger.sqlite3")

    assert store.parent.is_dir()
    assert oct(store.parent.stat().st_mode & 0o777) == "0o700"
