from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

from orama.graph.private_store import (
    prepare_private_store,
    replace_file,
    safe_replace,
)


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


def test_windows_creates_private_parent_and_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    store = tmp_path / "win_private" / "ledger.sqlite3"
    assert prepare_private_store(store) == store
    assert store.parent.is_dir()
    assert store.is_file()


def test_windows_accepts_existing_database_and_parent_regardless_of_posix_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent = tmp_path / "win_shared"
    parent.mkdir(mode=0o777)
    parent.chmod(0o755)

    store = parent / "ledger.sqlite3"
    store.touch(mode=0o666)
    store.chmod(0o644)

    wal = Path(f"{store}-wal")
    shm = Path(f"{store}-shm")
    wal.touch(mode=0o666)
    wal.chmod(0o644)
    shm.touch(mode=0o666)
    shm.chmod(0o666)

    assert prepare_private_store(store) == store
    assert store.is_file()


def _symlink_or_skip(link: Path, target: Path, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("Symlink creation requires elevation or Developer Mode on Windows")
        raise


def test_windows_refuses_symlink_parent_and_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    actual = tmp_path / "actual"
    actual.mkdir()
    link_parent = tmp_path / "link_parent"
    _symlink_or_skip(link_parent, actual, target_is_directory=True)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(link_parent / "ledger.sqlite3")

    target_db = actual / "target.sqlite3"
    target_db.touch()
    link_db = actual / "ledger.sqlite3"
    _symlink_or_skip(link_db, target_db)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(link_db)


def test_windows_refuses_junction_parent_and_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent = tmp_path / "junction_parent"
    parent.mkdir()
    store = parent / "ledger.sqlite3"
    store.touch()

    monkeypatch.setattr(os.path, "isjunction", lambda p: Path(p) == parent)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)

    monkeypatch.setattr(os.path, "isjunction", lambda p: Path(p) == store)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)


def test_windows_refuses_reparse_point_attribute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent = tmp_path / "reparse_dir"
    parent.mkdir()
    store = parent / "ledger.sqlite3"
    store.touch()

    real_lstat = os.lstat

    class FakeStatResult:
        def __init__(self, orig: os.stat_result, attrs: int) -> None:
            self._orig = orig
            self.st_file_attributes = attrs
            self.st_mode = orig.st_mode
            self.st_uid = orig.st_uid
            self.st_dev = orig.st_dev
            self.st_ino = orig.st_ino

        def __getattr__(self, name: str) -> Any:
            return getattr(self._orig, name)

    def fake_lstat_parent(p: Any, **kwargs: Any) -> Any:
        st = real_lstat(p, **kwargs)
        if Path(p) == parent:
            return FakeStatResult(st, 0x400)
        return st

    monkeypatch.setattr(os, "lstat", fake_lstat_parent)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)

    def fake_lstat_store(p: Any, **kwargs: Any) -> Any:
        st = real_lstat(p, **kwargs)
        if Path(p) == store:
            return FakeStatResult(st, 0x400)
        return st

    monkeypatch.setattr(os, "lstat", fake_lstat_store)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)


def test_windows_refuses_symlink_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    store = tmp_path / "ledger.sqlite3"
    store.touch()
    target = tmp_path / "sidecar-target"
    target.touch()
    wal = Path(f"{store}-wal")
    _symlink_or_skip(wal, target)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)


def test_windows_refuses_non_regular_database_and_non_directory_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent_file = tmp_path / "not_a_dir"
    parent_file.touch()
    with pytest.raises(PermissionError, match="directory"):
        prepare_private_store(parent_file / "ledger.sqlite3")

    dir_store = tmp_path / "dir_store.sqlite3"
    dir_store.mkdir()
    with pytest.raises(PermissionError, match="regular file"):
        prepare_private_store(dir_store)


def test_windows_refuses_unowned_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    monkeypatch.setattr(ps_mod, "_check_windows_ownership", lambda p: False)

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(tmp_path / "unowned" / "ledger.sqlite3")


def test_windows_refuses_unowned_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent = tmp_path / "valid_parent"
    parent.mkdir()
    store = parent / "ledger.sqlite3"
    store.touch()

    monkeypatch.setattr(ps_mod, "_check_windows_ownership", lambda p: Path(p) != store)

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(store)


def test_windows_ownership_win32_api_mock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ctypes
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)

    class FakeAdvapi32:
        def __init__(self, equal_sid: int) -> None:
            self._equal = equal_sid

        def OpenProcessToken(self, proc: Any, query: int, handle_ref: Any) -> int:
            return 1

        def GetTokenInformation(
            self, handle: Any, info_class: int, buf: Any, length: int, return_len: Any
        ) -> int:
            return_len._obj.value = 64
            return 1

        def GetNamedSecurityInfoW(
            self,
            path: str,
            obj_type: int,
            sec_info: int,
            owner: Any,
            group: Any,
            dacl: Any,
            sacl: Any,
            sd: Any,
        ) -> int:
            return 0

        def EqualSid(self, sid1: Any, sid2: Any) -> int:
            return self._equal

    class FakeKernel32:
        def GetCurrentProcess(self) -> int:
            return 42

        def CloseHandle(self, handle: Any) -> int:
            return 1

        def LocalFree(self, mem: Any) -> None:
            pass

    class FakeWindll:
        advapi32 = FakeAdvapi32(equal_sid=1)
        kernel32 = FakeKernel32()

    monkeypatch.setattr(ctypes, "windll", FakeWindll(), raising=False)
    p = tmp_path / "owned_check.txt"
    p.touch()

    assert ps_mod._check_windows_ownership(p) is True

    FakeWindll.advapi32 = FakeAdvapi32(equal_sid=0)
    assert ps_mod._check_windows_ownership(p) is False


def test_safe_replace_succeeds_on_first_try(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    safe_replace(src, dst)
    assert dst.read_text(encoding="utf-8") == "updated"
    assert not src.exists()


def test_safe_replace_retries_on_oserror_contention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    src = tmp_path / "src_os.txt"
    dst = tmp_path / "dst_os.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    real_replace = os.replace
    attempts = 0
    slept: list[float] = []

    def mock_replace(s: Any, d: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            err = OSError("Sharing violation")
            err.winerror = 32
            raise err
        real_replace(s, d)

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(os, "replace", mock_replace)

    safe_replace(
        src,
        dst,
        max_retries=4,
        initial_delay=0.001,
        backoff_factor=2.0,
        _sleep=slept.append,
    )

    assert attempts == 3
    assert len(slept) == 2
    assert dst.read_text(encoding="utf-8") == "updated"


def test_safe_replace_retries_on_windows_contention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    real_replace = os.replace
    attempts = 0
    slept: list[float] = []

    def mock_replace(s: Any, d: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 4:
            err = PermissionError("The process cannot access the file because it is being used by another process.")
            err.winerror = 32
            raise err
        real_replace(s, d)

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(os, "replace", mock_replace)

    safe_replace(
        src,
        dst,
        max_retries=5,
        initial_delay=0.001,
        backoff_factor=2.0,
        _sleep=slept.append,
    )

    assert attempts == 4
    assert len(slept) == 3
    assert slept[0] == 0.001
    assert slept[1] == 0.002
    assert slept[2] == 0.004
    assert dst.read_text(encoding="utf-8") == "updated"


def test_safe_replace_fails_after_exceeding_max_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orama.graph.private_store as ps_mod

    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    attempts = 0
    slept: list[float] = []

    def mock_replace(s: Any, d: Any) -> None:
        nonlocal attempts
        attempts += 1
        err = PermissionError("Access denied.")
        err.winerror = 5
        raise err

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(os, "replace", mock_replace)

    with pytest.raises(PermissionError, match="Access denied"):
        safe_replace(
            src,
            dst,
            max_retries=5,
            initial_delay=0.002,
            backoff_factor=2.0,
            _sleep=slept.append,
        )

    assert attempts == 6
    assert len(slept) == 5
    assert sum(slept) == pytest.approx(0.062, abs=1e-4)


def test_grant_lib_cross_platform_locking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[2]
    import sys
    sys.path.insert(0, str(root / "scripts" / "reporting"))
    import grant_lib

    lock_file = tmp_path / "test.lock"
    lock_file.touch()

    with open(lock_file, "r+", encoding="utf-8") as handle:
        grant_lib.lock_file_exclusive(handle)
        grant_lib.unlock_file(handle)

    locked_calls: list[tuple[int, int, int]] = []

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        def locking(self, fileno: int, mode: int, nbytes: int) -> None:
            locked_calls.append((fileno, mode, nbytes))

    fake_msvcrt = FakeMsvcrt()
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(grant_lib, "os", os)
    monkeypatch.setattr(grant_lib, "msvcrt", fake_msvcrt)

    with open(lock_file, "r+", encoding="utf-8") as handle:
        grant_lib.lock_file_exclusive(handle)
        grant_lib.unlock_file(handle)

    assert len(locked_calls) == 2
    assert locked_calls[0][1] == FakeMsvcrt.LK_LOCK
    assert locked_calls[0][2] == 1
    assert locked_calls[1][1] == FakeMsvcrt.LK_UNLCK
    assert locked_calls[1][2] == 1
