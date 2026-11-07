"""Private-store validation, replacement and advisory-lock regressions."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any
import errno

import pytest

from orama.graph.private_store import (
    prepare_private_store,
    replace_file,
    safe_replace,
)

_posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX mode bits, UID, and umask not enforced on Windows NTFS DACLs",
)


@pytest.fixture(autouse=True)
def simulated_windows_security(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub native APIs only for existing Linux-hosted Windows flow simulations."""
    if os.name == "nt" or not request.node.name.startswith("test_windows_"):
        return
    if "ownership" in request.node.name or "native" in request.node.name:
        return
    import orama.graph.private_store as module

    monkeypatch.setattr(module, "_check_windows_ownership", lambda path: True)
    monkeypatch.setattr(module, "_check_windows_acl", lambda path: True)
    monkeypatch.setattr(module, "_create_windows_directory", lambda path: os.mkdir(path, 0o700))

    def create_file(path: Path) -> None:
        """Simulate exclusive creation, not the native security guarantee."""
        with path.open("xb"):
            pass

    monkeypatch.setattr(module, "_create_windows_file", create_file)


def _mode(path: Path) -> int:
    """Read POSIX permission bits without following symlinks."""
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.mark.parametrize("aces,expected", [
    ([(0, 0x1F01FF, "user"), (0, 0x1F01FF, "S-1-5-18")], True),
    ([(0, 0x1F01FF, "S-1-5-32-544")], True),
    ([(0, 1, "S-1-1-0")], False),
    ([(0, 0x10000000, "other-user")], False),
    ([(1, 0x1F01FF, "S-1-1-0")], True),
    ([(5, 1, "user")], False),
])
def test_acl_policy_rejects_foreign_or_unknown_grants(
    aces: list[tuple[int, int, str]], expected: bool
) -> None:
    """Foreign read/write grants and unknown ACE forms must refuse validation."""
    from orama.graph.windows_private import acl_is_private

    assert acl_is_private(aces, "user") is expected


@_posix_only
def test_creates_private_parent_and_database_without_changing_ancestor(tmp_path: Path) -> None:
    """Verify creates private parent and database without changing ancestor."""
    ancestor_mode = _mode(tmp_path)
    store = tmp_path / "private" / "ledger.sqlite3"

    assert prepare_private_store(store) == store

    assert _mode(tmp_path) == ancestor_mode
    assert _mode(store.parent) == 0o700
    assert _mode(store) == 0o600
    assert store.is_file()


@_posix_only
@pytest.mark.parametrize("mode", [0o400, 0o640, 0o666])
def test_refuses_existing_database_with_non_private_mode_without_chmod(
    tmp_path: Path, mode: int
) -> None:
    """Verify refuses existing database with non private mode without chmod."""
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    store.chmod(mode)

    with pytest.raises(PermissionError, match="0600"):
        prepare_private_store(store)

    assert _mode(store) == mode


@_posix_only
def test_refuses_existing_parent_with_non_private_mode_without_chmod(tmp_path: Path) -> None:
    """Verify refuses existing parent with non private mode without chmod."""
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o700)
    parent.chmod(0o755)

    with pytest.raises(PermissionError, match="0700"):
        prepare_private_store(parent / "ledger.sqlite3")

    assert _mode(parent) == 0o755


@_posix_only
def test_accepts_existing_private_database(tmp_path: Path) -> None:
    """Verify accepts existing private database."""
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)

    assert prepare_private_store(str(store)) == store
    assert _mode(store) == 0o600


@_posix_only
def test_accepts_existing_private_wal_and_shm(tmp_path: Path) -> None:
    """Verify accepts existing private wal and shm."""
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    wal = Path(f"{store}-wal")
    shm = Path(f"{store}-shm")
    wal.touch(mode=0o600)
    shm.touch(mode=0o600)

    assert prepare_private_store(store) == store
    assert _mode(wal) == 0o600
    assert _mode(shm) == 0o600


@_posix_only
def test_refuses_parent_not_owned_by_current_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify refuses parent not owned by current user."""
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid + 1)

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(tmp_path / "ledger.sqlite3")


@_posix_only
def test_refuses_database_not_owned_by_current_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify refuses database not owned by current user."""
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    real_uid = store.stat().st_uid
    calls = iter((tmp_path.stat().st_uid, real_uid + 1))
    monkeypatch.setattr(os, "geteuid", lambda: next(calls))

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(store)


@_posix_only
def test_refuses_symlink_database_path(tmp_path: Path) -> None:
    """Verify refuses symlink database path."""
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    link = tmp_path / "ledger.sqlite3"
    link.symlink_to(target)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(link)


@_posix_only
def test_refuses_symlink_parent(tmp_path: Path) -> None:
    """Verify refuses symlink parent."""
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    parent = tmp_path / "linked"
    parent.symlink_to(actual, target_is_directory=True)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(parent / "ledger.sqlite3")

    assert not (actual / "ledger.sqlite3").exists()


@_posix_only
@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_refuses_non_private_sidecar_without_chmod(tmp_path: Path, suffix: str) -> None:
    """Verify refuses non private sidecar without chmod."""
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    sidecar = Path(f"{store}{suffix}")
    sidecar.touch(mode=0o600)
    sidecar.chmod(0o644)

    with pytest.raises(PermissionError, match="0600"):
        prepare_private_store(store)

    assert _mode(sidecar) == 0o644


def test_refuses_non_regular_database_and_sidecar(tmp_path: Path) -> None:
    """Verify refuses non regular database and sidecar."""
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


@_posix_only
def test_refuses_symlink_sidecar(tmp_path: Path) -> None:
    """Verify refuses symlink sidecar."""
    store = tmp_path / "ledger.sqlite3"
    store.touch(mode=0o600)
    target = tmp_path / "sidecar-target"
    target.touch(mode=0o600)
    Path(f"{store}-shm").symlink_to(target)

    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)


def test_does_not_create_missing_broad_ancestors(tmp_path: Path) -> None:
    """Verify does not create missing broad ancestors."""
    store = tmp_path / "missing" / "private" / "ledger.sqlite3"

    with pytest.raises(FileNotFoundError):
        prepare_private_store(store)

    assert not (tmp_path / "missing").exists()


@_posix_only
def test_created_database_is_not_affected_by_process_umask(tmp_path: Path) -> None:
    """Verify created database is not affected by process umask."""
    original_umask = os.umask(0o777)
    try:
        store = tmp_path / "ledger.sqlite3"
        prepare_private_store(store)
    finally:
        os.umask(original_umask)

    assert _mode(store) == 0o600


@_posix_only
def test_first_open_race_validates_the_winning_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent creator is validated, not turned into a FileExistsError."""
    real_mkdir = os.mkdir

    def racing_mkdir(path: Any, mode: int = 0o777, **kwargs: Any) -> None:
        """Perform racing mkdir."""
        real_mkdir(path, 0o700)  # the other process wins first
        raise FileExistsError(path)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    store = prepare_private_store(tmp_path / "fresh" / "ledger.sqlite3")

    assert store.parent.is_dir()
    assert oct(store.parent.stat().st_mode & 0o777) == "0o700"


def test_windows_creates_private_parent_and_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify windows creates private parent and database."""
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
    """Verify windows accepts existing database and parent regardless of posix mode."""
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
    """Perform symlink or skip."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("Symlink creation requires elevation or Developer Mode on Windows")
        raise


def test_windows_refuses_symlink_parent_and_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify windows refuses symlink parent and database."""
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
    """Verify windows refuses junction parent and database."""
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent = tmp_path / "junction_parent"
    parent.mkdir()
    store = parent / "ledger.sqlite3"
    store.touch()

    monkeypatch.setattr(os.path, "isjunction", lambda p: Path(p) == parent, raising=False)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)

    monkeypatch.setattr(os.path, "isjunction", lambda p: Path(p) == store, raising=False)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)


def test_windows_refuses_reparse_point_attribute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify windows refuses reparse point attribute."""
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    parent = tmp_path / "reparse_dir"
    parent.mkdir()
    store = parent / "ledger.sqlite3"
    store.touch()

    real_lstat = os.lstat

    class FakeStatResult:
        """Perform FakeStatResult."""
        def __init__(self, orig: os.stat_result, attrs: int) -> None:
            """Retain the configured fields for this narrow test double."""
            self._orig = orig
            self.st_file_attributes = attrs
            self.st_mode = orig.st_mode
            self.st_uid = orig.st_uid
            self.st_dev = orig.st_dev
            self.st_ino = orig.st_ino

        def __getattr__(self, name: str) -> Any:
            """Forward unmodified stat attributes to the real result."""
            return getattr(self._orig, name)

    def fake_lstat_parent(p: Any, **kwargs: Any) -> Any:
        """Perform fake lstat parent."""
        st = real_lstat(p, **kwargs)
        if Path(p) == parent:
            return FakeStatResult(st, 0x400)
        return st

    monkeypatch.setattr(os, "lstat", fake_lstat_parent)
    with pytest.raises(PermissionError, match="symlink"):
        prepare_private_store(store)

    def fake_lstat_store(p: Any, **kwargs: Any) -> Any:
        """Perform fake lstat store."""
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
    """Verify windows refuses symlink sidecars."""
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
    """Verify windows refuses non regular database and non directory parent."""
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
    """Verify windows refuses unowned paths."""
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)
    monkeypatch.delattr(os, "geteuid", raising=False)

    monkeypatch.setattr(ps_mod, "_check_windows_ownership", lambda p: False)

    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(tmp_path / "unowned" / "ledger.sqlite3")


def test_windows_refuses_unowned_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify windows refuses unowned database."""
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
    """Verify windows ownership win32 api mock."""
    import ctypes
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: True)

    class FakeAdvapi32:
        """Perform FakeAdvapi32."""
        def __init__(self, equal_sid: int) -> None:
            """Retain the configured fields for this narrow test double."""
            self._equal = equal_sid

        def OpenProcessToken(self, proc: Any, query: int, handle_ref: Any) -> int:
            """Perform OpenProcessToken."""
            return 1

        def GetTokenInformation(
            self, handle: Any, info_class: int, buf: Any, length: int, return_len: Any
        ) -> int:
            """Expose a nonzero full-width SID pointer in the token buffer."""
            return_len._obj.value = 64
            if buf is not None:
                ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x1234567887654321
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
            """Perform GetNamedSecurityInfoW."""
            return 0

        def EqualSid(self, sid1: Any, sid2: Any) -> int:
            """Require a full-width SID pointer before returning the configured match."""
            assert isinstance(sid1, ctypes.c_void_p)
            assert sid1.value == 0x1234567887654321
            return self._equal

    class FakeKernel32:
        """Perform FakeKernel32."""
        def GetCurrentProcess(self) -> int:
            """Perform GetCurrentProcess."""
            return 42

        def CloseHandle(self, handle: Any) -> int:
            """Perform CloseHandle."""
            return 1

        def LocalFree(self, mem: Any) -> None:
            """Perform LocalFree."""
            pass

    class FakeWindll:
        """Perform FakeWindll."""
        advapi32 = FakeAdvapi32(equal_sid=1)
        kernel32 = FakeKernel32()

    monkeypatch.setattr(ctypes, "windll", FakeWindll(), raising=False)
    p = tmp_path / "owned_check.txt"
    p.touch()

    assert ps_mod._check_windows_ownership(p) is True

    FakeWindll.advapi32 = FakeAdvapi32(equal_sid=0)
    assert ps_mod._check_windows_ownership(p) is False


@pytest.mark.skipif(os.name == "nt", reason="exercises a missing native API, not Windows itself")
def test_windows_security_missing_native_api_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unavailable native security API must never become an ownership bypass."""
    import ctypes
    import orama.graph.private_store as module

    monkeypatch.setattr(module, "_is_windows", lambda: True)
    monkeypatch.delattr(ctypes, "windll", raising=False)
    assert not module._check_windows_ownership(tmp_path)
    assert not module._check_windows_acl(tmp_path)


def test_safe_replace_succeeds_on_first_try(tmp_path: Path) -> None:
    """Verify safe replace succeeds on first try."""
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    safe_replace(src, dst)
    assert dst.read_text(encoding="utf-8") == "updated"
    assert not src.exists()


@pytest.mark.parametrize("windows,error", [
    (True, FileNotFoundError(errno.ENOENT, "missing source")),
    (True, OSError(errno.EXDEV, "cross-device")),
    (False, PermissionError(errno.EACCES, "denied")),
])
def test_safe_replace_permanent_error_never_sleeps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool, error: OSError
) -> None:
    """Permanent failures retain their exception and never enter the retry budget."""
    import orama.graph.private_store as ps_mod

    monkeypatch.setattr(ps_mod, "_is_windows", lambda: windows)
    sleeps: list[float] = []

    def fail_replace(src: Any, dst: Any) -> None:
        """Represent a permanent operating-system replacement failure."""
        raise error

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError) as caught:
        safe_replace(tmp_path / "source", tmp_path / "destination", _sleep=sleeps.append)
    assert caught.value is error
    assert sleeps == []


@pytest.mark.parametrize("acquired", [False, True])
def test_nonce_lock_failure_always_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, acquired: bool
) -> None:
    """Acquisition failures never unlock; unlock failures still close the handle."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "grant_cleanup_test", Path(__file__).resolve().parents[2] / "scripts/reporting/grant_lib.py"
    )
    assert spec and spec.loader
    grant = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(grant)
    monkeypatch.setattr(grant, "NONCE_STATE_PATH", tmp_path / "nonce.json")
    handles: list[Any] = []
    unlocks: list[Any] = []

    def acquire(handle: Any) -> None:
        """Retain the actual file handle and optionally refuse acquisition."""
        handles.append(handle)
        if not acquired:
            raise OSError("acquisition refused")

    def unlock(handle: Any) -> None:
        """Exercise cleanup failure after a successfully acquired lock."""
        unlocks.append(handle)
        raise OSError("unlock refused")

    monkeypatch.setattr(grant, "lock_file_exclusive", acquire)
    monkeypatch.setattr(grant, "unlock_file", unlock)
    with pytest.raises(OSError, match="unlock refused" if acquired else "acquisition refused"):
        with grant._locked_nonce_state():
            pass
    assert handles[0].closed
    assert len(unlocks) == int(acquired)


def test_safe_replace_retries_on_oserror_contention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify safe replace retries on oserror contention."""
    import orama.graph.private_store as ps_mod

    src = tmp_path / "src_os.txt"
    dst = tmp_path / "dst_os.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    real_replace = os.replace
    attempts = 0
    slept: list[float] = []

    def mock_replace(s: Any, d: Any) -> None:
        """Inject bounded contention before applying the real replacement."""
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
    """Verify safe replace retries on windows contention."""
    import orama.graph.private_store as ps_mod

    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    real_replace = os.replace
    attempts = 0
    slept: list[float] = []

    def mock_replace(s: Any, d: Any) -> None:
        """Inject bounded contention before applying the real replacement."""
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
    """Verify safe replace fails after exceeding max retries."""
    import orama.graph.private_store as ps_mod

    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("updated", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    attempts = 0
    slept: list[float] = []

    def mock_replace(s: Any, d: Any) -> None:
        """Inject bounded contention before applying the real replacement."""
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
    """Verify grant lib cross platform locking."""
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
        """Perform FakeMsvcrt."""
        LK_LOCK = 1
        LK_UNLCK = 2

        def locking(self, fileno: int, mode: int, nbytes: int) -> None:
            """Perform locking."""
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
