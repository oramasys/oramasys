"""Private filesystem preparation for SQLite ledger stores."""
from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Any

__all__ = [
    "prepare_private_store",
    "safe_replace",
    "replace_file",
]

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_windows() -> bool:
    """Return True if running on Windows."""
    return os.name == "nt"


def _permission_error(path: Path, requirement: str) -> PermissionError:
    """Build the uniform error for a path that violates the private-store contract."""
    return PermissionError(f"{path} {requirement}")


def _is_link_or_reparse_point(path: Path, status: os.stat_result | None = None) -> bool:
    """Check whether path or stat result is a symlink, junction, or reparse point."""
    if status is not None:
        if stat.S_ISLNK(status.st_mode):
            return True
        attrs = getattr(status, "st_file_attributes", 0)
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    try:
        if os.path.islink(path):
            return True
        isjunction = getattr(os.path, "isjunction", None)
        if isjunction and isjunction(path):
            return True
    except (OSError, ValueError):
        pass
    if status is None:
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                return True
            attrs = getattr(st, "st_file_attributes", 0)
            if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
                return True
        except (OSError, ValueError):
            pass
    return False


def _check_windows_ownership(path: Path) -> bool:
    """Verify that path is owned by the current process token user on Windows."""
    if not _is_windows():
        return True
    try:
        import ctypes
        from ctypes import wintypes

        if not hasattr(ctypes, "windll"):
            return False

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        TOKEN_QUERY = 0x0008

        # 64-bit Windows handle & pointer signatures
        try:
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.GetCurrentProcess.argtypes = []

            advapi32.OpenProcessToken.restype = wintypes.BOOL
            advapi32.OpenProcessToken.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ]

            advapi32.GetTokenInformation.restype = wintypes.BOOL
            advapi32.GetTokenInformation.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]

            advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
            advapi32.GetNamedSecurityInfoW.argtypes = [
                wintypes.LPCWSTR,
                ctypes.c_int,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
            ]

            advapi32.EqualSid.restype = wintypes.BOOL
            advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        except (AttributeError, TypeError):
            pass

        token_handle = wintypes.HANDLE()
        current_process = kernel32.GetCurrentProcess()
        if not advapi32.OpenProcessToken(current_process, TOKEN_QUERY, ctypes.byref(token_handle)):
            return False

        try:
            token_info_length = wintypes.DWORD()
            advapi32.GetTokenInformation(token_handle, 1, None, 0, ctypes.byref(token_info_length))
            if token_info_length.value == 0:
                return False
            buffer = ctypes.create_string_buffer(token_info_length.value)
            if not advapi32.GetTokenInformation(
                token_handle, 1, buffer, token_info_length.value, ctypes.byref(token_info_length)
            ):
                return False
            user_sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents

            OWNER_SECURITY_INFORMATION = 0x00000001
            p_file_owner_sid = ctypes.c_void_p()
            p_sd = ctypes.c_void_p()
            ret = advapi32.GetNamedSecurityInfoW(
                str(path),
                1,  # SE_FILE_OBJECT
                OWNER_SECURITY_INFORMATION,
                ctypes.byref(p_file_owner_sid),
                None,
                None,
                None,
                ctypes.byref(p_sd),
            )
            if ret != 0:
                return False

            try:
                is_equal = advapi32.EqualSid(user_sid, p_file_owner_sid)
                return bool(is_equal)
            finally:
                if p_sd.value:
                    kernel32.LocalFree(p_sd)
        finally:
            kernel32.CloseHandle(token_handle)
    except Exception:
        return False


def _validate_directory(path: Path, status: os.stat_result) -> None:
    """Require current-user ownership and POSIX 0700 or a private Windows DACL."""
    if _is_link_or_reparse_point(path, status):
        raise _permission_error(path, "must not be a symlink")
    if not (stat.S_ISDIR(status.st_mode) and os.path.isdir(path)):
        raise _permission_error(path, "must be a directory")
    if _is_windows():
        if not _check_windows_ownership(path):
            raise _permission_error(path, "must be owned by the current user")
        if not _check_windows_acl(path):
            raise _permission_error(path, "must have a private Windows DACL")
    else:
        if status.st_uid != os.geteuid():
            raise _permission_error(path, "must be owned by the current user")
        if stat.S_IMODE(status.st_mode) != _DIRECTORY_MODE:
            raise _permission_error(path, "must have mode 0700")


def _validate_file(path: Path, status: os.stat_result) -> None:
    """Require a current-user regular file with POSIX 0600 or a private Windows DACL."""
    if _is_link_or_reparse_point(path, status):
        raise _permission_error(path, "must not be a symlink")
    if not stat.S_ISREG(status.st_mode) or os.path.isdir(path):
        raise _permission_error(path, "must be a regular file")
    if _is_windows():
        if not _check_windows_ownership(path):
            raise _permission_error(path, "must be owned by the current user")
        if not _check_windows_acl(path):
            raise _permission_error(path, "must have a private Windows DACL")
    else:
        if status.st_uid != os.geteuid():
            raise _permission_error(path, "must be owned by the current user")
        if stat.S_IMODE(status.st_mode) != _FILE_MODE:
            raise _permission_error(path, "must have mode 0600")


def _lstat_at(parent_fd: int, name: str) -> os.stat_result | None:
    """Stat ``name`` under ``parent_fd`` without following symlinks; None if absent."""
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def safe_replace(
    src: Path | str,
    dst: Path | str,
    *,
    max_retries: int = 5,
    initial_delay: float = 0.002,
    backoff_factor: float = 2.0,
    _sleep: Any = time.sleep,
) -> None:
    """Atomically replace ``dst`` with ``src`` with bounded exponential backoff on Windows.

    Under Windows / NTFS, os.replace can fail transiently with PermissionError
    (WinError 5 / 32) due to file sharing contention, antivirus scanning, or indexing.
    Only explicit WinError 5/32 contention candidates are retried. Permanent
    errors, including POSIX EACCES, propagate immediately. The default five
    deterministic delays total 62 ms; no jitter is applied. WinError 5 can also
    be a permanent ACL denial, so it is retried only within this bounded budget.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    delay = initial_delay
    if max_retries < 0:
        raise ValueError("max_retries must be nonnegative")

    for attempt in range(max_retries + 1):
        try:
            os.replace(src_path, dst_path)
            return
        except OSError as err:
            is_contention = getattr(err, "winerror", None) in (5, 32)
            if is_contention and attempt < max_retries:
                _sleep(delay)
                delay *= backoff_factor
                continue
            raise

replace_file = safe_replace


def _check_windows_acl(path: Path) -> bool:
    """Refuse unavailable or unsafe native Windows security descriptors."""
    from .windows_private import WindowsSecurity

    try:
        return WindowsSecurity().private_acl(path)
    except (OSError, ValueError, AttributeError):
        return False


def _create_windows_directory(path: Path) -> None:
    """Create a directory with an explicit owner and protected inheritable DACL."""
    from .windows_private import WindowsSecurity

    WindowsSecurity().create_directory(path)


def _create_windows_file(path: Path) -> None:
    """Create a database atomically with explicit owner and protected DACL."""
    from .windows_private import WindowsSecurity

    WindowsSecurity().create_file(path)


def _prepare_private_store_posix(store: Path) -> Path:
    """Validate and precreate a private SQLite store on POSIX systems."""
    parent = store.parent
    created_parent = False

    try:
        parent_status = os.lstat(parent)
    except FileNotFoundError:
        try:
            os.mkdir(parent, _DIRECTORY_MODE)
            created_parent = True
        except FileExistsError:
            # Another process won the race: validate its directory below and
            # never change its permissions.
            pass
        parent_status = os.lstat(parent)

    if stat.S_ISLNK(parent_status.st_mode):
        raise _permission_error(parent, "must not be a symlink")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW

    try:
        parent_fd = os.open(parent, directory_flags)
    except OSError as error:
        if stat.S_ISLNK(os.lstat(parent).st_mode):
            raise _permission_error(parent, "must not be a symlink") from error
        raise

    try:
        opened_parent_status = os.fstat(parent_fd)
        if created_parent:
            if (opened_parent_status.st_dev, opened_parent_status.st_ino) != (
                parent_status.st_dev,
                parent_status.st_ino,
            ):
                raise _permission_error(parent, "changed during preparation")
            os.fchmod(parent_fd, _DIRECTORY_MODE)
            opened_parent_status = os.fstat(parent_fd)
        _validate_directory(parent, opened_parent_status)

        target_status = _lstat_at(parent_fd, store.name)
        if target_status is not None:
            _validate_file(store, target_status)

        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{store}{suffix}")
            sidecar_status = _lstat_at(parent_fd, f"{store.name}{suffix}")
            if sidecar_status is not None:
                _validate_file(sidecar, sidecar_status)

        if target_status is None:
            file_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                file_flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            try:
                store_fd = os.open(store.name, file_flags, _FILE_MODE, dir_fd=parent_fd)
            except FileExistsError:
                raced_status = _lstat_at(parent_fd, store.name)
                if raced_status is None:
                    raise
                _validate_file(store, raced_status)
            else:
                try:
                    os.fchmod(store_fd, _FILE_MODE)
                    _validate_file(store, os.fstat(store_fd))
                finally:
                    os.close(store_fd)
    finally:
        os.close(parent_fd)

    return store


def _prepare_private_store_windows(store: Path) -> Path:
    """Create private Windows objects and refuse unsafe existing ACLs.

    Ancestors must not be writable/renameable by unrelated users. This flow
    still resolves pathnames separately; it is not a handle-relative traversal
    guarantee against concurrent ancestor/junction replacement. Deployment
    qualification must establish that precondition before promotion.
    """
    parent = store.parent

    try:
        parent_status = os.lstat(parent)
    except FileNotFoundError:
        try:
            _create_windows_directory(parent)
        except FileExistsError:
            pass
        parent_status = os.lstat(parent)

    _validate_directory(parent, parent_status)

    try:
        target_status = os.lstat(store)
    except FileNotFoundError:
        target_status = None

    if target_status is not None:
        _validate_file(store, target_status)

    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{store}{suffix}")
        try:
            sidecar_status = os.lstat(sidecar)
        except FileNotFoundError:
            sidecar_status = None
        if sidecar_status is not None:
            _validate_file(sidecar, sidecar_status)

    if target_status is None:
        try:
            _create_windows_file(store)
        except FileExistsError:
            raced_status = os.lstat(store)
            _validate_file(store, raced_status)
        else:
            _validate_file(store, os.lstat(store))

    return store


def prepare_private_store(path: Path | str) -> Path:
    """Validate and precreate a private SQLite store without repairing existing paths."""
    store = Path(path)
    if _is_windows():
        return _prepare_private_store_windows(store)
    return _prepare_private_store_posix(store)
