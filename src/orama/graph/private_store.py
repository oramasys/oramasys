"""Private filesystem preparation for SQLite ledger stores."""
from __future__ import annotations

import os
import stat
from pathlib import Path

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


def _permission_error(path: Path, requirement: str) -> PermissionError:
    return PermissionError(f"{path} {requirement}")


def _validate_directory(path: Path, status: os.stat_result) -> None:
    if stat.S_ISLNK(status.st_mode):
        raise _permission_error(path, "must not be a symlink")
    if not stat.S_ISDIR(status.st_mode):
        raise _permission_error(path, "must be a directory")
    if status.st_uid != os.geteuid():
        raise _permission_error(path, "must be owned by the current user")
    if stat.S_IMODE(status.st_mode) != _DIRECTORY_MODE:
        raise _permission_error(path, "must have mode 0700")


def _validate_file(path: Path, status: os.stat_result) -> None:
    if stat.S_ISLNK(status.st_mode):
        raise _permission_error(path, "must not be a symlink")
    if not stat.S_ISREG(status.st_mode):
        raise _permission_error(path, "must be a regular file")
    if status.st_uid != os.geteuid():
        raise _permission_error(path, "must be owned by the current user")
    if stat.S_IMODE(status.st_mode) != _FILE_MODE:
        raise _permission_error(path, "must have mode 0600")


def _lstat_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def prepare_private_store(path: Path | str) -> Path:
    """Validate and precreate a private SQLite store without repairing existing paths."""
    store = Path(path)
    parent = store.parent
    created_parent = False

    try:
        parent_status = os.lstat(parent)
    except FileNotFoundError:
        os.mkdir(parent, _DIRECTORY_MODE)
        created_parent = True
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
