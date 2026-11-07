"""Native Windows evidence is separate from simulated filesystem-flow tests."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from orama.graph.private_store import _check_windows_ownership, prepare_private_store
from orama.graph.windows_private import WindowsSecurity


@pytest.mark.skipif(os.name != "nt", reason="requires actual Win32 ctypes and NTFS ACLs")
def test_native_windows_created_store_is_current_user_owned(tmp_path: Path) -> None:
    """Real token/SID conversion recognizes newly created files, including elevated runs."""
    store = prepare_private_store(tmp_path / "private" / "ledger.sqlite3")
    assert _check_windows_ownership(store)
    security = WindowsSecurity()
    assert security.private_acl(store.parent)
    assert security.private_acl(store)
    assert prepare_private_store(store) == store


@pytest.mark.skipif(os.name != "nt", reason="requires actual Windows access rules")
@pytest.mark.parametrize("target", ["parent", "store", "wal", "shm"])
def test_native_windows_refuses_everyone_acl(tmp_path: Path, target: str) -> None:
    """A caller-owned object must refuse if Everyone receives read access."""
    store = prepare_private_store(tmp_path / "private" / "ledger.sqlite3")
    selected = {"parent": store.parent, "store": store,
                "wal": Path(f"{store}-wal"), "shm": Path(f"{store}-shm")}[target]
    if target in ("wal", "shm"):
        # Elevated runners may default to Administrators ownership. Establish
        # the valid owner first so this case specifically tests ACL refusal.
        WindowsSecurity().create_file(selected)
    assert prepare_private_store(store) == store
    subprocess.run(["icacls", str(selected), "/grant", "*S-1-1-0:(R)"],
                   check=True, capture_output=True)
    with pytest.raises(PermissionError, match="DACL"):
        prepare_private_store(store)


@pytest.mark.skipif(os.name != "nt", reason="requires native token default-owner semantics")
def test_native_windows_refuses_different_default_owner(tmp_path: Path) -> None:
    """Existing default-Administrators-owned sidecars are not silently repaired."""
    store = prepare_private_store(tmp_path / "private" / "ledger.sqlite3")
    sidecar = Path(f"{store}-wal")
    sidecar.touch()
    if _check_windows_ownership(sidecar):
        pytest.skip("token default owner already equals TokenUser")
    with pytest.raises(PermissionError, match="owned by the current user"):
        prepare_private_store(store)


@pytest.mark.skipif(os.name != "nt", reason="requires a separately provisioned Windows principal")
def test_native_windows_foreign_owner_fixture() -> None:
    """Read-only check of an operator-provisioned foreign-owned disposable file."""
    fixture = os.environ.get("ORAMA_TEST_FOREIGN_OWNER_FILE")
    if not fixture:
        pytest.skip("operator-provisioned foreign-owner fixture not supplied")
    assert Path(fixture).is_file(), "foreign-owner fixture must exist as a regular file"
    assert not _check_windows_ownership(Path(fixture))
