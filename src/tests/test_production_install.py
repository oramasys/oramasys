"""The production install proof: a clean, non-editable install of the exact Core pin.

Editable overlays and candidate checkouts are oracle evidence only. The verifier must
reject an editable Core, a missing or mismatched PEP 610 record, a Core imported from
outside its installed distribution, a missing public symbol, and a graph that cannot run.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_production_install.py"
SHA = CORE_PINS["production"]
CORE_URL = "https://github.com/oramasys/perpetua-core.git"


def load_script():
    spec = importlib.util.spec_from_file_location("verify_production_install", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_production_install"] = module
    spec.loader.exec_module(module)
    return module


class FakeDist:
    def __init__(self, direct_url, site: Path) -> None:
        self._direct_url, self._site = direct_url, site

    def read_text(self, name: str):
        if name != "direct_url.json" or self._direct_url is None:
            return None
        return self._direct_url if isinstance(self._direct_url, str) else json.dumps(self._direct_url)

    def locate_file(self, path: str) -> Path:
        return self._site / path


def vcs(commit: str = SHA, url: str = CORE_URL, **extra) -> dict:
    return {"url": url, "vcs_info": {"vcs": "git", "commit_id": commit}, **extra}


def fixture(tmp_path: Path, core_direct=None, orama_direct="absent"):
    """Dists whose files sit under tmp_path/site, plus real modules for the smoke test."""
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    dists = {
        "perpetua-core": FakeDist(core_direct if core_direct is not None else vcs(), site),
        "oramasys": FakeDist(None if orama_direct == "absent" else orama_direct, site),
    }

    def distribution(name: str):
        if name not in dists:
            raise ModuleNotFoundError(name)
        return dists[name]

    return distribution, site


def run(module, tmp_path: Path, *, core_direct=None, orama_direct="absent",
        locate_under_site: bool = True, import_module=None, expected: str = SHA) -> None:
    distribution, site = fixture(tmp_path, core_direct, orama_direct)

    module.verify_production_install(
        expected, distribution=distribution,
        module_file=(lambda name: str(site / name / "__init__.py")) if locate_under_site
        else (lambda name: str(tmp_path / "checkout" / name / "__init__.py")),
        import_module=import_module or __import__("importlib").import_module)


def test_accepts_a_pinned_non_editable_install(tmp_path: Path) -> None:
    run(load_script(), tmp_path)


@pytest.mark.parametrize("name, direct", [
    ("not json", "{not json"),
    ("wrong commit", vcs(commit="0" * 40)),
    ("short commit", vcs(commit=SHA[:12])),
    ("not git", {"url": CORE_URL, "vcs_info": {"vcs": "hg", "commit_id": SHA}}),
    ("wrong repository", vcs(url="https://github.com/other/perpetua-core.git")),
    ("local directory", {"url": "file:///src/perpetua-core", "dir_info": {}}),
    ("editable directory", {"url": "file:///src/perpetua-core", "dir_info": {"editable": True}}),
    ("editable flag on vcs record", vcs(dir_info={"editable": True})),
    ("archive", {"url": CORE_URL, "archive_info": {"hash": "sha256=00"}}),
])
def test_rejects_core_identity_failures(tmp_path: Path, name: str, direct) -> None:
    module = load_script()
    with pytest.raises(module.InstallError):
        run(module, tmp_path, core_direct=direct)


def test_rejects_a_core_without_a_direct_url_record(tmp_path: Path) -> None:
    """An index or wheel install carries no PEP 610 proof of which commit it is."""
    module = load_script()
    site = tmp_path / "site"
    with pytest.raises(module.InstallError, match="direct_url"):
        module.verify_production_install(
            SHA, distribution=lambda name: FakeDist(None, site),
            module_file=lambda name: str(site / name / "__init__.py"))


def test_rejects_an_editable_oramasys(tmp_path: Path) -> None:
    module = load_script()
    with pytest.raises(module.InstallError, match="editable"):
        run(module, tmp_path, orama_direct={"url": "file:///x", "dir_info": {"editable": True}})


def test_rejects_modules_imported_from_outside_the_installed_distribution(tmp_path: Path) -> None:
    module = load_script()
    with pytest.raises(module.InstallError, match="outside"):
        run(module, tmp_path, locate_under_site=False)


def test_rejects_a_malformed_expected_sha(tmp_path: Path) -> None:
    module = load_script()
    for bad in ("main", SHA[:12], SHA.upper(), ""):
        with pytest.raises(module.InstallError):
            run(module, tmp_path, expected=bad)


def test_rejects_a_missing_public_symbol(tmp_path: Path) -> None:
    module = load_script()
    real = __import__("importlib").import_module

    def without_join_spec(name: str):
        loaded = real(name)
        if name == "perpetua_core.graph.spec":
            return types.SimpleNamespace(**{k: v for k, v in vars(loaded).items() if k != "JoinSpec"})
        return loaded

    with pytest.raises(module.InstallError, match="JoinSpec"):
        run(module, tmp_path, import_module=without_join_spec)


def test_rejects_a_graph_that_cannot_execute(tmp_path: Path) -> None:
    module = load_script()
    real = __import__("importlib").import_module

    def broken_core(name: str):
        loaded = real(name)
        if name == "perpetua_core":
            class Broken:
                def __init__(self, *a, **k): raise RuntimeError("scheduler unavailable")
            return types.SimpleNamespace(**{**vars(loaded), "MiniGraph": Broken})
        return loaded

    with pytest.raises(module.InstallError, match="graph"):
        run(module, tmp_path, import_module=broken_core)


def test_a_clean_install_verifies_from_outside_the_checkout(tmp_path: Path) -> None:
    """Required in CI (clean install job); skipped where an editable overlay is expected."""
    if not os.environ.get("ORAMA_REQUIRE_CLEAN_INSTALL"):
        pytest.skip("ORAMA_REQUIRE_CLEAN_INSTALL not set")
    result = subprocess.run([sys.executable, "-I", str(SCRIPT), SHA], cwd=tmp_path,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
