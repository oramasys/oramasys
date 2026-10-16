"""The final suite runner keeps harness tests separate from installed runtime code."""

from __future__ import annotations

import importlib.util
import sysconfig
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def tool():
    spec = importlib.util.spec_from_file_location(
        "installed_qualification_suite",
        ROOT / "scripts" / "run_installed_qualification_suite.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bundle_refuses_a_runtime_source_tree(tool, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "src/orama").mkdir(parents=True)
    with pytest.raises(ValueError, match="runtime source"):
        tool.validate_bundle(bundle)


def test_bundle_requires_tests_and_no_runtime_source(tool, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "src/tests").mkdir(parents=True)
    tool.validate_bundle(bundle)


def test_import_origin_must_be_an_installed_site_package(
    tool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = tmp_path / "site-packages"
    origin = site / "orama/__init__.py"
    origin.parent.mkdir(parents=True)
    origin.write_text("", encoding="utf-8")
    module = SimpleNamespace(__file__=str(origin))
    monkeypatch.setattr(tool.importlib, "import_module", lambda _: module)
    monkeypatch.setattr(
        sysconfig, "get_path", lambda name: str(site) if name == "purelib" else None
    )
    tool.assert_installed_origin()
    module.__file__ = str(tmp_path / "source/orama/__init__.py")
    with pytest.raises(ValueError, match="site-packages"):
        tool.assert_installed_origin()


def test_runner_records_every_phase_of_each_executed_test() -> None:
    """Executed ids come from the run itself, so membership can be compared to collection."""
    import importlib.util
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location(
        "run_installed_qualification_suite",
        Path(__file__).resolve().parents[2] / "scripts/run_installed_qualification_suite.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    plugin = module._Collected()
    for when in ("setup", "call", "teardown"):
        plugin.pytest_runtest_logreport(SimpleNamespace(nodeid="src/tests/a.py::test_one", when=when))
    plugin.pytest_runtest_logreport(SimpleNamespace(nodeid="src/tests/a.py::test_two", when="call"))

    assert plugin.executed_node_ids == ["src/tests/a.py::test_one", "src/tests/a.py::test_two"]
