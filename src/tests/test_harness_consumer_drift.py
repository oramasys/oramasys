"""The harness commit may differ from the qualified consumer commit only in tests and tooling."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_harness_consumer_drift", ROOT / "scripts" / "check_harness_consumer_drift.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_harness_consumer_drift"] = module
    spec.loader.exec_module(module)
    return module


guard = _load()


def test_tooling_tests_workflows_and_requirements_are_allowed() -> None:
    """The four harness areas never change what the consumer ships."""
    result = guard.classify([
        "requirements/compatibility-manifest.v3.json", "scripts/verify_cell_results.py",
        ".github/workflows/final-producers.yml", "src/tests/test_x.py", "tests/oracles/README.md",
    ])
    assert guard.permitted(result)
    assert len(result["allowed"]) == 5


@pytest.mark.parametrize("path", [
    "src/orama/graph/lost_run_recovery.py", "src/orama/compat/manifest.py", "pyproject.toml",
])
def test_runtime_paths_force_c_to_be_reselected(path: str) -> None:
    """Any runtime or dependency change makes C stale."""
    result = guard.classify(["scripts/x.py", path])
    assert not guard.permitted(result)
    assert result["forbidden"] == [path]


@pytest.mark.parametrize("path", ["README.md", "docs/x.md", "setup.cfg", "src/other/mod.py", "Makefile"])
def test_an_unclassified_path_is_refused_rather_than_assumed_harmless(path: str) -> None:
    """The allowlist is closed: unknown means refused."""
    result = guard.classify([path])
    assert not guard.permitted(result)
    assert result["unclassified"] == [path]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _repo_with(tmp_path: Path, changed: str) -> tuple[Path, str, str]:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "src" / "orama").mkdir(parents=True)
    (repo / "src" / "orama" / "a.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "c")
    consumer = _git(repo, "rev-parse", "HEAD")
    target = repo / changed
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("y = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "h")
    return repo, consumer, _git(repo, "rev-parse", "HEAD")


def test_cli_accepts_a_tooling_only_difference(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Real git history: a scripts-only commit is permitted and reported."""
    repo, consumer, harness = _repo_with(tmp_path, "scripts/tool.py")
    assert guard.main(["x", consumer, harness, "--repo", str(repo)]) == 0
    assert json.loads(capsys.readouterr().out)["allowed"] == ["scripts/tool.py"]


def test_cli_refuses_a_runtime_difference(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Real git history: a runtime change exits 1 and names the path."""
    repo, consumer, harness = _repo_with(tmp_path, "src/orama/b.py")
    assert guard.main(["x", consumer, harness, "--repo", str(repo)]) == 1
    assert json.loads(capsys.readouterr().out)["forbidden"] == ["src/orama/b.py"]


def test_cli_distinguishes_a_git_error_from_a_refusal(tmp_path: Path) -> None:
    """An unknown commit is exit 2, never a silent pass."""
    repo, _consumer, harness = _repo_with(tmp_path, "scripts/tool.py")
    assert guard.main(["x", "0" * 40, harness, "--repo", str(repo)]) == 2
    assert guard.main(["x", "only-one-arg"]) == 2
