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
    """Import the drift guard script as a module so its functions can be tested."""
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
    """Run a git command in ``repo`` and return its stripped stdout."""
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _repo_with(tmp_path: Path, changed: str) -> tuple[Path, str, str]:
    """Build a repo and return (repo, consumer, harness); harness adds the file ``changed``."""
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


def test_cli_refuses_divergent_consumer_and_harness_histories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directional diff is sound only when the consumer is an ancestor of the harness."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "scripts").mkdir()
    (repo / "scripts" / "base.py").write_text("base = 1\n")
    base = _commit_all(repo, "base")
    _git(repo, "checkout", "-qb", "consumer")
    (repo / "scripts" / "consumer.py").write_text("consumer = 1\n")
    consumer = _commit_all(repo, "consumer")
    _git(repo, "checkout", "-q", "-b", "harness", base)
    (repo / "scripts" / "harness.py").write_text("harness = 1\n")
    harness = _commit_all(repo, "harness")

    assert guard.main(["x", consumer, harness, "--repo", str(repo)]) == 2
    assert "consumer is not an ancestor of harness" in capsys.readouterr().err


def _commit_all(repo: Path, message: str) -> str:
    """Stage everything, commit with ``message`` and return the new commit SHA."""
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


def test_a_gitlink_change_is_not_hidden_by_a_user_diff_configuration(tmp_path: Path) -> None:
    """diff.ignoreSubmodules=all must not suppress a committed submodule pointer change."""
    repo, consumer, _harness = _repo_with(tmp_path, "scripts/tool.py")
    consumer = _git(repo, "rev-parse", "HEAD")
    _git(repo, "config", "diff.ignoreSubmodules", "all")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},src/orama/vendored")
    _git(repo, "commit", "-qm", "gitlink")  # no `add -A`: the gitlink has no work-tree entry
    harness = _git(repo, "rev-parse", "HEAD")
    paths = guard.changed_paths(str(repo), consumer, harness)
    assert paths == ["src/orama/vendored"]
    assert not guard.permitted(guard.classify(paths))


def test_unusual_allowed_filenames_are_read_canonically(tmp_path: Path) -> None:
    """Quotes, spaces and non-ASCII names under allowed prefixes are allowed, never misparsed."""
    repo, consumer, _harness = _repo_with(tmp_path, "scripts/tool.py")
    consumer = _git(repo, "rev-parse", "HEAD")
    names = ['scripts/with space.py', 'scripts/quote"d.py', "scripts/caf\u00e9.py", "src/tests/tab\tname.py"]
    for name in names:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("z = 3\n")
    harness = _commit_all(repo, "unusual names")
    paths = guard.changed_paths(str(repo), consumer, harness)
    assert sorted(paths) == sorted(names)
    result = guard.classify(paths)
    assert guard.permitted(result) and sorted(result["allowed"]) == sorted(names)


def test_a_newline_in_a_runtime_filename_is_still_refused(tmp_path: Path) -> None:
    """A path crafted to split across lines cannot launder a forbidden change."""
    repo, consumer, _harness = _repo_with(tmp_path, "scripts/tool.py")
    consumer = _git(repo, "rev-parse", "HEAD")
    nasty = "src/orama/bad\nscripts/looks_allowed.py"
    target = repo / nasty
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("w = 1\n")
    harness = _commit_all(repo, "newline name")
    paths = guard.changed_paths(str(repo), consumer, harness)
    assert paths == [nasty]
    assert not guard.permitted(guard.classify(paths))
