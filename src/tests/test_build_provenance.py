"""Build identities are bound to clean source and compared without path disclosure."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "build_provenance", ROOT / "scripts/build_provenance.py"
)
assert spec and spec.loader
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
spec.loader.exec_module(tool)


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "synthetic@example.invalid")
    git(repo, "config", "user.name", "Synthetic Builder")
    (repo / "module.py").write_text("VALUE = 1\n")
    (repo / ".gitignore").write_text("ignored/\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "synthetic source")
    sdist, wheel = tmp_path / "source.tar.gz", tmp_path / "source.whl"
    sdist.write_bytes(b"synthetic sdist")
    wheel.write_bytes(b"synthetic wheel")
    return repo, git(repo, "rev-parse", "HEAD"), sdist, wheel


def record(source):
    return tool.record(*source)


def test_record_has_only_source_and_build_identities(source):
    result = record(source)
    repo, commit, _, _ = source
    assert set(result) == {
        "schema",
        "source_commit",
        "source_tree",
        "build_inputs",
        "source_date_epoch",
        "sdist_sha256",
        "wheel_sha256",
    }
    assert result["schema"] == 1 and result["source_commit"] == commit
    assert result["source_tree"] == git(repo, "rev-parse", "HEAD^{tree}")
    assert result["source_date_epoch"] == int(
        git(repo, "show", "-s", "--format=%ct", "HEAD")
    )
    assert result["build_inputs"]["python_version"]
    assert str(repo.parent) not in json.dumps(result)
    assert "source.whl" not in json.dumps(result)


@pytest.mark.parametrize("dirty", ["tracked", "staged", "untracked", "ignored"])
def test_dirty_build_source_is_refused(source, dirty):
    repo = source[0]
    if dirty in {"tracked", "staged"}:
        (repo / "module.py").write_text("VALUE = 2\n")
        if dirty == "staged":
            git(repo, "add", "module.py")
    elif dirty == "untracked":
        (repo / "injected.py").write_text("VALUE = 2\n")
    else:
        (repo / "ignored").mkdir()
        (repo / "ignored/injected.py").write_text("VALUE = 2\n")
    with pytest.raises(tool.ProvenanceError):
        record(source)


def test_wrong_head_and_wrong_epoch_are_refused(source, monkeypatch):
    with pytest.raises(tool.ProvenanceError):
        tool.record(source[0], "0" * 40, *source[2:])
    epoch = int(git(source[0], "show", "-s", "--format=%ct", "HEAD"))
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(epoch))
    assert record(source)["source_date_epoch"] == epoch
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(epoch + 1))
    with pytest.raises(tool.ProvenanceError):
        record(source)


def test_artifacts_must_be_outside_source_and_distinct(source):
    inside = source[0] / "source.whl"
    inside.write_bytes(b"build output")
    with pytest.raises(tool.ProvenanceError):
        tool.record(source[0], source[1], source[2], inside)
    inside.unlink()
    with pytest.raises(tool.ProvenanceError):
        tool.record(source[0], source[1], source[2], source[2])


@pytest.mark.parametrize(
    "field",
    [
        "source_commit",
        "source_tree",
        "source_date_epoch",
        "build_inputs",
        "sdist_sha256",
        "wheel_sha256",
    ],
)
def test_each_identity_mismatch_never_qualifies(source, tmp_path, capsys, field):
    first = record(source)
    second = json.loads(json.dumps(first))
    if field == "build_inputs":
        second[field]["python_version"] = "3.99.0"
    elif field == "source_date_epoch":
        second[field] += 1
    else:
        second[field] = "0" * len(second[field])
    a, b = tmp_path / "private-first.json", tmp_path / "private-second.json"
    a.write_text(json.dumps(first))
    b.write_text(json.dumps(second))
    assert tool.main(["compare", str(a), str(b)]) == 1
    report = capsys.readouterr()
    assert json.loads(report.out)["reproducible"] is False
    assert field in json.loads(report.out)["mismatches"]
    assert str(tmp_path) not in report.out + report.err


def test_cli_record_and_identical_compare(source, tmp_path, capsys):
    repo, commit, sdist, wheel = source
    output = tmp_path / "provenance.json"
    assert (
        tool.main(
            [
                "record",
                "--source-repo",
                str(repo),
                "--source-commit",
                commit,
                "--sdist",
                str(sdist),
                "--wheel",
                str(wheel),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert tool.main(["compare", str(output), str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["reproducible"] is True


@pytest.mark.parametrize(
    "raw", ["{}", '{"schema":1,"schema":1}', "[]", '{"schema":NaN}']
)
def test_invalid_records_exit_two_without_private_paths(tmp_path, capsys, raw):
    path = tmp_path / "private-record.json"
    path.write_text(raw)
    assert tool.main(["compare", str(path), str(path)]) == 2
    assert str(tmp_path) not in capsys.readouterr().err


def test_missing_record_and_missing_artifact_are_sanitized(source, tmp_path, capsys):
    assert (
        tool.main(["compare", str(tmp_path / "missing"), str(tmp_path / "missing")])
        == 2
    )
    repo, commit, sdist, _ = source
    assert (
        tool.main(
            [
                "record",
                "--source-repo",
                str(repo),
                "--source-commit",
                commit,
                "--sdist",
                str(sdist),
                "--wheel",
                str(tmp_path / "missing"),
                "--output",
                str(tmp_path / "result"),
            ]
        )
        == 2
    )
    assert str(tmp_path) not in capsys.readouterr().err


def test_source_changed_while_hashing_is_refused(source, monkeypatch):
    original = tool._hash

    def changing_hash(path):
        result = original(path)
        (source[0] / "module.py").write_text("VALUE = 999\n")
        return result

    monkeypatch.setattr(tool, "_hash", changing_hash)
    with pytest.raises(tool.ProvenanceError):
        record(source)


def test_git_environment_cannot_redirect_source(source, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/synthetic/invalid/git")
    assert record(source)["source_commit"] == source[1]


def test_private_version_is_refused(source, monkeypatch):
    monkeypatch.setattr(
        tool.metadata, "version", lambda name: "1.0+/private/build/path"
    )
    with pytest.raises(tool.ProvenanceError):
        record(source)


@pytest.mark.parametrize("epoch", ["invalid", "-1", "1.5", ""])
def test_invalid_build_epoch_is_refused(source, monkeypatch, epoch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    with pytest.raises(tool.ProvenanceError):
        record(source)


def test_output_cannot_overwrite_artifact_or_enter_checkout(source):
    repo, commit, sdist, wheel = source
    for output in (wheel, repo / "result.json"):
        assert (
            tool.main(
                [
                    "record",
                    "--source-repo",
                    str(repo),
                    "--source-commit",
                    commit,
                    "--sdist",
                    str(sdist),
                    "--wheel",
                    str(wheel),
                    "--output",
                    str(output),
                ]
            )
            == 2
        )
    assert wheel.read_bytes() == b"synthetic wheel"
