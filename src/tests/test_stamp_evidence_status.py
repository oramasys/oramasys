"""The retained-record seal must make an evidence run auditable or refuse to call it evidence."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    """Import the stamping script as a module so its functions can be tested."""
    spec = importlib.util.spec_from_file_location(
        "stamp_evidence_status", ROOT / "scripts" / "stamp_evidence_status.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["stamp_evidence_status"] = module
    spec.loader.exec_module(module)
    return module


seal = _load()
HEAD = "a" * 40


def _populate(directory: Path) -> None:
    """Write one non-empty record for every required file and directory."""
    for name in seal.REQUIRED_FILES:
        (directory / name).write_text(f"record {name}\n", encoding="utf-8")
    for name in seal.REQUIRED_DIRECTORIES:
        (directory / name).mkdir()
        (directory / name / "one.json").write_text(f"{name} one\n", encoding="utf-8")


def _status(directory: Path, *, mode: str = "evidence", job_status: str = "success") -> dict:
    """Build the sealed status for ``directory`` with a fixed head and run."""
    return seal.build_status(directory, mode=mode, job_status=job_status, head_sha=HEAD,
                             run_id="42", run_attempt="1")


def _argv(directory: Path, *extra: str, job_status: str = "success") -> list[str]:
    """Return a complete command line for ``seal.main``."""
    return ["x", "--directory", str(directory), "--mode", "evidence", "--job-status", job_status,
            "--head-sha", HEAD, "--run-id", "42", "--run-attempt", "1", *extra]


def test_a_complete_successful_evidence_run_is_sealed_as_evidence(tmp_path: Path) -> None:
    """Every required record is hashed and the run is bound to its head and run id."""
    _populate(tmp_path)
    status = _status(tmp_path)

    assert status["evidence"] is True
    assert status["complete"] is True
    assert status["problems"] == []
    assert (status["head_sha"], status["run_id"], status["run_attempt"]) == (HEAD, "42", "1")
    expected = hashlib.sha256(b"record collection.json\n").hexdigest()
    assert status["files"]["collection.json"] == expected
    assert status["files"]["scenario-traces/one.json"] == hashlib.sha256(
        b"scenario-traces one\n").hexdigest()
    assert len(status["files"]) == len(seal.REQUIRED_FILES) + len(seal.REQUIRED_DIRECTORIES)


@pytest.mark.parametrize(("mode", "job_status"), [
    ("rehearsal", "success"), ("evidence", "failure"), ("evidence", "cancelled"),
])
def test_only_a_successful_evidence_mode_run_can_be_evidence(
    tmp_path: Path, mode: str, job_status: str
) -> None:
    """Rehearsal and failed runs stay non-evidence even when every record is present."""
    _populate(tmp_path)

    assert _status(tmp_path, mode=mode, job_status=job_status)["evidence"] is False


@pytest.mark.parametrize("name", [*("identity.json", "provenance-one.json", "collection.json",
                                    "final-results.xml", "rebuild-comparison.json")])
def test_a_missing_required_file_removes_the_evidence_claim(tmp_path: Path, name: str) -> None:
    """A lost provenance, collection or result record cannot be sealed as evidence."""
    _populate(tmp_path)
    (tmp_path / name).unlink()
    status = _status(tmp_path)

    assert status["evidence"] is False
    assert status["complete"] is False
    assert f"{name}: missing" in status["problems"]
    assert name not in status["files"]


def test_an_empty_record_is_not_a_record(tmp_path: Path) -> None:
    """A zero-byte file proves nothing and is rejected."""
    _populate(tmp_path)
    (tmp_path / "collection.json").write_text("")

    assert "collection.json: empty" in _status(tmp_path)["problems"]


@pytest.mark.parametrize("name", ["scenario-traces", "install-reports"])
def test_an_empty_or_missing_record_directory_is_rejected(tmp_path: Path, name: str) -> None:
    """Traces and install reports must contain at least one file."""
    _populate(tmp_path)
    (tmp_path / name / "one.json").unlink()
    assert f"{name}/: no records" in _status(tmp_path)["problems"]

    (tmp_path / name).rmdir()
    assert f"{name}/: missing" in _status(tmp_path)["problems"]


def test_symlinked_records_are_never_followed(tmp_path: Path) -> None:
    """A link cannot smuggle outside content into the sealed set."""
    _populate(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("secret\n")
    (tmp_path / "identity.json").unlink()
    (tmp_path / "identity.json").symlink_to(outside)
    (tmp_path / "scenario-traces" / "link.json").symlink_to(outside)
    status = _status(tmp_path)

    assert "identity.json: is a symlink" in status["problems"]
    assert "scenario-traces/link.json: is a symlink" in status["problems"]
    assert "identity.json" not in status["files"]
    assert "scenario-traces/link.json" not in status["files"]
    assert status["evidence"] is False


def test_nested_trace_paths_are_recorded_with_posix_separators(tmp_path: Path) -> None:
    """A trace in a subdirectory is hashed under a stable relative key."""
    _populate(tmp_path)
    nested = tmp_path / "scenario-traces" / "group"
    nested.mkdir()
    (nested / "deep.json").write_text("deep\n")

    assert "scenario-traces/group/deep.json" in _status(tmp_path)["files"]


def test_main_writes_the_seal_and_exits_zero_for_a_sound_run(tmp_path: Path) -> None:
    """The default output is evidence-status.json beside the records."""
    _populate(tmp_path)

    assert seal.main(_argv(tmp_path)) == 0
    written = json.loads((tmp_path / "evidence-status.json").read_text(encoding="utf-8"))
    assert written["evidence"] is True
    assert written["schema"] == 2


def test_main_fails_a_green_job_that_lost_records(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A job that reports success but lost records must not pass, and still writes the seal."""
    _populate(tmp_path)
    (tmp_path / "provenance-two.json").unlink()

    assert seal.main(_argv(tmp_path)) == 1
    assert "provenance-two.json: missing" in capsys.readouterr().err
    assert json.loads((tmp_path / "evidence-status.json").read_text())["evidence"] is False


def test_main_does_not_mask_an_already_failed_job(tmp_path: Path) -> None:
    """When the job already failed, the seal records it and the stamp step adds no second failure."""
    _populate(tmp_path)
    (tmp_path / "provenance-two.json").unlink()

    assert seal.main(_argv(tmp_path, job_status="failure")) == 0


def test_main_honours_an_explicit_output_path(tmp_path: Path) -> None:
    """``--output`` redirects the seal and leaves the records directory untouched."""
    _populate(tmp_path)
    target = tmp_path.parent / f"{tmp_path.name}-status.json"

    assert seal.main(_argv(tmp_path, "--output", str(target))) == 0
    assert target.is_file()
    assert not (tmp_path / "evidence-status.json").exists()


def test_main_rejects_bad_usage(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A missing directory or missing arguments are usage errors (exit 2)."""
    assert seal.main(_argv(tmp_path / "absent")) == 2
    assert "is not a directory" in capsys.readouterr().err
    assert seal.main(["x", "--mode", "evidence"]) == 2
