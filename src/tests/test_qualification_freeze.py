"""A proposed digest is useful evidence but cannot confer operator acceptance."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONSUMER = "a" * 40
HARNESS = "b" * 40


def helper():
    spec = importlib.util.spec_from_file_location(
        "qualification_freeze", ROOT / "scripts/qualification_freeze.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_proposal_never_claims_approval() -> None:
    proposal = helper().proposal({"schema": 3}, {"packet_version": 1}, CONSUMER, HARNESS)
    assert proposal["status"] == "proposed"
    assert proposal["approval_ref"] is None
    with pytest.raises(ValueError, match="approved"):
        helper().verify(proposal, {"schema": 3}, {"packet_version": 1}, CONSUMER, HARNESS)


def test_approved_record_binds_inputs_consumer_and_harness() -> None:
    manifest, coverage = {"schema": 3}, {"packet_version": 1}
    record = helper().proposal(manifest, coverage, CONSUMER, HARNESS)
    record.update(
        status="approved", approval_ref="operator-decision:synthetic-approval"
    )
    helper().verify(record, manifest, coverage, CONSUMER, HARNESS)
    for m, p, c, h in [
        ({"schema": 2}, coverage, CONSUMER, HARNESS),
        (manifest, {"packet_version": 2}, CONSUMER, HARNESS),
        (manifest, coverage, "c" * 40, HARNESS),
        (manifest, coverage, CONSUMER, "d" * 40),
    ]:
        with pytest.raises(ValueError):
            helper().verify(record, m, p, c, h)


@pytest.mark.parametrize("approval", [None, "", "   "])
def test_blank_approval_ref_is_rejected(approval: str | None) -> None:
    record = helper().proposal({}, {}, CONSUMER, HARNESS)
    record.update(status="approved", approval_ref=approval)
    with pytest.raises(ValueError):
        helper().verify(record, {}, {}, CONSUMER, HARNESS)


def test_binding_retains_only_the_verified_approval_inputs() -> None:
    record = helper().proposal({}, {}, CONSUMER, HARNESS)
    record.update(
        status="approved",
        approval_ref="https://github.com/example/repo/issues/1#issuecomment-2",
        ignored="not retained",
    )
    binding = helper().binding(record, {}, {}, CONSUMER, HARNESS)
    assert binding == {
        "schema": 2,
        "status": "approved",
        "approval_ref": "https://github.com/example/repo/issues/1#issuecomment-2",
        "consumer_commit": CONSUMER,
        "harness_commit": HARNESS,
        "manifest_digest": helper().digest({}),
        "coverage_digest": helper().digest({}),
    }


def test_binding_cli_emits_one_sanitized_record(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The workflow output is one JSON record and never forwards extra record fields."""
    manifest = tmp_path / "manifest.json"
    coverage = tmp_path / "coverage.json"
    record_path = tmp_path / "record.json"
    manifest.write_text("{}", encoding="utf-8")
    coverage.write_text("{}", encoding="utf-8")
    record = helper().proposal({}, {}, CONSUMER, HARNESS)
    record.update(
        status="approved",
        approval_ref="https://github.com/example/repo/issues/1#issuecomment-2",
        ignored="not retained",
    )
    record_path.write_text(json.dumps(record), encoding="utf-8")

    assert helper().main([
        "binding", str(manifest), str(coverage), "--consumer", CONSUMER,
        "--harness", HARNESS, "--record", str(record_path),
    ]) == 0

    output = capsys.readouterr().out
    assert output.count("\n") == 1
    assert json.loads(output) == helper().binding(record, {}, {}, CONSUMER, HARNESS)


def test_refusal_names_the_reason_on_stderr_and_writes_no_stdout(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "m.json"
    coverage = tmp_path / "c.json"
    manifest.write_text("{}")
    coverage.write_text("{}")
    code = helper().main(
        ["verify", str(manifest), str(coverage), "--consumer", CONSUMER, "--harness", HARNESS]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "freeze-refused: ValueError: record required" in captured.err
