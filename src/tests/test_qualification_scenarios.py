"""Deterministic qualification scenarios are scoped evidence, never acceptance."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _tool():
    spec = importlib.util.spec_from_file_location(
        "qualification_scenarios", ROOT / "scripts" / "run_qualification_scenarios.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runner_emits_each_frozen_scenario_with_bound_trace(tmp_path: Path) -> None:
    tool = _tool()
    manifest = "a" * 64
    coverage = "b" * 64
    result = tool.run(manifest, coverage, tmp_path)

    assert result["schema"] == 1
    assert result["qualification_status"] == "unapproved"
    assert result["scope"] == "deterministic-synthetic"
    assert result["manifest_digest"] == manifest
    assert result["coverage_digest"] == coverage
    assert {item["scenario_id"] for item in result["scenarios"]} == set(tool.MANDATORY_SCENARIOS)
    assert result["complete"] is True
    for item in result["scenarios"]:
        trace = tmp_path / f"{item['scenario_id']}.json"
        assert trace.is_file()
        assert item["trace_digest"] == hashlib.sha256(trace.read_bytes()).hexdigest()
        assert item["passed"] is True
        assert item["limitations"]


@pytest.mark.parametrize("bad", ["", "A" * 64, "a" * 63, "a" * 65])
def test_runner_refuses_noncanonical_input_digests(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError):
        _tool().run(bad, "b" * 64, tmp_path)


def test_runner_refuses_existing_trace_destination(tmp_path: Path) -> None:
    destination = tmp_path / "POP-CASCADE-1.json"
    destination.write_text("existing", encoding="utf-8")
    with pytest.raises(FileExistsError):
        _tool().run("a" * 64, "b" * 64, tmp_path)


def test_output_is_json_serializable_without_probability_or_authority(tmp_path: Path) -> None:
    result = _tool().run("a" * 64, "b" * 64, tmp_path)
    encoded = json.dumps(result, sort_keys=True)
    assert "probability" not in encoded
    assert "authoriz" not in encoded.casefold()
