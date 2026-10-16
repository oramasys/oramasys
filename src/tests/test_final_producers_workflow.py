"""Structural guards for the manual final-producers lane.

The lane is skipped unless a freeze record is approved, so a defect in its steps
would otherwise surface only after an operator spends an approval. These tests
read the workflow as data and pin the properties that review found missing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/final-producers.yml"
MANIFEST = ROOT / "requirements/compatibility-manifest.v3.json"
CHECKOUT = "actions/checkout@"


def _workflow() -> dict[Any, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps(job: str) -> list[dict[str, Any]]:
    return _workflow()["jobs"][job]["steps"]


def _run_blocks() -> list[str]:
    return [
        step["run"]
        for job in _workflow()["jobs"].values()
        for step in job.get("steps", [])
        if "run" in step
    ]


def _checkout(path: str) -> dict[str, Any]:
    for step in _steps("final-producers"):
        if str(step.get("uses", "")).startswith(CHECKOUT) and step["with"].get("path") == path:
            return step["with"]
    raise AssertionError(f"no checkout at {path}")


def test_registry_checkout_matches_the_manifest_producer_registry() -> None:
    registry = json.loads(MANIFEST.read_text(encoding="utf-8"))["producer_registry"]
    checkout = _checkout("registry")
    assert checkout["repository"] == registry["repository"]
    assert checkout["ref"] == registry["ref"]


def test_parent_cleanliness_is_checked_before_any_nested_checkout() -> None:
    steps = _steps("final-producers")
    nested = [
        index for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith(CHECKOUT) and step.get("with", {}).get("path")
    ]
    clean = [
        index for index, step in enumerate(steps)
        if "git status --porcelain)" in step.get("run", "") and 'git -C' not in step["run"].split("\n")[0]
        and 'test -z "$(git status --porcelain)"' in step["run"]
    ]
    assert nested and clean, "cleanliness check or nested checkouts missing"
    assert min(clean) < min(nested)


def test_root_checkout_keeps_history_for_the_directional_drift_proof() -> None:
    """The job running the drift guard must retain the harness's history."""
    checkout = next(
        step for step in _steps("final-producers")
        if str(step.get("uses", "")).startswith(CHECKOUT)
        and not step.get("with", {}).get("path")
    )
    assert checkout["with"]["fetch-depth"] == 0


def test_no_expression_is_interpolated_into_a_shell_script() -> None:
    for block in _run_blocks():
        assert "${{ github.token }}" not in block
        assert "${{ github.event_name }}" not in block
        assert "${{ inputs." not in block


def test_orama_importing_validator_has_the_harness_source_on_its_path() -> None:
    commands = [
        line.strip()
        for block in _run_blocks()
        for line in block.splitlines()
        if "validate_coverage_packet.py" in line
    ]
    assert commands
    assert all(command.startswith("PYTHONPATH=src ") for command in commands)


def test_drift_guard_runs_before_the_source_path_is_trusted() -> None:
    step = next(
        step for step in _steps("final-producers")
        if "validate_coverage_packet.py" in step.get("run", "")
    )
    run = step["run"]
    assert run.index("check_harness_consumer_drift.py") < run.index("validate_coverage_packet.py")


def test_rebuild_difference_is_warned_not_silently_swallowed() -> None:
    build = next(
        step["run"] for step in _steps("final-producers")
        if "build_provenance.py compare" in step.get("run", "")
    )
    assert "|| true" not in build
    assert "::warning::" in build


def test_build_runs_in_a_prepared_environment_that_provenance_records() -> None:
    build = next(
        step["run"] for step in _steps("final-producers")
        if "build_provenance.py record" in step.get("run", "")
    )
    assert "--no-isolation" in build
    assert "python -m build " not in build.replace("-m build --no-isolation", "")


def test_rehearsal_mode_exists_and_never_produces_evidence() -> None:
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["rehearsal"]["type"] == "boolean"
    assert inputs["rehearsal"]["default"] is False
    gate = workflow["jobs"]["freeze-gate"]
    assert "mode" in gate["outputs"]
    upload = [s for s in _steps("final-producers") if "upload-artifact" in str(s.get("uses", ""))][0]
    assert "outputs.mode" in upload["with"]["name"]
    assert any("evidence-status.json" in block for block in _run_blocks())


def test_push_events_cannot_select_rehearsal() -> None:
    gate = next(s["run"] for s in _steps("freeze-gate") if "run" in s)
    assert "workflow_dispatch" in gate
    assert "GITHUB_EVENT_NAME" in gate
    assert "REHEARSAL" in gate


@pytest.mark.parametrize("name", ["consumer", "consumer-rebuild"])
def test_consumer_checkouts_pin_the_qualified_commit(name: str) -> None:
    assert _checkout(name)["ref"] == "f8898b35d5249e483b2f4a68c097957e675a0ef4"


def test_bundle_is_a_git_worktree_without_application_source() -> None:
    suite = next(
        step["run"] for step in _steps("final-producers")
        if "run_installed_qualification_suite.py" in step.get("run", "")
    )
    assert "git worktree add --detach" in suite
    assert "git archive" not in suite
    assert suite.index("git worktree add") < suite.index('rm -rf "$RUNNER_TEMP/harness-bundle/src/orama"')


@pytest.mark.parametrize("name", [
    "provenance-one.json", "provenance-two.json", "collection.json",
    "final-results.xml", "scenario-traces",
])
def test_artifact_upload_retains_the_inputs_a_reviewer_needs_to_recompute_verdicts(
    name: str,
) -> None:
    upload = [s for s in _steps("final-producers") if "upload-artifact" in str(s.get("uses", ""))][0]
    assert name in upload["with"]["path"]


def test_consumer_install_includes_the_extra_that_delivers_the_phylax_dependencies() -> None:
    """Producers are force-installed with --no-deps, so the extra must supply PyNaCl."""
    install = next(
        step["run"] for step in _steps("final-producers")
        if "install_with_retry.py" in step.get("run", "")
    )
    assert '"./consumer[dev,grant-serving]"' in install
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "grant-serving = [" in pyproject
