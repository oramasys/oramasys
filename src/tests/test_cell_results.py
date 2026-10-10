"""A green cell must have actually run: zero tests, failures, or extra skips are rejected.

The manifest records, per cell, a floor on passed tests and the exact skip allowance
measured from CI. A cell that collapses to few tests or starts skipping cannot pass.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from orama.compat.manifest import ManifestError, check_cell_results

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "requirements" / "compatibility-manifest.json").read_text())


def junit(tests: int, failures: int = 0, errors: int = 0, skipped: int = 0) -> str:
    return (f'<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="{tests}" '
            f'failures="{failures}" errors="{errors}" skipped="{skipped}"/></testsuites>')


def cell(profile: str, python: str = "3.12") -> dict:
    return next(c for c in MANIFEST["cells"] if (c["profile"], c["python"]) == (profile, python))


def test_every_cell_declares_a_floor_and_a_skip_allowance() -> None:
    for c in MANIFEST["cells"]:
        assert isinstance(c["min_passed"], int) and c["min_passed"] > 0
        assert isinstance(c["max_skipped"], int) and c["max_skipped"] >= 0


@pytest.mark.parametrize("profile, tests, skipped", [
    ("production", 378, 1), ("core-r3", 378, 1), ("policy-r3", 367, 5)])
def test_the_measured_results_of_each_lane_pass(profile: str, tests: int, skipped: int) -> None:
    check_cell_results(junit(tests, skipped=skipped), cell(profile))


@pytest.mark.parametrize("name, xml", [
    ("no tests ran", junit(0)),
    ("collapsed below the floor", junit(40)),
    ("a failure", junit(379, failures=1, skipped=1)),
    ("an error", junit(379, errors=1, skipped=1)),
    ("an extra skip", junit(380, skipped=2)),
    ("not xml", "not xml"),
    ("no testsuite", "<testsuites/>"),
])
def test_rejects_a_cell_that_did_not_really_pass(name: str, xml: str) -> None:
    with pytest.raises(ManifestError):
        check_cell_results(xml, cell("production"))


def test_sums_every_testsuite_in_the_report() -> None:
    xml = ('<testsuites><testsuite tests="200" failures="0" errors="0" skipped="0"/>'
           '<testsuite tests="179" failures="0" errors="0" skipped="1"/></testsuites>')
    check_cell_results(xml, cell("production"))


def test_manifest_rejects_a_cell_without_the_result_gate_fields() -> None:
    from orama.compat.manifest import validate_manifest
    from tests.test_compatibility_manifest import check
    broken = copy.deepcopy(MANIFEST)
    del broken["cells"][0]["max_skipped"]
    with pytest.raises(ManifestError):
        check(broken)
