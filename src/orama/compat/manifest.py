"""Exact-cell validation for the P0 compatibility manifest.

The manifest names every (profile, interpreter) cell P0 must run, each bound to one
immutable Core revision. Validation is strict on purpose: a missing, duplicate, extra
or mispinned cell, an unknown key, or a workflow matrix that disagrees with the
manifest is an error, never a warning.
"""
from __future__ import annotations

import itertools
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

SCHEMA = 2
PROFILES = ("production", "policy-r3", "core-r3")
PYTHONS = ("3.11", "3.12")
PRODUCER_REPOSITORY = "diazMelgarejo/orama-system"
CELL_KEYS = frozenset({"profile", "python", "core_file", "core_sha", "require_r3",
                       "min_passed", "max_skipped"})
TOP_KEYS = frozenset({"schema", "producer_registry", "cells"})
FULL_SHA = re.compile(r"[0-9a-f]{40}")


class ManifestError(ValueError):
    """The manifest, a lane file, or the workflow does not describe the required cells."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def validate_manifest(
    manifest: Mapping[str, Any],
    *,
    core_pins: Mapping[str, str],
    lane_files: Mapping[str, Mapping[str, str]],
    producer_ref: str,
) -> None:
    """Reject anything but exactly one valid cell per profile and interpreter."""
    _need(set(manifest) == TOP_KEYS, f"manifest keys must be exactly {sorted(TOP_KEYS)}")
    _need(manifest["schema"] == SCHEMA, f"manifest schema must be {SCHEMA}")
    registry = manifest["producer_registry"]
    _need(isinstance(registry, Mapping) and set(registry) == {"repository", "ref"},
          "producer_registry must hold exactly repository and ref")
    _need(registry["repository"] == PRODUCER_REPOSITORY, "unexpected producer repository")
    _need(isinstance(registry["ref"], str) and FULL_SHA.fullmatch(registry["ref"]) is not None,
          "producer ref must be a full commit SHA")
    _need(registry["ref"] == producer_ref, "producer ref differs from the workflow checkout")

    seen: set[tuple[str, str]] = set()
    cells = manifest["cells"]
    _need(isinstance(cells, list), "cells must be a list")
    for cell in cells:
        _need(isinstance(cell, Mapping) and set(cell) == CELL_KEYS,
              f"each cell must have exactly {sorted(CELL_KEYS)}")
        key = (cell["profile"], cell["python"])
        _need(cell["profile"] in PROFILES, f"unknown profile {cell['profile']!r}")
        _need(cell["python"] in PYTHONS, f"unknown interpreter {cell['python']!r}")
        _need(key not in seen, f"duplicate cell {key}")
        seen.add(key)
        _need(isinstance(cell["require_r3"], bool), "require_r3 must be a boolean")
        for field in ("min_passed", "max_skipped"):
            _need(type(cell[field]) is int and cell[field] >= 0, f"{key}: {field} must be an integer")
        _need(cell["min_passed"] > 0, f"{key}: min_passed must be positive")
        sha = cell["core_sha"]
        _need(isinstance(sha, str) and FULL_SHA.fullmatch(sha) is not None,
              f"{key}: core_sha must be a full commit SHA")
        _need(sha == core_pins[cell["profile"]], f"{key}: core_sha differs from registry profile")
        lane = lane_files[cell["profile"]]
        _need(cell["core_file"] == lane["path"], f"{key}: core_file is not the lane file")
        _need(sha == lane["sha"], f"{key}: lane file content differs from core_sha")
    required = set(itertools.product(PROFILES, PYTHONS))
    _need(seen == required, f"cells must be exactly {sorted(required)}, got {sorted(seen)}")


_ENTRY = re.compile(
    r'-\s*python-version:\s*"(?P<python>[^"]+)"\s*\n'
    r"\s*profile:\s*(?P<profile>\S+)\s*\n"
    r"\s*core-file:\s*(?P<core_file>\S+)\s*\n"
    r'\s*require-r3:\s*"(?P<require>[01])"'
)


def workflow_cells(text: str) -> list[dict[str, Any]]:
    """Return every oracle matrix entry in the workflow, in file order."""
    return [{"python": m["python"], "profile": m["profile"], "core_file": m["core_file"],
             "require_r3": m["require"] == "1"} for m in _ENTRY.finditer(text)]


def validate_workflow(manifest: Mapping[str, Any], text: str) -> None:
    """The workflow matrix must contain exactly the manifest's cells, no more or fewer."""
    expected = sorted((c["python"], c["profile"], c["core_file"], c["require_r3"])
                      for c in manifest["cells"])
    actual = sorted((c["python"], c["profile"], c["core_file"], c["require_r3"])
                    for c in workflow_cells(text))
    _need(actual == expected, f"workflow matrix differs from manifest:\n{actual}\n{expected}")
    # Each matrix cell has exactly one of each key, whatever their order; count them all.
    key_patterns = {
        "python-version": r'^\s*(?:-\s*)?python-version:\s*"',
        "profile": r"^\s*(?:-\s*)?profile:",
        "core-file": r"^\s*(?:-\s*)?core-file:",
        "require-r3": r"^\s*(?:-\s*)?require-r3:",
    }
    counts = {k: len(re.findall(p, text, flags=re.MULTILINE)) for k, p in key_patterns.items()}
    _need(all(n == len(actual) for n in counts.values()),
          f"workflow matrix keys {counts} disagree with the {len(actual)} parsed cells")


def check_cell_results(junit_xml: str, cell: Mapping[str, Any]) -> None:
    """Reject a cell whose JUnit report shows failures, too few passes, or extra skips."""
    try:
        root = ET.fromstring(junit_xml)
    except ET.ParseError as error:
        raise ManifestError("cell result is not valid JUnit XML") from error
    # Count only top-level suites: a parent suite already totals its nested children.
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    _need(bool(suites), "cell result contains no testsuite")
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for suite in suites:
        for name in totals:
            raw = suite.get(name, "0")
            _need(raw.isascii() and raw.isdigit(), f"JUnit {name} count is not a non-negative integer")
            totals[name] += int(raw)
    passed = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
    label = f"{cell['profile']} on {cell['python']}"
    _need(totals["failures"] == 0 and totals["errors"] == 0, f"{label}: failures or errors reported")
    _need(passed >= cell["min_passed"],
          f"{label}: {passed} passed is below the floor of {cell['min_passed']}")
    _need(totals["skipped"] <= cell["max_skipped"],
          f"{label}: {totals['skipped']} skipped exceeds the allowance of {cell['max_skipped']}")
