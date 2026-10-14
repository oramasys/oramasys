"""Exact-cell validation for the P0 compatibility manifest.

The manifest names every (profile, interpreter) cell P0 must run, each bound to one
immutable Core revision. Validation is strict on purpose: a missing, duplicate, extra
or mispinned cell, an unknown key, or a workflow matrix that disagrees with the
manifest is an error, never a warning.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

SCHEMA = 2
SCHEMA_V3 = 3
SUPPORTED_SCHEMAS = (SCHEMA, SCHEMA_V3)
FINAL_PROFILE = "final-producers"
CODE_INVALID = "manifest-invalid"
CODE_SCHEMA_UNKNOWN = "manifest-schema-unknown"
CODE_SCHEMA_MISMATCH = "manifest-schema-mismatch"
CODE_DIGEST_MISMATCH = "manifest-digest-mismatch"
PROFILES = ("production", "policy-r3", "core-r3")
PYTHONS = ("3.11", "3.12")
PRODUCER_REPOSITORY = "diazMelgarejo/orama-system"
CELL_KEYS = frozenset({"profile", "python", "core_file", "core_sha", "require_r3",
                       "min_passed", "max_skipped"})
TOP_KEYS = frozenset({"schema", "producer_registry", "cells"})
FULL_SHA = re.compile(r"[0-9a-f]{40}")


class ManifestError(ValueError):
    """The manifest, a lane file, or the workflow does not describe the required cells."""

    def __init__(self, message: str, code: str = CODE_INVALID) -> None:
        """Carry a stable machine-readable code next to the human message."""
        super().__init__(message)
        self.code = code


def _need(condition: bool, message: str, code: str = CODE_INVALID) -> None:
    if not condition:
        raise ManifestError(message, code)


def _check_registry(manifest: Mapping[str, Any], producer_ref: str) -> None:
    """The producer registry must be the one repository at the workflow's full SHA."""
    registry = manifest["producer_registry"]
    _need(isinstance(registry, Mapping) and set(registry) == {"repository", "ref"},
          "producer_registry must hold exactly repository and ref")
    _need(registry["repository"] == PRODUCER_REPOSITORY, "unexpected producer repository")
    _need(isinstance(registry["ref"], str) and FULL_SHA.fullmatch(registry["ref"]) is not None,
          "producer ref must be a full commit SHA")
    _need(registry["ref"] == producer_ref, "producer ref differs from the workflow checkout")


def _check_pinned_cell(
    cell: Mapping[str, Any],
    key: tuple[str, str],
    core_pins: Mapping[str, str],
    lane_files: Mapping[str, Mapping[str, str]],
) -> None:
    """Check one historical cell's flags, counts, Core pin and lane file."""
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


def _validate_v2(
    manifest: Mapping[str, Any],
    *,
    core_pins: Mapping[str, str],
    lane_files: Mapping[str, Mapping[str, str]],
    producer_ref: str,
) -> None:
    """Reject anything but exactly one valid cell per profile and interpreter."""
    _need(set(manifest) == TOP_KEYS, f"manifest keys must be exactly {sorted(TOP_KEYS)}")
    _need(manifest["schema"] == SCHEMA, f"manifest schema must be {SCHEMA}")
    _check_registry(manifest, producer_ref)

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
        _check_pinned_cell(cell, key, core_pins, lane_files)
    required = set(itertools.product(PROFILES, PYTHONS))
    _need(seen == required, f"cells must be exactly {sorted(required)}, got {sorted(seen)}")


# ---- schema 3 ---------------------------------------------------------------------
PROFILES_V3 = PROFILES + (FINAL_PROFILE,)
TOP_KEYS_V3 = TOP_KEYS | {"consumer", "producers", "registry_profiles", "artifacts", "environments",
                          "required_capabilities", "disabled_capabilities", "source_contracts",
                          "contract_ids"}
FINAL_CELL_KEYS = frozenset({"profile", "python", "require_r3", "min_passed", "max_skipped",
                             "candidate_set"})
PRODUCER_ROLES = frozenset({"neutral-mechanics", "endpoint-policy", "hardware-eligibility",
                            "grant-authority"})
COMPOSITION_ROLE = "grant-authority"
CONTRACT_IDS = ("M1-Q-MANIFEST-1", "M1-Q-INSTALL-1", "M1-Q-DELIVERY-1", "M1-Q-ACCOUNTING-1",
                "M1-Q-COMPOSITION-1", "COLLAB-HANDOFF-1", "INTERACTION-RISK-ASSESSMENT-1")


def canonical_digest(manifest: Mapping[str, Any]) -> str:
    """Return sha256 of the canonical JSON (UTF-8, sorted keys, no extra whitespace)."""
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _full_sha(value: Any) -> bool:
    """True only for a 40-character lowercase hex string."""
    return isinstance(value, str) and FULL_SHA.fullmatch(value) is not None


def _check_producers(manifest: Mapping[str, Any]) -> dict[str, str]:
    """Validate producer identities and return role -> candidate SHA."""
    producers = manifest["producers"]
    _need(isinstance(producers, Mapping) and set(producers) == PRODUCER_ROLES,
          f"producers must be exactly {sorted(PRODUCER_ROLES)}")
    candidates: dict[str, str] = {}
    for role, entry in producers.items():
        allowed = {"candidate", "declared_dependency"} | (
            set() if role == COMPOSITION_ROLE else {"production_pin"})
        required = {"candidate", "declared_dependency"}
        _need(isinstance(entry, Mapping) and required <= set(entry) <= allowed,
              f"producer {role}: unexpected keys")
        _need(_full_sha(entry["candidate"]), f"producer {role}: candidate must be a full SHA")
        if "production_pin" in entry:
            _need(_full_sha(entry["production_pin"]), f"producer {role}: pin must be a full SHA")
        _need(entry["declared_dependency"] is (role != COMPOSITION_ROLE),
              f"producer {role}: declared_dependency is wrong for its role")
        candidates[role] = entry["candidate"]
    return candidates


def _check_final_cell(cell: Mapping[str, Any], candidates: Mapping[str, str]) -> tuple[str, str]:
    """Validate one final-producers cell and return its (profile, python) key."""
    _need(set(cell) == FINAL_CELL_KEYS, f"each final cell must have exactly {sorted(FINAL_CELL_KEYS)}")
    key = (cell["profile"], cell["python"])
    _need(cell["python"] in PYTHONS, f"unknown interpreter {cell['python']!r}")
    _need(isinstance(cell["require_r3"], bool), "require_r3 must be a boolean")
    _need(type(cell["min_passed"]) is int and cell["min_passed"] > 0,
          f"{key}: min_passed must be a positive integer")
    _need(cell["max_skipped"] == 0 and type(cell["max_skipped"]) is int,
          f"{key}: final-producers cells must allow no skips")
    _need(cell["candidate_set"] == dict(candidates),
          f"{key}: candidate_set differs from the declared producers")
    return key


def _check_v3_extras(manifest: Mapping[str, Any]) -> None:
    """Validate consumer, registry profiles, contract ids and the declared-only sections."""
    consumer = manifest["consumer"]
    _need(isinstance(consumer, Mapping) and set(consumer) == {"repository", "sha"}
          and isinstance(consumer["repository"], str) and _full_sha(consumer["sha"]),
          "consumer must hold a repository and a full SHA")
    _need(manifest["contract_ids"] == list(CONTRACT_IDS),
          f"contract_ids must be exactly {list(CONTRACT_IDS)}")
    for name in ("artifacts", "environments", "source_contracts"):
        _need(isinstance(manifest[name], Mapping) and bool(manifest[name]),
              f"{name} must be a non-empty mapping")
    for name in ("required_capabilities", "disabled_capabilities"):
        value = manifest[name]
        _need(isinstance(value, list) and bool(value) and len(set(value)) == len(value)
              and all(isinstance(v, str) and v for v in value),
              f"{name} must be a non-empty list of unique strings")


def _validate_v3(
    manifest: Mapping[str, Any],
    *,
    core_pins: Mapping[str, str],
    lane_files: Mapping[str, Mapping[str, str]],
    producer_ref: str,
) -> None:
    """Schema 3: the six historical cells plus final-producers cells bound to producers."""
    _need(set(manifest) == TOP_KEYS_V3, f"manifest keys must be exactly {sorted(TOP_KEYS_V3)}")
    _check_registry(manifest, producer_ref)
    _check_v3_extras(manifest)
    candidates = _check_producers(manifest)
    _need(manifest["registry_profiles"] == {p: core_pins[p] for p in PROFILES},
          "registry_profiles differ from the registry core pins")
    cells = manifest["cells"]
    _need(isinstance(cells, list), "cells must be a list")
    seen: set[tuple[str, str]] = set()
    for cell in cells:
        _need(isinstance(cell, Mapping), "each cell must be a mapping")
        profile = cell.get("profile")
        _need(profile in PROFILES_V3, f"unknown profile {profile!r}")
        if profile == FINAL_PROFILE:
            key = _check_final_cell(cell, candidates)
        else:
            _need(set(cell) == CELL_KEYS, f"each cell must have exactly {sorted(CELL_KEYS)}")
            key = (profile, cell["python"])
            _need(cell["python"] in PYTHONS, f"unknown interpreter {cell['python']!r}")
            _check_pinned_cell(cell, key, core_pins, lane_files)
        _need(key not in seen, f"duplicate cell {key}")
        seen.add(key)
    required = set(itertools.product(PROFILES_V3, PYTHONS))
    _need(seen == required, f"cells must be exactly {sorted(required)}, got {sorted(seen)}")


def _schema_of(manifest: Mapping[str, Any]) -> int:
    """Return the manifest's schema or refuse it with the stable unknown-schema code."""
    schema = manifest.get("schema") if isinstance(manifest, Mapping) else None
    _need(type(schema) is int and schema in SUPPORTED_SCHEMAS,
          f"unsupported manifest schema {schema!r}; supported {list(SUPPORTED_SCHEMAS)}",
          CODE_SCHEMA_UNKNOWN)
    return schema


def validate_manifest(
    manifest: Mapping[str, Any],
    *,
    core_pins: Mapping[str, str],
    lane_files: Mapping[str, Mapping[str, str]],
    producer_ref: str,
    expected_schema: int | None = None,
    expected_digest: str | None = None,
) -> None:
    """Dispatch on the manifest schema; schema 2 rules are unchanged, schema 3 adds producers."""
    schema = _schema_of(manifest)
    _need(expected_schema is None or schema == expected_schema,
          f"gate requires schema {expected_schema}, manifest is schema {schema}",
          CODE_SCHEMA_MISMATCH)
    if expected_digest is not None:
        _need(schema == SCHEMA_V3 and canonical_digest(manifest) == expected_digest,
              "manifest digest differs from the frozen digest", CODE_DIGEST_MISMATCH)
    checker = _validate_v3 if schema == SCHEMA_V3 else _validate_v2
    checker(manifest, core_pins=core_pins, lane_files=lane_files, producer_ref=producer_ref)


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


def _matrix_row(cell: Mapping[str, Any]) -> tuple[str, str, str, bool]:
    """Project a cell to a comparable row; final-producers cells have no lane file."""
    core_file = "" if cell["profile"] == FINAL_PROFILE else cell["core_file"]
    return (cell["python"], cell["profile"], core_file, cell["require_r3"])


def validate_workflow(manifest: Mapping[str, Any], text: str) -> None:
    """The workflow matrix must contain exactly the manifest's cells, no more or fewer."""
    schema = _schema_of(manifest)
    if schema == SCHEMA:
        expected = sorted((c["python"], c["profile"], c["core_file"], c["require_r3"])
                          for c in manifest["cells"])
        actual = sorted((c["python"], c["profile"], c["core_file"], c["require_r3"])
                        for c in workflow_cells(text))
    else:
        expected = sorted(_matrix_row(c) for c in manifest["cells"])
        actual = sorted(_matrix_row(c) for c in workflow_cells(text))
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
    allowed_skips = 0 if cell["profile"] == FINAL_PROFILE else cell["max_skipped"]
    _need(totals["skipped"] <= allowed_skips,
          f"{label}: {totals['skipped']} skipped exceeds the allowance of {allowed_skips}")
