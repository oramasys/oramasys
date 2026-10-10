"""The six-cell compatibility manifest is the one declaration of what P0 must run.

A hand-written workflow matrix can silently lose a cell. The manifest names every
(profile, interpreter) cell with its immutable Core revision; validation rejects any
missing, duplicate, extra, or mispinned cell, and the workflow must match it exactly.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from orama.compat.manifest import (
    ManifestError,
    validate_manifest,
    validate_workflow,
    workflow_cells,
)
from tests.test_compatibility_pins import LANE_FILES, producer_refs
from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "requirements" / "compatibility-manifest.json"
ORACLES = ROOT / ".github" / "workflows" / "compatibility-oracles.yml"


def load() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def lane_shas() -> dict[str, dict[str, str]]:
    return {p: {"path": f"requirements/{n}",
                "sha": (ROOT / "requirements" / n).read_text(encoding="utf-8").strip()}
            for p, n in LANE_FILES.items()}


def check(manifest: dict) -> None:
    validate_manifest(manifest, core_pins=CORE_PINS, lane_files=lane_shas(),
                      producer_ref=next(iter({r for v in producer_refs().values() for r in v})))


def test_committed_manifest_is_valid_and_has_exactly_six_cells() -> None:
    manifest = load()
    check(manifest)
    assert len(manifest["cells"]) == 6
    assert {(c["profile"], c["python"]) for c in manifest["cells"]} == {
        (p, v) for p in LANE_FILES for v in ("3.11", "3.12")}


def test_oracle_workflow_matches_the_manifest_exactly() -> None:
    validate_workflow(load(), ORACLES.read_text(encoding="utf-8"))


def mutated(fn) -> dict:
    manifest = copy.deepcopy(load())
    fn(manifest)
    return manifest


@pytest.mark.parametrize("name, change", [
    ("missing cell", lambda m: m["cells"].pop()),
    ("duplicate cell", lambda m: m["cells"].append(copy.deepcopy(m["cells"][0]))),
    ("extra cell", lambda m: m["cells"].append(
        {**m["cells"][0], "python": "3.13"})),
    ("wrong core sha", lambda m: m["cells"][0].update(core_sha="0" * 40)),
    ("short core sha", lambda m: m["cells"][0].update(core_sha=m["cells"][0]["core_sha"][:12])),
    ("wrong lane file", lambda m: m["cells"][0].update(core_file="requirements/other.txt")),
    ("unknown profile", lambda m: m["cells"][0].update(profile="mystery")),
    ("unknown cell key", lambda m: m["cells"][0].update(skip=True)),
    ("unknown top-level key", lambda m: m.update(extra=1)),
    ("old schema", lambda m: m.update(schema=1)),
    ("future schema", lambda m: m.update(schema=3)),
    ("mutable producer ref", lambda m: m["producer_registry"].update(ref="main")),
    ("other producer ref", lambda m: m["producer_registry"].update(ref="1" * 40)),
    ("wrong repository", lambda m: m["producer_registry"].update(repository="x/y")),
    ("non-boolean require_r3", lambda m: m["cells"][0].update(require_r3="1")),
])
def test_manifest_rejects(name: str, change) -> None:
    with pytest.raises(ManifestError):
        check(mutated(change))


def test_manifest_rejects_a_lane_file_that_drifted_from_its_cell() -> None:
    shas = lane_shas()
    shas["production"]["sha"] = "2" * 40
    with pytest.raises(ManifestError):
        validate_manifest(load(), core_pins=CORE_PINS, lane_files=shas,
                          producer_ref=load()["producer_registry"]["ref"])


def test_workflow_cells_parses_every_matrix_entry() -> None:
    cells = workflow_cells(ORACLES.read_text(encoding="utf-8"))
    assert len(cells) == 6
    assert all(set(c) == {"python", "profile", "core_file", "require_r3"} for c in cells)


@pytest.mark.parametrize("name, edit", [
    ("dropped cell", lambda t: t.replace(
        '          - python-version: "3.11"\n            profile: production\n'
        '            core-file: requirements/compatibility-core-production.txt\n'
        '            require-r3: "1"\n', "")),
    ("flipped require-r3", lambda t: re.sub(
        r'(profile: production\n\s+core-file: \S+\n\s+require-r3: )"1"', r'\1"0"', t, count=1)),
    ("swapped lane file", lambda t: t.replace(
        "core-file: requirements/compatibility-core-candidate.txt",
        "core-file: requirements/compatibility-core-production.txt", 1)),
    ("changed interpreter", lambda t: t.replace('python-version: "3.12"', 'python-version: "3.13"', 1)),
])
def test_workflow_rejects(name: str, edit) -> None:
    text = ORACLES.read_text(encoding="utf-8")
    broken = edit(text)
    assert broken != text, f"mutation {name} did not change the workflow"
    with pytest.raises(ManifestError):
        validate_workflow(load(), broken)
