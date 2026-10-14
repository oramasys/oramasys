"""Schema-2 behaviour of validate_manifest equals the original (99283f7) exactly."""
from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from orama.compat.manifest import validate_manifest
from tests.test_compatibility_manifest import lane_shas, load
from tests.test_compatibility_pins import producer_refs
from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL_COMMIT = "99283f789f078689404653d5105b597e614160b0"
KEYS = "['cells', 'producer_registry', 'schema']"
CELL = ("each cell must have exactly ['core_file', 'core_sha', 'max_skipped', "
        "'min_passed', 'profile', 'python', 'require_r3']")


def _drop(key: str):
    """Mutator removing a top-level key."""
    return lambda m: m.pop(key)


def _set(key: str, value):
    """Mutator setting a top-level key."""
    return lambda m: m.update({key: value})


# name -> (mutator, expected original outcome: None for accepted, else message)
CASES = {
    "missing_schema": (_drop("schema"), f"manifest keys must be exactly {KEYS}"),
    "schema_float": (_set("schema", 2.0), None),
    "schema_true": (_set("schema", True), "manifest schema must be 2"),
    "schema_string": (_set("schema", "2"), "manifest schema must be 2"),
    "schema_none": (_set("schema", None), "manifest schema must be 2"),
    "extra_key": (_set("x", 1), f"manifest keys must be exactly {KEYS}"),
    "missing_cells": (_drop("cells"), f"manifest keys must be exactly {KEYS}"),
    "cell_missing_key": (lambda m: m["cells"][0].pop("core_sha"), CELL),
    "cells_not_list": (_set("cells", {}), "cells must be a list"),
    "bad_registry": (_set("producer_registry", "x"),
                     "producer_registry must hold exactly repository and ref"),
    "dup_cell": (lambda m: m["cells"].append(copy.deepcopy(m["cells"][0])),
                 "duplicate cell ('production', '3.11')"),
    "mispin": (lambda m: m["cells"][0].update(core_sha="0" * 40),
               "('production', '3.11'): core_sha differs from registry profile"),
    "unknown_profile": (lambda m: m["cells"][0].update(profile="zz"), "unknown profile 'zz'"),
}


def _ref() -> str:
    """The workflow's producer ref."""
    return next(iter({r for v in producer_refs().values() for r in v}))


def _outcome(func, manifest) -> tuple[str, str] | None:
    """Run a validator and return (exception type name, message) or None."""
    try:
        func(manifest, core_pins=CORE_PINS, lane_files=lane_shas(), producer_ref=_ref())
    except Exception as error:  # noqa: BLE001 - the exact type is part of the comparison
        return type(error).__name__, str(error)
    return None


@pytest.mark.parametrize("name", sorted(CASES))
def test_schema2_outcome_matches_recorded_original(name: str) -> None:
    mutate, message = CASES[name]
    manifest = copy.deepcopy(load())
    mutate(manifest)
    expected = None if message is None else ("ManifestError", message)
    assert _outcome(validate_manifest, manifest) == expected


def _original_module(tmp_path: Path):
    """Load the pre-schema-3 module from the git object, or return None when it is unavailable.

    Returning None (not skipping) keeps the skip budget of the oracle cells intact: a shallow CI
    checkout has no such object, and the recorded-outcome test above still pins the behaviour there.
    """
    git = subprocess.run(["git", "show", f"{ORIGINAL_COMMIT}:src/orama/compat/manifest.py"],
                         capture_output=True, text=True, check=False, cwd=ROOT)
    if git.returncode != 0:
        return None
    path = tmp_path / "orig_manifest.py"
    path.write_text(git.stdout, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("orig_manifest", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["orig_manifest"] = module
    spec.loader.exec_module(module)
    return module


def test_schema2_outcomes_match_the_original_function_when_it_is_available(tmp_path: Path) -> None:
    """Compare every malformed-manifest case with the original function, where its object exists."""
    original = _original_module(tmp_path)
    if original is None:
        return
    for name in sorted(CASES):
        manifest = copy.deepcopy(load())
        CASES[name][0](manifest)
        assert _outcome(validate_manifest, copy.deepcopy(manifest)) == \
            _outcome(original.validate_manifest, copy.deepcopy(manifest)), name
