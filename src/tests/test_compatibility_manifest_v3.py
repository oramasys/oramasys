"""Schema-3 manifest: dispatch on schema, schema 2 untouched, schema 3 adds producer binding."""
from __future__ import annotations

import copy

import pytest

from orama.compat.manifest import (
    ManifestError,
    canonical_digest,
    check_cell_results,
    validate_manifest,
    validate_workflow,
)
from tests.test_compatibility_manifest import check, lane_shas, load
from tests.test_compatibility_pins import producer_refs
from tests.test_ownership_registry import CORE_PINS

CONTRACTS = ["M1-Q-MANIFEST-1", "M1-Q-INSTALL-1", "M1-Q-DELIVERY-1", "M1-Q-ACCOUNTING-1",
             "M1-Q-COMPOSITION-1", "COLLAB-HANDOFF-1", "INTERACTION-RISK-ASSESSMENT-1"]
ROLES = {"neutral-mechanics": "a", "endpoint-policy": "b", "hardware-eligibility": "c",
         "grant-authority": "d"}


def producers(candidates: dict) -> dict:
    """Producer entries: distinct pins, the core producer's bound to the registry pin."""
    out = {}
    for role, sha in candidates.items():
        entry = {"candidate": sha, "declared_dependency": role != "grant-authority"}
        if role != "grant-authority":
            entry["production_pin"] = ("1" * 40 if role != "neutral-mechanics"
                                       else CORE_PINS["production"])
        out[role] = entry
    return out


def v3() -> dict:
    """Build a valid schema-3 manifest from the committed schema-2 one."""
    base = copy.deepcopy(load())
    candidates = {role: ch * 40 for role, ch in ROLES.items()}
    final = [{"profile": "final-producers", "python": py, "require_r3": False,
              "min_passed": 1, "max_skipped": 0, "candidate_set": dict(candidates)}
             for py in ("3.11", "3.12")]
    return {
        "schema": 3,
        "producer_registry": base["producer_registry"],
        "cells": base["cells"] + final,
        "consumer": {"repository": "oramasys/oramasys", "sha": "e" * 40},
        "producers": producers(candidates),
        "registry_profiles": dict(CORE_PINS),
        "artifacts": {"install_mode": "wheel"},
        "environments": {"gating": "ubuntu"},
        "required_capabilities": ["seam-positive"],
        "disabled_capabilities": ["t3-implementation"],
        "source_contracts": {"mode": "read-only-source-tree"},
        "contract_ids": list(CONTRACTS),
    }


def check3(manifest: dict, **kw) -> None:
    """Validate a schema-3 manifest against the real pins."""
    validate_manifest(manifest, core_pins=CORE_PINS, lane_files=lane_shas(),
                      producer_ref=next(iter({r for v in producer_refs().values() for r in v})),
                      **kw)


def test_valid_schema3_manifest_passes() -> None:
    check3(v3())


def test_schema2_manifest_still_validates_unchanged() -> None:
    check(load())


def test_unknown_schema_is_refused_with_stable_code() -> None:
    for bad in (1, 4):
        manifest = v3()
        manifest["schema"] = bad
        with pytest.raises(ManifestError) as info:
            check3(manifest)
        assert info.value.code == "manifest-schema-unknown"


def test_non_int_schema_takes_the_original_schema2_path() -> None:
    """Non-int schemas are not "unknown": the untouched schema-2 path refuses them."""
    for bad in ("3", None, True):
        manifest = v3()
        manifest["schema"] = bad
        with pytest.raises(ManifestError) as info:
            check3(manifest)
        assert info.value.code == "manifest-invalid"


def test_schema3_relabelled_as_schema2_is_rejected() -> None:
    manifest = v3()
    manifest["schema"] = 2
    with pytest.raises(ManifestError):
        check3(manifest)


def test_schema2_relabelled_as_schema3_is_rejected() -> None:
    manifest = copy.deepcopy(load())
    manifest["schema"] = 3
    with pytest.raises(ManifestError):
        check3(manifest)


def test_gate_pinned_to_schema2_refuses_schema3() -> None:
    with pytest.raises(ManifestError) as info:
        check3(v3(), expected_schema=2)
    assert info.value.code == "manifest-schema-mismatch"


def test_gate_pinned_to_schema3_refuses_schema2() -> None:
    with pytest.raises(ManifestError) as info:
        validate_manifest(load(), core_pins=CORE_PINS, lane_files=lane_shas(),
                          producer_ref=load()["producer_registry"]["ref"], expected_schema=3)
    assert info.value.code == "manifest-schema-mismatch"


def test_digest_binding_accepts_matching_and_rejects_other() -> None:
    manifest = v3()
    check3(manifest, expected_digest=canonical_digest(manifest))
    with pytest.raises(ManifestError) as info:
        check3(manifest, expected_digest="0" * 64)
    assert info.value.code == "manifest-digest-mismatch"


def test_canonical_digest_is_key_order_independent_and_content_sensitive() -> None:
    manifest = v3()
    reordered = dict(reversed(list(manifest.items())))
    assert canonical_digest(manifest) == canonical_digest(reordered)
    changed = v3()
    changed["consumer"]["sha"] = "f" * 40
    assert canonical_digest(changed) != canonical_digest(manifest)


@pytest.mark.parametrize("name, change", [
    ("missing top key", lambda m: m.pop("producers")),
    ("unknown top key", lambda m: m.update(extra=1)),
    ("missing final cell", lambda m: m["cells"].pop()),
    ("duplicate final cell", lambda m: m["cells"].append(copy.deepcopy(m["cells"][-1]))),
    ("historical cell dropped", lambda m: m["cells"].pop(0)),
    ("historical mispin", lambda m: m["cells"][0].update(core_sha="0" * 40)),
    ("final cell wrong key", lambda m: m["cells"][-1].update(core_sha="a" * 40)),
    ("final cell skips allowed", lambda m: m["cells"][-1].update(max_skipped=1)),
    ("candidate set mismatch", lambda m: m["cells"][-1]["candidate_set"].update(
        {"endpoint-policy": "9" * 40})),
    ("candidate set missing role", lambda m: m["cells"][-1]["candidate_set"].pop("grant-authority")),
    ("candidate set extra role", lambda m: m["cells"][-1]["candidate_set"].update(x="1" * 40)),
    ("short candidate", lambda m: m["producers"]["endpoint-policy"].update(candidate="abc")),
    ("composition declared as dependency", lambda m: m["producers"]["grant-authority"].update(
        declared_dependency=True)),
    ("composition with production pin", lambda m: m["producers"]["grant-authority"].update(
        production_pin="1" * 40)),
    ("pin zeroed", lambda m: m["producers"]["endpoint-policy"].update(production_pin="0" * 40)),
    ("pin deleted", lambda m: m["producers"]["endpoint-policy"].pop("production_pin")),
    ("pin equals candidate", lambda m: m["producers"]["endpoint-policy"].update(
        production_pin=m["producers"]["endpoint-policy"]["candidate"])),
    ("equal flag but differ", lambda m: m["producers"]["endpoint-policy"].update(
        candidate_equals_pin=True)),
    ("equal flag not bool", lambda m: m["producers"]["endpoint-policy"].update(
        candidate_equals_pin="yes")),
    ("composition equal flag", lambda m: m["producers"]["grant-authority"].update(
        candidate_equals_pin=True)),
    ("core pin differs from registry", lambda m: m["producers"]["neutral-mechanics"].update(
        production_pin="7" * 40)),
    ("missing producer role", lambda m: m["producers"].pop("hardware-eligibility")),
    ("consumer short sha", lambda m: m["consumer"].update(sha="abc")),
    ("registry profile drift", lambda m: m["registry_profiles"].update(production="0" * 40)),
    ("contract ids incomplete", lambda m: m["contract_ids"].pop()),
    ("contract ids duplicated", lambda m: m["contract_ids"].append("COLLAB-HANDOFF-1")),
    ("empty disabled capabilities", lambda m: m.update(disabled_capabilities=[])),
    ("wrong producer repository", lambda m: m["producer_registry"].update(repository="x/y")),
])
def test_schema3_rejects(name: str, change) -> None:
    manifest = v3()
    change(manifest)
    with pytest.raises(ManifestError):
        check3(manifest)


def test_pin_equal_to_candidate_allowed_with_explicit_flag() -> None:
    manifest = v3()
    entry = manifest["producers"]["endpoint-policy"]
    entry.update(production_pin=entry["candidate"], candidate_equals_pin=True)
    check3(manifest)


def test_core_producer_pin_is_bound_to_registry_production_pin() -> None:
    check3(v3())


def test_consumer_sha_is_bound() -> None:
    manifest = v3()
    check3(manifest, consumer_sha="e" * 40)
    with pytest.raises(ManifestError) as info:
        check3(manifest, consumer_sha="f" * 40)
    assert info.value.code == "manifest-consumer-mismatch"


def test_consumer_sha_cannot_bind_schema2() -> None:
    with pytest.raises(ManifestError) as info:
        validate_manifest(load(), core_pins=CORE_PINS, lane_files=lane_shas(),
                          producer_ref=load()["producer_registry"]["ref"], consumer_sha="e" * 40)
    assert info.value.code == "manifest-consumer-mismatch"


def test_canonical_digest_refuses_nan_and_lone_surrogate() -> None:
    for bad in (float("nan"), "\ud800"):
        manifest = v3()
        manifest["artifacts"]["x"] = bad
        with pytest.raises(ManifestError) as info:
            canonical_digest(manifest)
        assert info.value.code == "manifest-invalid"


def test_workflow_validated_against_schema3_cells() -> None:
    text = (
        '          - python-version: "3.11"\n            profile: production\n'
        "            core-file: requirements/compatibility-core-production.txt\n"
        '            require-r3: "1"\n'
        '          - python-version: "3.12"\n            profile: final-producers\n'
        "            core-file: none\n"
        '            require-r3: "0"\n')
    manifest = v3()
    manifest["cells"] = [c for c in manifest["cells"]
                         if (c["profile"], c["python"]) in
                         {("production", "3.11"), ("final-producers", "3.12")}]
    validate_workflow(manifest, text)
    with pytest.raises(ManifestError):
        validate_workflow(manifest, text.replace('"0"', '"1"'))


def test_workflow_rejects_unknown_schema() -> None:
    manifest = v3()
    manifest["schema"] = 9
    with pytest.raises(ManifestError) as info:
        validate_workflow(manifest, "")
    assert info.value.code == "manifest-schema-unknown"


def test_result_gate_allows_no_skips_for_final_producers_cells() -> None:
    xml = '<testsuite tests="3" failures="0" errors="0" skipped="1"/>'
    cell = {"profile": "final-producers", "python": "3.12", "min_passed": 1, "max_skipped": 5}
    with pytest.raises(ManifestError):
        check_cell_results(xml, cell)
    check_cell_results(xml, {**cell, "profile": "production"})
