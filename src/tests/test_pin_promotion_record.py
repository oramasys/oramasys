"""The generation-2 promotion record agrees with every place it describes.

The record links the active generation to an immutable rollback target. It must agree with
the active manifest, the package dependencies, the registry snapshots and the archived
generation 1. Its status is a label that matches what main installs (``pins-merged``); serving
activation and T3 are separate switches listed in ``still_off``. The approved manifest keeps its
frozen pre-merge labels, which the record explicitly supersedes.
"""
from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

from orama.compat.manifest import canonical_digest
from tests.test_compatibility_pins import producer_refs

ROOT = Path(__file__).resolve().parents[2]
REQ = ROOT / "requirements"
RECORD = json.loads((REQ / "pin-promotion-record.v1.json").read_text(encoding="utf-8"))
MANIFEST = json.loads((REQ / "compatibility-manifest.v3.json").read_text(encoding="utf-8"))
FIXTURES = ROOT / "src" / "tests" / "fixtures"


def test_record_says_pins_are_merged_and_names_what_stays_off() -> None:
    """The status is a label that must match what main installs; serving and T3 stay separate."""
    assert RECORD["schema"] == 1 and RECORD["generation"] == "m1-gen2"
    assert RECORD["status"] == "pins-merged"
    assert RECORD["pins_merged"] == {
        "orama_system_pr": 414, "oramasys_consumer_pr": 53, "oramasys_harness_pr": 55}
    assert {"serving", "t3", "t4", "t5"} <= set(RECORD["still_off"])
    assert "authorizes nothing" not in RECORD["scope"], "stale: the pins are already installed"


def test_frozen_manifest_keeps_its_original_labels_and_the_record_supersedes_them() -> None:
    """The approved manifest is never edited; its pre-merge capability label is superseded here."""
    assert "production-pin-promotion" in MANIFEST["disabled_capabilities"]
    assert RECORD["supersedes_frozen_labels"] == ["production-pin-promotion"]


def test_promoted_pins_are_the_active_manifest_and_package_pins() -> None:
    deps = "\n".join(tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"])
    for role, move in RECORD["promoted"].items():
        entry = MANIFEST["producers"][role]
        assert entry["production_pin"] == entry["candidate"] == move["to"]
        assert move["from"] != move["to"]
        assert f"@{move['to']}" in deps and f"@{move['from']}" not in deps
    phylax = RECORD["unchanged"]["grant-authority"]
    assert MANIFEST["producers"]["grant-authority"]["candidate"] == phylax["pin"]


def test_registry_move_matches_the_snapshots_and_the_workflow_ref() -> None:
    reg = RECORD["registry"]
    assert MANIFEST["producer_registry"] == {"repository": reg["repository"], "ref": reg["to_ref"]}
    assert {ref for refs in producer_refs().values() for ref in refs} == {reg["to_ref"]}
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()  # noqa: E731
    assert digest(FIXTURES / "graph-ownership-registry.json") == reg["to_sha256"]
    assert digest(FIXTURES / "graph-ownership-registry-m1-gen1.json") == reg["from_sha256"]


def test_consumer_move_matches_the_manifest_and_the_archive() -> None:
    assert MANIFEST["consumer"]["sha"] == RECORD["consumer"]["to"]
    rollback = RECORD["rollback"]
    assert RECORD["consumer"]["from"] == rollback["consumer_commit"]


def test_rollback_target_is_the_archived_generation_one() -> None:
    rollback = RECORD["rollback"]
    archive = ROOT / rollback["archive"]
    gen1 = json.loads((archive / "compatibility-manifest.v3.json").read_text(encoding="utf-8"))
    coverage = json.loads((archive / "qualification-coverage-packet.v1.json").read_text())
    assert canonical_digest(gen1) == rollback["manifest_digest"]
    assert canonical_digest(coverage) == rollback["coverage_digest"]
    assert gen1["consumer"]["sha"] == rollback["consumer_commit"]
    for role, move in RECORD["promoted"].items():
        assert gen1["producers"][role]["production_pin"] == move["from"]
    assert (ROOT / rollback["registry_archive"]).is_file()
    assert rollback["conditions"] and rollback["procedure"]
