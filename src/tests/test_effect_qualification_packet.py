"""Candidate qualification preserves legacy contracts and closes effect coverage gaps."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONSUMER = "02e4f6d7b0b24a50fa3f50f11977cbccf2915bcb"
PRODUCER = "cf3a300c6d39092ab64df54f0d1ab3fea3db3c38"
EFFECT_MODULES = [
    "src/tests/effect_interop/test_signed_effect_grant.py",
    "src/tests/test_effect_grant_composition.py",
    "src/tests/test_final_boundary.py",
    "src/tests/test_inert_effect_api.py",
    "src/tests/test_inert_effect_integration.py",
    "src/tests/test_inert_effect_process_crashes.py",
    "src/tests/test_sealed_effect_qualification.py",
    "src/tests/test_sealed_inert_driver.py",
]


def load(name: str) -> ModuleType:
    """Load a repository-owned validator without modifying its behavior."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate() -> tuple[dict, dict, dict]:
    """Construct the reviewed candidate from independent legacy source documents."""
    plan = json.loads((ROOT / "requirements/final-producers-install-plan.v1.json").read_text())
    manifest = json.loads((ROOT / "requirements/compatibility-manifest.v3.json").read_text())
    packet = json.loads((ROOT / "requirements/qualification-coverage-packet.v1.json").read_text())
    plan["schema"] = 2
    plan["consumer"]["commit"] = CONSUMER
    plan["producers"]["grant-authority"]["commit"] = PRODUCER
    manifest["consumer"]["sha"] = CONSUMER
    manifest["producers"]["grant-authority"]["candidate"] = PRODUCER
    for cell in manifest["cells"]:
        if cell["profile"] == "final-producers":
            cell["candidate_set"]["grant-authority"] = PRODUCER
    packet["packet_version"] = 2
    packet["required_modules"] = sorted(packet["required_modules"] + EFFECT_MODULES)
    packet["required_environment"] = sorted(packet["required_environment"] + ["ORAMA_EFFECT_INTEROP_REQUIRED"])
    return plan, manifest, packet


def test_schema_two_emits_the_merged_producer_without_changing_legacy() -> None:
    """The new consumer tuple is valid only under the explicitly newer schema."""
    tool = load("final_set_install_plan")
    plan, manifest, _ = candidate()
    assert tool.emit_requirements(plan, manifest)[-1] == (
        "oramasys-phylax @ git+https://github.com/oramasys/phylax.git@" + PRODUCER
    )
    plan["schema"] = 1
    with pytest.raises(ValueError):
        tool.validate_plan(plan, manifest)


@pytest.mark.parametrize("mutation", ["short", "foreign", "extra", "mismatch", "schema"])
def test_schema_two_refuses_unbound_consumer(mutation: str) -> None:
    """No malformed or differently bound consumer can reuse a packet."""
    tool = load("final_set_install_plan")
    plan, manifest, _ = candidate()
    if mutation == "short":
        plan["consumer"]["commit"] = "02e4f6d"
    elif mutation == "foreign":
        plan["consumer"]["repository"] = "foreign/repo"
    elif mutation == "extra":
        plan["consumer"]["extra"] = True
    elif mutation == "mismatch":
        manifest["consumer"]["sha"] = "a" * 40
    else:
        plan["schema"] = 3
    with pytest.raises(ValueError):
        tool.validate_plan(plan, manifest)


def test_version_two_preserves_legacy_and_requires_real_effect_modules() -> None:
    """Removing effect or legacy coverage invalidates the proposed packet."""
    tool = load("validate_coverage_packet")
    _, manifest, packet = candidate()
    assert tool.validate_packet(packet, manifest, ROOT) == []
    for name in (EFFECT_MODULES[0], "src/tests/core_gate/test_delivery_seam.py"):
        changed = copy.deepcopy(packet)
        changed["required_modules"].remove(name)
        assert tool.validate_packet(changed, manifest, ROOT)
    packet["required_environment"].remove("ORAMA_EFFECT_INTEROP_REQUIRED")
    assert tool.validate_packet(packet, manifest, ROOT)


def test_collection_refuses_missing_real_effect_test_or_gate() -> None:
    """A passing legacy subset is not a passing effect qualification run."""
    tool = load("collection_gate")
    _, _, packet = candidate()
    nodes = [name + "::test_contract" for name in packet["required_modules"]]
    env = {name: "1" for name in packet["required_environment"]}
    env["ORAMA_DOCS_V2_REGISTRY"] = "registry.json"
    assert tool.check_collection(packet, nodes, env) == []
    assert tool.check_collection(packet, nodes[1:], env)
    env.pop("ORAMA_EFFECT_INTEROP_REQUIRED")
    assert tool.check_collection(packet, nodes, env)


def test_committed_candidate_documents_validate_as_one_tuple() -> None:
    """The shipped packet actually binds the intended producer, consumer and coverage."""
    base = ROOT / "requirements/effect-qualification"
    plan = json.loads((base / "install-plan.v2.json").read_text())
    manifest = json.loads((base / "manifest.v3.json").read_text())
    packet = json.loads((base / "coverage.v2.json").read_text())
    load("final_set_install_plan").validate_plan(plan, manifest)
    assert load("validate_coverage_packet").validate_packet(packet, manifest, ROOT) == []
    assert plan["consumer"]["commit"] == CONSUMER
    assert plan["producers"]["grant-authority"]["commit"] == PRODUCER


def test_dispatch_bridge_preserves_legacy_default_and_gates_candidate_evidence() -> None:
    """An unapproved PR cannot select evidence; explicit dispatch binds the new tuple."""
    import yaml

    legacy = yaml.safe_load((ROOT / ".github/workflows/final-producers.yml").read_text())
    workflow = yaml.safe_load((ROOT / ".github/workflows/final-producers-effect.yml").read_text())
    triggers = legacy.get("on", legacy.get(True))
    assert triggers["workflow_dispatch"]["inputs"]["packet"]["default"] == "legacy"
    bridge = legacy["jobs"]["effect-candidate"]
    assert bridge["uses"] == "./.github/workflows/final-producers-effect.yml"
    assert bridge["if"] == "github.event_name == 'workflow_dispatch' && inputs.packet == 'effect'"
    gate = workflow["jobs"]["freeze-gate"]["steps"][-1]
    assert gate["env"]["QUALIFICATION_PULL_REQUEST"] == "81"
    script = gate["run"]
    assert '[ "$GITHUB_EVENT_NAME" = pull_request ]' in script
    assert "qualification_approval.py verify" in script
    assert script.count('--harness "$GITHUB_SHA"') == 3
    assert "exit 1" in script
    steps = workflow["jobs"]["final-producers"]["steps"]
    checkouts = [s["with"] for s in steps if s.get("with", {}).get("path") in ("consumer", "consumer-rebuild")]
    assert len(checkouts) == 2 and all(s["ref"] == CONSUMER for s in checkouts)
    for step in steps:
        assert "${{ inputs." not in step.get("run", "")
