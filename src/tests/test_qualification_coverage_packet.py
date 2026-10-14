"""The coverage packet is consistent with the manifest and the repository, and is digest-bound."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

from orama.compat.manifest import canonical_digest

ROOT = Path(__file__).resolve().parents[2]
PACKET_PATH = ROOT / "requirements" / "qualification-coverage-packet.v1.json"
MANIFEST_PATH = ROOT / "requirements" / "compatibility-manifest.v3.json"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "validate_coverage_packet", ROOT / "scripts" / "validate_coverage_packet.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_coverage_packet"] = module
    spec.loader.exec_module(module)
    return module


tool = _load()
PACKET = json.loads(PACKET_PATH.read_text())
MANIFEST = json.loads(MANIFEST_PATH.read_text())


def _problems(packet: object) -> list[str]:
    return tool.validate_packet(packet, MANIFEST, ROOT)


def test_the_committed_packet_is_consistent_with_the_manifest_and_the_repository() -> None:
    """Profiles, scenarios, modules, gates, capabilities and skip policy all agree."""
    assert _problems(PACKET) == []


def test_exactly_three_profiles_and_the_source_commit_is_the_agate_candidate() -> None:
    """The hardware profiles are those of the candidate Agate commit, and there are three."""
    assert PACKET["agate_profiles"] == ["mac-studio", "win-rtx3080", "win-rtx5080"]
    assert PACKET["agate_profile_source"]["commit"] == (
        MANIFEST["producers"]["hardware-eligibility"]["candidate"])
    changed = copy.deepcopy(PACKET)
    changed["agate_profiles"] = changed["agate_profiles"][:2]
    assert "agate_profiles must list exactly three distinct profile ids" in _problems(changed)
    changed = copy.deepcopy(PACKET)
    changed["agate_profile_source"]["commit"] = "0" * 40
    assert any("agate_profile_source.commit" in p for p in _problems(changed))


def test_the_six_scenarios_are_exactly_the_frozen_mandatory_set() -> None:
    """A missing, extra or renamed scenario is refused."""
    for mutate in (lambda s: s[:-1], lambda s: [*s, "POP-NEW-1"], lambda s: ["X", *s[1:]]):
        changed = copy.deepcopy(PACKET)
        changed["scenarios"] = mutate(changed["scenarios"])
        assert any(p.startswith("scenarios must equal") for p in _problems(changed))


def test_a_gated_module_missing_from_the_packet_is_refused() -> None:
    """Adding a capability-gated test module forces the packet to list it."""
    changed = copy.deepcopy(PACKET)
    changed["required_modules"] = changed["required_modules"][:-1]
    assert any(p.startswith("required_modules") for p in _problems(changed))
    assert all((ROOT / m).is_file() for m in PACKET["required_modules"])


def test_every_opt_in_gate_the_tests_name_is_listed() -> None:
    """The final job must set exactly the inventory of ORAMA_REQUIRE_* gates."""
    changed = copy.deepcopy(PACKET)
    changed["required_environment"] = changed["required_environment"][1:]
    assert any(p.startswith("required_environment") for p in _problems(changed))
    assert "ORAMA_REQUIRE_CLEAN_INSTALL" in PACKET["required_environment"]


def test_capabilities_and_zero_skips_must_match_the_manifest() -> None:
    """The packet cannot widen or narrow what the manifest declares."""
    changed = copy.deepcopy(PACKET)
    changed["disabled_capabilities"] = changed["disabled_capabilities"][:-1]
    assert any(p.startswith("disabled_capabilities") for p in _problems(changed))
    changed = copy.deepcopy(PACKET)
    changed["final_cell_skips_allowed"] = 1
    assert "final-producer cells must allow exactly zero skips" in _problems(changed)


def test_unknown_keys_and_a_non_object_are_refused() -> None:
    """The packet shape is closed, like the manifest's."""
    assert _problems([]) == ["packet must be an object"]
    changed = copy.deepcopy(PACKET)
    changed["extra"] = 1
    assert any(p.startswith("packet keys differ") for p in _problems(changed))


def test_the_digest_is_canonical_and_changes_with_any_content() -> None:
    """The digest is what the evidence index binds; key order must not matter."""
    reordered = dict(reversed(list(PACKET.items())))
    assert canonical_digest(reordered) == canonical_digest(PACKET)
    changed = copy.deepcopy(PACKET)
    changed["residual_limits"] = [*changed["residual_limits"], "another limit"]
    assert canonical_digest(changed) != canonical_digest(PACKET)
