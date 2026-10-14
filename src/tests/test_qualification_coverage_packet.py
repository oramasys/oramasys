"""The coverage packet is consistent with the manifest and the repository, and is digest-bound."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

from orama.compat.manifest import canonical_digest

ROOT = Path(__file__).resolve().parents[2]
PACKET_PATH = ROOT / "requirements" / "qualification-coverage-packet.v1.json"
MANIFEST_PATH = ROOT / "requirements" / "compatibility-manifest.v3.json"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "validate_coverage_packet", ROOT / "scripts" / "validate_coverage_packet.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_coverage_packet"] = module
    spec.loader.exec_module(module)
    return module


tool = _load()
PACKET = json.loads(PACKET_PATH.read_text())
MANIFEST = json.loads(MANIFEST_PATH.read_text())
HISTORICAL = "src/tests/core_gate/test_start_seam_absent.py"
AGATE_FIXTURE = "src/tests/fixtures/agate-hardware-profiles-172bfc3.json"
AGATE_SHA256 = "ce0eed94041e191398516958b240fb3bb838255c3644eb63bec55508e7051edc"


def _partitioned_packet() -> dict:
    packet = copy.deepcopy(PACKET)
    packet["required_modules"] = [
        m for m in packet["required_modules"] if m != HISTORICAL
    ]
    packet["historical_only_modules"] = [HISTORICAL]
    packet["required_setup_inputs"] = ["ORAMA_DOCS_V2_REGISTRY"]
    return packet


@pytest.fixture
def evidence_repo(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "src/tests", tmp_path / "src/tests")
    return tmp_path


def test_trusted_fixture_bytes_and_exact_profile_ids() -> None:
    raw = (ROOT / AGATE_FIXTURE).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == AGATE_SHA256
    assert [p["profile_id"] for p in json.loads(raw)["profiles"]] == PACKET[
        "agate_profiles"
    ]
    assert PACKET["agate_profile_source"]["sha256"] == AGATE_SHA256
    assert tool.trusted_agate_profile_ids(ROOT) == PACKET["agate_profiles"]
    assert tool.discovered_historical_modules(ROOT) == [HISTORICAL]
    assert PACKET["required_setup_inputs"] == ["ORAMA_DOCS_V2_REGISTRY"]
    assert _problems(_partitioned_packet()) == []


@pytest.mark.parametrize(
    "profiles",
    [
        ["invented-a", "invented-b", "invented-c"],
        ["mac-studio", "win-rtx3080", "invented-c"],
        ["mac-studio", "win-rtx3080", "win-rtx3080"],
    ],
)
def test_same_cardinality_profile_substitutions_are_refused(
    profiles: list[str],
) -> None:
    packet = _partitioned_packet()
    packet["agate_profiles"] = profiles
    assert any(p.startswith("agate_profiles") for p in _problems(packet))


@pytest.mark.parametrize(
    "key,value",
    [
        ("repository", "not-agate"),
        ("path", "other.json"),
        ("commit", "0" * 40),
        ("extra", "untrusted"),
        ("sha256", "0" * 64),
    ],
)
def test_profile_source_tuple_is_closed_and_exact(key: str, value: str) -> None:
    packet = _partitioned_packet()
    packet["agate_profile_source"][key] = value
    assert any(p.startswith("agate_profile_source") for p in _problems(packet))


@pytest.mark.parametrize("source", [None, [], {}, "not-a-source"])
def test_malformed_profile_source_is_refused(source: object) -> None:
    packet = _partitioned_packet()
    packet["agate_profile_source"] = source
    assert any(p.startswith("agate_profile_source") for p in _problems(packet))


def test_unreviewed_candidate_cannot_reanchor_the_profile_source() -> None:
    packet = _partitioned_packet()
    manifest = copy.deepcopy(MANIFEST)
    packet["agate_profile_source"]["commit"] = "0" * 40
    manifest["producers"]["hardware-eligibility"]["candidate"] = "0" * 40
    assert any(
        p.startswith("agate_profile_source")
        for p in tool.validate_packet(packet, manifest, ROOT)
    )


@pytest.mark.parametrize("mutation", ["missing", "whitespace", "profile", "malformed"])
def test_missing_or_changed_trusted_fixture_is_refused(
    evidence_repo: Path, mutation: str
) -> None:
    path = evidence_repo / AGATE_FIXTURE
    if mutation == "missing":
        path.unlink()
    elif mutation == "whitespace":
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "profile":
        data = json.loads(path.read_bytes())
        data["profiles"][0]["profile_id"] = "invented-a"
        path.write_text(json.dumps(data))
    else:
        path.write_bytes(b"{")
    assert any(
        p.startswith("agate profile fixture")
        for p in tool.validate_packet(_partitioned_packet(), MANIFEST, evidence_repo)
    )


def test_committed_partition_has_exact_historical_module() -> None:
    assert PACKET["historical_only_modules"] == [HISTORICAL]
    assert HISTORICAL not in PACKET["required_modules"]
    assert sorted(PACKET["required_modules"] + PACKET["historical_only_modules"]) == (
        tool.discovered_modules(ROOT)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "overlap",
        "required-duplicate",
        "historical-duplicate",
        "missing",
        "wrong-historical",
        "non-list",
    ],
)
def test_module_partition_mutations_are_refused(mutation: str) -> None:
    packet = _partitioned_packet()
    if mutation == "overlap":
        packet["required_modules"].append(HISTORICAL)
    elif mutation == "required-duplicate":
        packet["required_modules"].append(packet["required_modules"][0])
    elif mutation == "historical-duplicate":
        packet["historical_only_modules"].append(HISTORICAL)
    elif mutation == "missing":
        packet["required_modules"].pop()
    elif mutation == "wrong-historical":
        packet["historical_only_modules"] = [packet["required_modules"].pop()]
        packet["required_modules"].append(HISTORICAL)
    else:
        packet["required_modules"] = [None]
    assert any("modules" in p for p in _problems(packet))


def test_new_nested_module_requires_explicit_partition(evidence_repo: Path) -> None:
    relative = "src/tests/core_gate/nested/test_new.py"
    path = evidence_repo / relative
    path.parent.mkdir()
    path.write_text("def test_new(): pass\n")
    packet = _partitioned_packet()
    assert any(
        "modules" in p for p in tool.validate_packet(packet, MANIFEST, evidence_repo)
    )
    packet["required_modules"].append(relative)
    assert tool.validate_packet(packet, MANIFEST, evidence_repo) == []


def test_historical_policy_is_read_literally_without_execution(
    evidence_repo: Path,
) -> None:
    path = evidence_repo / "src/tests/core_gate/conftest.py"
    path.write_text(
        "raise RuntimeError('must not execute')\n"
        "_SEAM_ABSENT_ONLY = ['test_start_seam_absent.py']\n"
    )
    assert tool.validate_packet(_partitioned_packet(), MANIFEST, evidence_repo) == []


@pytest.mark.parametrize(
    "policy",
    [
        "_SEAM_ABSENT_ONLY = compute_modules()",
        "_SEAM_ABSENT_ONLY = [None]",
        "_SEAM_ABSENT_ONLY = ['../test_outside.py']",
        "_SEAM_ABSENT_ONLY = ['test_start_seam_absent.py'] * 2",
        "_SEAM_ABSENT_ONLY = []",
        "# missing assignment",
        "_SEAM_ABSENT_ONLY = [",
    ],
)
def test_malformed_historical_policy_fails_closed(
    evidence_repo: Path, policy: str
) -> None:
    (evidence_repo / "src/tests/core_gate/conftest.py").write_text(policy)
    assert any(
        p.startswith("historical_only_modules")
        for p in tool.validate_packet(_partitioned_packet(), MANIFEST, evidence_repo)
    )


@pytest.mark.parametrize(
    "inputs",
    [
        [],
        ["ORAMA_REQUIRE_CORE_GATE"],
        ["ORAMA_DOCS_V2_REGISTRY", "EXTRA"],
        ["ORAMA_DOCS_V2_REGISTRY"] * 2,
        None,
    ],
)
def test_setup_inputs_are_exact_and_separate(inputs: object) -> None:
    packet = _partitioned_packet()
    packet["required_setup_inputs"] = inputs
    assert any(p.startswith("required_setup_inputs") for p in _problems(packet))


@pytest.mark.parametrize(
    "scenarios",
    [
        None,
        1,
        "POP-CASCADE-1",
        {},
        [],
        [1, *PACKET["scenarios"][1:]],
        [None],
        [{}],
        [[]],
        [False],
        PACKET["scenarios"] * 2,
    ],
)
def test_malformed_scenarios_return_controlled_problems(scenarios: object) -> None:
    packet = _partitioned_packet()
    packet["scenarios"] = scenarios
    assert any(p.startswith("scenarios must equal") for p in _problems(packet))


@pytest.mark.parametrize(
    "key,value",
    [
        ("packet_version", True),
        ("packet_version", False),
        ("packet_version", 1.0),
        ("final_cell_skips_allowed", False),
        ("final_cell_skips_allowed", 0.0),
    ],
)
def test_packet_integer_fields_do_not_accept_booleans_or_floats(
    key: str, value: object
) -> None:
    packet = _partitioned_packet()
    packet[key] = value
    expected = (
        "packet_version is not 1"
        if key == "packet_version"
        else "final-producer cells must allow exactly zero skips"
    )
    assert expected in _problems(packet)


@pytest.mark.parametrize("value", [False, 0.0, 1])
def test_final_manifest_skip_policy_is_exact_integer_zero(value: object) -> None:
    manifest = copy.deepcopy(MANIFEST)
    manifest["cells"][-1]["max_skipped"] = value
    assert "final-producer cells must allow exactly zero skips" in (
        tool.validate_packet(_partitioned_packet(), manifest, ROOT)
    )


def test_cli_malformed_scenarios_are_a_controlled_refusal(
    tmp_path: Path, capsys
) -> None:
    packet = _partitioned_packet()
    packet["scenarios"] = [1, *PACKET["scenarios"][1:]]
    path = tmp_path / "packet.json"
    path.write_text(json.dumps(packet))
    assert (
        tool.main(["validator", str(path), str(MANIFEST_PATH), "--repo", str(ROOT)])
        == 1
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert "scenarios must equal" in output.err
    assert "Traceback" not in output.err


def _problems(packet: object) -> list[str]:
    return tool.validate_packet(packet, MANIFEST, ROOT)


def test_the_committed_packet_is_consistent_with_the_manifest_and_the_repository() -> (
    None
):
    """Profiles, scenarios, modules, gates, capabilities and skip policy all agree."""
    assert _problems(PACKET) == []


def test_exactly_three_profiles_and_the_source_commit_is_the_agate_candidate() -> None:
    """The hardware profiles are those of the candidate Agate commit, and there are three."""
    assert PACKET["agate_profiles"] == ["mac-studio", "win-rtx3080", "win-rtx5080"]
    assert (
        PACKET["agate_profile_source"]["commit"]
        == (MANIFEST["producers"]["hardware-eligibility"]["candidate"])
    )
    changed = copy.deepcopy(PACKET)
    changed["agate_profiles"] = changed["agate_profiles"][:2]
    assert "agate_profiles must list exactly three distinct profile ids" in _problems(
        changed
    )
    changed = copy.deepcopy(PACKET)
    changed["agate_profile_source"]["commit"] = "0" * 40
    assert any(p.startswith("agate_profile_source") for p in _problems(changed))


def test_the_six_scenarios_are_exactly_the_frozen_mandatory_set() -> None:
    """A missing, extra or renamed scenario is refused."""
    for mutate in (
        lambda s: s[:-1],
        lambda s: [*s, "POP-NEW-1"],
        lambda s: ["X", *s[1:]],
    ):
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
