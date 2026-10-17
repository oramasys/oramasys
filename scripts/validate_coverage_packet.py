"""Validate the qualification coverage packet against the schema-3 manifest and the repository.

Usage: validate_coverage_packet.py <packet.json> <manifest.json> [--repo DIR]

The packet joins what the manifest deliberately does not carry: the exact hardware profiles, the
frozen interaction scenarios, the capability-gated modules that must be collected, the opt-in
environment gates that must be set, and the residual limits. It is bound by its own canonical digest
(printed on success) in the evidence index; the manifest needs no schema change to reference it.
Exit 0 and print the digest on success, 1 with problem lines on a refusal, 2 on a read error.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from orama.compat.interaction_risk_receipt import MANDATORY_SCENARIOS
from orama.compat.manifest import FINAL_PROFILE, canonical_digest

PACKET_VERSION = 1
AGATE_PROFILE_FIXTURE = "src/tests/fixtures/agate-hardware-profiles-172bfc3.json"
# Reviewed raw bytes from the producer candidate, not a packet-supplied trust anchor.
AGATE_PROFILE_SHA256 = "ce0eed94041e191398516958b240fb3bb838255c3644eb63bec55508e7051edc"
AGATE_PROFILE_SOURCE = {
    "repository": "oramasys/agate",
    "path": "src/agate/data/hardware_profiles.json",
    "commit": "172bfc3ebf00d507856e70d0f6a0e7dbd577ffbc",
    "sha256": AGATE_PROFILE_SHA256,
}
REQUIRED_SETUP_INPUTS = ["ORAMA_DOCS_V2_REGISTRY"]
KEYS = frozenset({
    "packet_version", "agate_profile_source", "agate_profiles", "scenarios", "required_modules",
    "required_environment", "required_capabilities", "disabled_capabilities",
    "final_cell_skips_allowed", "residual_limits", "historical_only_modules", "required_setup_inputs",
})
GATED_DIRECTORIES = (
    "src/tests/core_gate", "src/tests/agate_evidence", "src/tests/interop", "src/tests/owner_candidates",
)
_GATE = re.compile(r"ORAMA_REQUIRE_[A-Z0-9_]+")
SELF_TESTS = frozenset({"test_qualification_coverage_packet.py"})


def discovered_modules(repo: Path) -> list[str]:
    """Every test module in a capability-gated directory (collected-out where the gate is absent)."""
    found: list[str] = []
    for directory in GATED_DIRECTORIES:
        base = repo / directory
        if base.is_dir():
            found += [str(p.relative_to(repo)) for p in base.rglob("test_*.py") if p.is_file()]
    return sorted(found)


def discovered_historical_modules(repo: Path) -> list[str]:
    """Read the literal historical-only collection policy without executing conftest."""
    directory = "src/tests/core_gate"
    tree = ast.parse((repo / directory / "conftest.py").read_text(encoding="utf-8"))
    values = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "_SEAM_ABSENT_ONLY"
                      for target in node.targets)]
    if len(values) != 1:
        raise ValueError("expected one literal _SEAM_ABSENT_ONLY assignment")
    names = ast.literal_eval(values[0])
    if not (_nonblank_list(names) and len(set(names)) == len(names)
            and all(Path(name).name == name and name.startswith("test_")
                    and name.endswith(".py") for name in names)):
        raise ValueError("invalid historical-only module names")
    return sorted(f"{directory}/{name}" for name in names)


def trusted_agate_profile_ids(repo: Path) -> list[str]:
    """Return profile ids only after authenticating the pinned fixture's raw bytes."""
    raw = (repo / AGATE_PROFILE_FIXTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != AGATE_PROFILE_SHA256:
        raise ValueError("raw SHA-256 differs from the reviewed candidate fixture")
    return [profile["profile_id"] for profile in json.loads(raw)["profiles"]]


def discovered_gates(repo: Path) -> list[str]:
    """Every ORAMA_REQUIRE_* gate named by a conftest or test module (the actual inventory)."""
    names: set[str] = set()
    for path in sorted((repo / "src" / "tests").rglob("*.py")):
        if path.name in SELF_TESTS or path.name.startswith("test_harness_consumer_drift"):
            continue
        if path.name == "conftest.py" or path.name.startswith("test_"):
            names.update(_GATE.findall(path.read_text(encoding="utf-8")))
    return sorted(names)


def _nonblank_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and item.strip() for item in value)


def validate_packet(packet: object, manifest: Mapping[str, object], repo: Path) -> list[str]:
    """Return the problem lines for a packet; an empty list means it is consistent."""
    if not isinstance(packet, Mapping):
        return ["packet must be an object"]
    if not isinstance(manifest, Mapping):
        return ["manifest must be an object"]
    problems: list[str] = []
    if set(packet) != KEYS:
        problems.append(f"packet keys differ: {sorted(set(packet) ^ KEYS)}")
        return problems
    if type(packet["packet_version"]) is not int or packet["packet_version"] != PACKET_VERSION:
        problems.append("packet_version is not 1")
    profiles = packet["agate_profiles"]
    if not (_nonblank_list(profiles) and len(profiles) == 3 and len(set(profiles)) == 3):
        problems.append("agate_profiles must list exactly three distinct profile ids")
    else:
        try:
            expected_profiles = trusted_agate_profile_ids(repo)
        except (OSError, ValueError) as error:
            problems.append(f"agate profile fixture is not trusted: {error}")
        else:
            if sorted(profiles) != sorted(expected_profiles):
                problems.append("agate_profiles must equal the trusted candidate fixture's profile ids")
    source = packet["agate_profile_source"]
    producers = manifest.get("producers")
    hardware = producers.get("hardware-eligibility") if isinstance(producers, Mapping) else None
    candidate = hardware.get("candidate") if isinstance(hardware, Mapping) else None
    if source != AGATE_PROFILE_SOURCE:
        problems.append("agate_profile_source must equal the reviewed repository/path/commit/sha256 tuple")
    if candidate != AGATE_PROFILE_SOURCE["commit"]:
        problems.append("agate_profile_source.commit must equal the reviewed hardware-eligibility candidate")
    scenarios = packet["scenarios"]
    if not _nonblank_list(scenarios) or sorted(scenarios) != sorted(MANDATORY_SCENARIOS):
        problems.append("scenarios must equal the six frozen mandatory scenario ids")
    modules = packet["required_modules"]
    historical = packet["historical_only_modules"]
    if not _nonblank_list(modules) or not _nonblank_list(historical):
        problems.append("required_modules and historical_only_modules must be non-empty string lists")
    else:
        if len(set(modules)) != len(modules) or len(set(historical)) != len(historical):
            problems.append("required_modules and historical_only_modules must have no duplicates")
        if set(modules) & set(historical):
            problems.append("required_modules and historical_only_modules must be disjoint")
        if sorted(modules + historical) != discovered_modules(repo):
            problems.append("required_modules and historical_only_modules union must equal the capability-gated inventory")
        try:
            expected_historical = discovered_historical_modules(repo)
        except (OSError, SyntaxError, ValueError, TypeError) as error:
            problems.append(f"historical_only_modules policy is unreadable: {error}")
        else:
            if sorted(historical) != expected_historical:
                problems.append("historical_only_modules must equal the literal _SEAM_ABSENT_ONLY policy")
    gates = packet["required_environment"]
    if not _nonblank_list(gates) or sorted(gates) != discovered_gates(repo):
        problems.append("required_environment must equal the ORAMA_REQUIRE_* gates the tests name")
    if packet["required_setup_inputs"] != REQUIRED_SETUP_INPUTS:
        problems.append("required_setup_inputs must equal the established ORAMA_DOCS_V2_REGISTRY input")
    for key in ("required_capabilities", "disabled_capabilities"):
        if packet[key] != manifest.get(key):
            problems.append(f"{key} must equal the manifest's list")
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not all(isinstance(c, Mapping) for c in cells):
        problems.append("manifest cells must be a list of objects")
        cells = []
    final = [c for c in cells if c.get("profile") == FINAL_PROFILE]
    if (type(packet["final_cell_skips_allowed"]) is not int
            or packet["final_cell_skips_allowed"] != 0
            or any(type(c.get("max_skipped")) is not int or c.get("max_skipped") != 0 for c in final)
            or not final):
        problems.append("final-producer cells must allow exactly zero skips")
    if not _nonblank_list(packet["residual_limits"]):
        problems.append("residual_limits must be a non-empty list of statements")
    return problems


def main(argv: Sequence[str]) -> int:
    """Validate the packet; print its digest on success."""
    args = list(argv[1:])
    repo = Path(".")
    if "--repo" in args:
        index = args.index("--repo")
        if index + 1 >= len(args):
            print(__doc__, file=sys.stderr)
            return 2
        repo = Path(args[index + 1])
        del args[index:index + 2]
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        packet = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        manifest = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"unreadable: {type(error).__name__}", file=sys.stderr)
        return 2
    problems = validate_packet(packet, manifest, repo)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(canonical_digest(packet))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
