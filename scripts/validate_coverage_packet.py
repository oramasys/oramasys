"""Validate the qualification coverage packet against the schema-3 manifest and the repository.

Usage: validate_coverage_packet.py <packet.json> <manifest.json> [--repo DIR]

The packet joins what the manifest deliberately does not carry: the exact hardware profiles, the
frozen interaction scenarios, the capability-gated modules that must be collected, the opt-in
environment gates that must be set, and the residual limits. It is bound by its own canonical digest
(printed on success) in the evidence index; the manifest needs no schema change to reference it.
Exit 0 and print the digest on success, 1 with problem lines on a refusal, 2 on a read error.
"""
from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from orama.compat.interaction_risk_receipt import MANDATORY_SCENARIOS
from orama.compat.manifest import FINAL_PROFILE, canonical_digest

PACKET_VERSION = 1
KEYS = frozenset({
    "packet_version", "agate_profile_source", "agate_profiles", "scenarios", "required_modules",
    "required_environment", "required_capabilities", "disabled_capabilities",
    "final_cell_skips_allowed", "residual_limits",
})
GATED_DIRECTORIES = (
    "src/tests/core_gate", "src/tests/agate_evidence", "src/tests/interop", "src/tests/owner_candidates",
)
_GATE = re.compile(r"ORAMA_REQUIRE_[A-Z0-9_]+")
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
SELF_TESTS = frozenset({"test_qualification_coverage_packet.py"})


def discovered_modules(repo: Path) -> list[str]:
    """Every test module in a capability-gated directory (collected-out where the gate is absent)."""
    found: list[str] = []
    for directory in GATED_DIRECTORIES:
        base = repo / directory
        if base.is_dir():
            found += [str(p.relative_to(repo)) for p in base.glob("test_*.py")]
    return sorted(found)


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
    problems: list[str] = []
    if set(packet) != KEYS:
        problems.append(f"packet keys differ: {sorted(set(packet) ^ KEYS)}")
        return problems
    if packet["packet_version"] != PACKET_VERSION:
        problems.append("packet_version is not 1")
    profiles = packet["agate_profiles"]
    if not (_nonblank_list(profiles) and len(profiles) == 3 and len(set(profiles)) == 3):
        problems.append("agate_profiles must list exactly three distinct profile ids")
    source = packet["agate_profile_source"]
    candidate = (manifest.get("producers", {}) or {}).get("hardware-eligibility", {}).get("candidate")  # type: ignore[union-attr]
    if not (isinstance(source, Mapping) and _FULL_SHA.fullmatch(str(source.get("commit", "")))
            and source.get("commit") == candidate):
        problems.append("agate_profile_source.commit must equal the hardware-eligibility candidate")
    if sorted(packet["scenarios"]) != sorted(MANDATORY_SCENARIOS) if isinstance(
            packet["scenarios"], list) else True:
        problems.append("scenarios must equal the six frozen mandatory scenario ids")
    modules = packet["required_modules"]
    if not _nonblank_list(modules) or sorted(modules) != discovered_modules(repo):
        problems.append("required_modules must equal the capability-gated test modules on disk")
    gates = packet["required_environment"]
    if not _nonblank_list(gates) or sorted(gates) != discovered_gates(repo):
        problems.append("required_environment must equal the ORAMA_REQUIRE_* gates the tests name")
    for key in ("required_capabilities", "disabled_capabilities"):
        if packet[key] != manifest.get(key):
            problems.append(f"{key} must equal the manifest's list")
    final = [c for c in manifest.get("cells", []) if c.get("profile") == FINAL_PROFILE]  # type: ignore[union-attr]
    if packet["final_cell_skips_allowed"] != 0 or any(c.get("max_skipped") != 0 for c in final) or not final:
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
