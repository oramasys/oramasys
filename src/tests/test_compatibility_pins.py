"""One immutable pin per dependency edge: no second pin table can drift silently.

P0 qualification binds evidence to exact revisions. The producer registry checkout
and each Core lane must therefore be named once, as full commit SHAs, and every
place that repeats a pin must agree with it. Decisions: D-LG-7 P0 and the
revision-3 P0-T2 plan (successor evidence receipt, 2026-10-10).
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIREMENTS = ROOT / "requirements"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
CORE_URL = "git+https://github.com/oramasys/perpetua-core.git@"
PRODUCER_CHECKOUT = re.compile(
    r"repository:\s*diazMelgarejo/orama-system\s*\n\s*ref:\s*(\S+)"
)
LANE_FILES = {
    "production": "compatibility-core-production.txt",
    "policy-r3": "compatibility-core-policy-r3.txt",
    "core-r3": "compatibility-core-candidate.txt",
}


def producer_refs() -> dict[str, list[str]]:
    """Return every Orama registry checkout ref, keyed by workflow file name."""
    refs: dict[str, list[str]] = {}
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        found = PRODUCER_CHECKOUT.findall(workflow.read_text(encoding="utf-8"))
        if found:
            refs[workflow.name] = found
    return refs


def production_dependency_pin() -> str:
    """Return the Core commit the installable package depends on."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pins = [dep.split(CORE_URL, 1)[1] for dep in project["project"]["dependencies"]
            if dep.startswith("perpetua-core @ ") and CORE_URL in dep]
    assert len(pins) == 1, "exactly one perpetua-core dependency must be declared"
    return pins[0]


def test_producer_registry_checkout_is_one_immutable_sha() -> None:
    """Both workflows read the same immutable Orama revision; branch names never qualify."""
    refs = producer_refs()
    assert {"ci.yml", "compatibility-oracles.yml"} <= set(refs)
    pinned = {ref for found in refs.values() for ref in found}
    assert len(pinned) == 1, f"producer checkouts disagree: {refs}"
    assert FULL_SHA.fullmatch(pinned.pop())


def test_core_lane_files_match_the_registry_profiles() -> None:
    """Each oracle lane installs exactly the Core commit its registry profile declares."""
    for profile, name in LANE_FILES.items():
        sha = (REQUIREMENTS / name).read_text(encoding="utf-8").strip()
        assert FULL_SHA.fullmatch(sha), f"{name} must hold one full commit SHA"
        assert sha == CORE_PINS[profile], f"{name} disagrees with profile {profile}"


def test_production_pin_agrees_everywhere_it_is_repeated() -> None:
    """Package dependency, production lane and the clean-install check name one Core."""
    expected = CORE_PINS["production"]
    assert production_dependency_pin() == expected
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert f"{CORE_URL}{expected}" in ci
    assert len(set(re.findall(re.escape(CORE_URL) + r"([0-9a-f]{40})", ci))) == 1
