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

import pytest

from tests.active_pins import ACTIVE_PINS, LANE_FILES, M1_GEN1_CORE_PINS
from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIREMENTS = ROOT / "requirements"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
CORE_URL = "git+https://github.com/oramasys/perpetua-core.git@"
CHECKOUT_STEP = re.compile(r"(?m)^[ \t]*-\s+(?=name:|uses:)")
WITH_KEY = re.compile(r"^([ \t]*)with:[ \t]*(#.*)?$")
CHECKOUT_INPUT = re.compile(r"^[ \t]+(repository|ref|path):\s*([^\n#]+)")


def checkout_inputs(step: str, workflow: str) -> list[tuple[str, str]]:
    """Return ``repository``/``ref``/``path`` entries from the step's ``with:`` block only.

    ``actions/checkout`` reads its revision solely from ``with.ref``; a SHA under
    ``env:`` or any other key is ignored and the default branch is fetched. The
    block ends at the first non-blank line indented no deeper than ``with:``, so a
    later sibling such as ``env:`` is never read. Flow-style or repeated ``with:``
    mappings fail closed instead of being parsed approximately.
    """
    lines = step.splitlines()
    starts = [index for index, line in enumerate(lines) if re.match(r"^[ \t]*with:", line)]
    if not starts:
        return []
    assert len(starts) == 1, f"{workflow}: repeated checkout with mapping"
    opener = WITH_KEY.match(lines[starts[0]])
    assert opener, f"{workflow}: checkout with must be a block mapping"
    depth = len(opener[1])
    pairs: list[tuple[str, str]] = []
    for line in lines[starts[0] + 1:]:
        if not line.strip():
            continue
        if len(line) - len(line.lstrip(" \t")) <= depth:
            break
        found = CHECKOUT_INPUT.match(line)
        if found:
            pairs.append((found[1], found[2]))
    return pairs


def producer_refs() -> dict[str, list[str]]:
    """Return registry-role pins, separating explicit documentation-only checkouts.

    Repository identity alone does not identify the dependency edge. The existing
    ``docs-candidate`` / ``registry`` checkouts supply the qualified registry; ``legacy-map``
    supplies documentation/checker code only. Unknown roles fail closed rather
    than being silently ignored. Both roles still require immutable revisions.
    """
    refs: dict[str, list[str]] = {}
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        found: list[str] = []
        for step in CHECKOUT_STEP.split(workflow.read_text(encoding="utf-8")):
            if not re.search(r"(?m)^\s*uses:\s*actions/checkout@", step):
                continue
            pairs = checkout_inputs(step, workflow.name)
            fields = {key: value.strip().strip("\"'") for key, value in pairs}
            if fields.get("repository") != "diazMelgarejo/orama-system":
                continue
            assert len(fields) == len(pairs), f"{workflow.name}: duplicate checkout field"
            role = fields.get("path")
            assert role in {"docs-candidate", "registry", "legacy-map"}, (
                f"{workflow.name}: unclassified Orama checkout role {role!r}"
            )
            assert "ref" in fields, f"{workflow.name}: checkout with.ref is missing"
            ref = fields["ref"]
            assert FULL_SHA.fullmatch(ref), f"{workflow.name}: checkout ref must be immutable"
            if role in {"docs-candidate", "registry"}:
                found.append(ref)
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
        assert sha == ACTIVE_PINS[profile], f"{name} disagrees with profile {profile}"


def test_production_pin_agrees_everywhere_it_is_repeated() -> None:
    """Package dependency, production lane and the clean-install check name one Core."""
    expected = ACTIVE_PINS["production"]
    assert production_dependency_pin() == expected
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert f"{CORE_URL}{expected}" in ci
    assert len(set(re.findall(re.escape(CORE_URL) + r"([0-9a-f]{40})", ci))) == 1


README = ROOT / "tests" / "oracles" / "README.md"
FENCE = re.compile(r"```[a-z]*\n(.*?)```", re.DOTALL)


def test_reproduction_recipe_pairs_each_lane_sha_with_its_profile() -> None:
    """Every reproduction command names one lane Core SHA and its matching profile.

    A recipe that leaves ORAMA_REGISTRY_PROFILE unset silently selects production,
    so a candidate checkout could report a production-profile result.
    """
    blocks = [b for b in FENCE.findall(README.read_text(encoding="utf-8")) if "pytest" in b]
    seen: dict[str, str] = {}
    for block in blocks:
        profiles = re.findall(r"ORAMA_REGISTRY_PROFILE=(\S+)", block)
        shas = FULL_SHA.findall(block)
        assert len(profiles) == 1, f"command must set exactly one profile:\n{block}"
        assert len(set(shas)) == 1, f"command must name exactly one Core SHA:\n{block}"
        assert shas[0] == ACTIVE_PINS[profiles[0]], f"SHA does not match {profiles[0]}"
        seen[profiles[0]] = shas[0]
    assert set(seen) == set(LANE_FILES), f"recipe must cover every lane, got {sorted(seen)}"


def test_ci_repeats_only_the_production_core_and_the_producer_revision() -> None:
    """Every full SHA in ci.yml is either the production Core pin or the producer ref."""
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    allowed = {ACTIVE_PINS["production"], *producer_refs()["ci.yml"]}
    # Action pins are checked by test_every_workflow_action_is_pinned_to_a_full_commit.
    without_actions = "\n".join(ln for ln in ci.splitlines() if "uses:" not in ln)
    assert set(FULL_SHA.findall(without_actions)) == allowed
    assert ACTIVE_PINS["production"] in re.findall(
        r"verify_production_install\.py\"\s+([0-9a-f]{40})", ci)


def test_every_workflow_action_is_pinned_to_a_full_commit() -> None:
    """Third-party actions must name a full commit SHA, never a movable tag."""
    for wf in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = re.search(r"uses:\s*(\S+)", line)
            if m and not m.group(1).startswith("./"):
                assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{wf.name}: {line.strip()}"


def test_active_pins_differ_from_frozen_only_where_declared() -> None:
    """Generation two moves production Core alone; generation one keeps its own table."""
    moved = {p for p in M1_GEN1_CORE_PINS if ACTIVE_PINS[p] != M1_GEN1_CORE_PINS[p]}
    assert moved == {"production"}, f"undeclared pin movement: {sorted(moved)}"
    assert ACTIVE_PINS == CORE_PINS
    assert all(FULL_SHA.fullmatch(sha) for sha in ACTIVE_PINS.values())


@pytest.mark.parametrize("registry_path", ["docs-candidate", "registry"])
def test_registry_scan_separates_documentation_and_registry_checkouts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registry_path: str,
) -> None:
    """A map-only checkout must not become a second compatibility registry pin."""
    workflow = tmp_path / "roles.yml"
    workflow.write_text(
        "steps:\n"
        "  - uses: actions/checkout@" + "a" * 40 + "\n"
        "    with:\n"
        "      repository: diazMelgarejo/orama-system\n"
        "      ref: " + "1" * 40 + "\n"
        f"      path: {registry_path}\n"
        "  - name: Documentation map\n"
        "    uses: actions/checkout@" + "a" * 40 + "\n"
        "    with:\n"
        "      path: legacy-map\n"
        "      repository: diazMelgarejo/orama-system\n"
        "      ref: " + "2" * 40 + "\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    assert producer_refs() == {"roles.yml": ["1" * 40]}


@pytest.mark.parametrize("path_line", ["", "      path: unclassified\n"])
def test_registry_scan_refuses_an_unclassified_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path_line: str,
) -> None:
    """Missing or unknown checkout roles cannot silently evade the registry gate."""
    (tmp_path / "unknown.yml").write_text(
        "steps:\n"
        "  - uses: actions/checkout@" + "a" * 40 + "\n"
        "    with:\n"
        "      repository: diazMelgarejo/orama-system\n"
        "      ref: " + "1" * 40 + "\n" + path_line,
        encoding="utf-8",
    )
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    with pytest.raises(AssertionError, match="checkout role"):
        producer_refs()


@pytest.mark.parametrize("role", ["docs-candidate", "registry", "legacy-map"])
@pytest.mark.parametrize("ref", ["main", "abcd1234"])
def test_registry_scan_requires_immutable_refs_for_every_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, ref: str,
) -> None:
    """Excluding map-only refs from registry agreement never permits mutable pins."""
    (tmp_path / "mutable.yml").write_text(
        "steps:\n"
        "  - uses: actions/checkout@" + "a" * 40 + "\n"
        "    with:\n"
        "      repository: diazMelgarejo/orama-system\n"
        f"      ref: {ref}\n"
        f"      path: {role}\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    with pytest.raises(AssertionError, match="immutable"):
        producer_refs()


def test_registry_scan_refuses_duplicate_checkout_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambiguous role or pin declarations must not select a convenient last value."""
    (tmp_path / "duplicate.yml").write_text(
        "steps:\n"
        "  - uses: actions/checkout@" + "a" * 40 + "\n"
        "    with:\n"
        "      repository: diazMelgarejo/orama-system\n"
        "      ref: " + "1" * 40 + "\n"
        "      path: docs-candidate\n"
        "      path: legacy-map\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    with pytest.raises(AssertionError, match="duplicate"):
        producer_refs()


ORAMA_STEP = "  - uses: actions/checkout@" + "a" * 40 + "\n"


@pytest.mark.parametrize(
    "body",
    [
        "    env:\n      ref: " + "1" * 40 + "\n"
        "    with:\n      repository: diazMelgarejo/orama-system\n      path: docs-candidate\n",
        "    with:\n      repository: diazMelgarejo/orama-system\n      path: docs-candidate\n"
        "    env:\n      ref: " + "1" * 40 + "\n",
    ],
    ids=["env-before-with", "env-after-with"],
)
def test_registry_scan_reads_ref_only_from_the_with_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str,
) -> None:
    """A SHA outside ``with:`` is ignored by checkout, so it must not count as the pin."""
    (tmp_path / "env_ref.yml").write_text("steps:\n" + ORAMA_STEP + body, encoding="utf-8")
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    with pytest.raises(AssertionError, match=r"with\.ref is missing"):
        producer_refs()


def test_registry_scan_ignores_inputs_after_the_with_mapping_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sibling key after ``with:`` cannot override or duplicate a real checkout input."""
    (tmp_path / "sibling.yml").write_text(
        "steps:\n" + ORAMA_STEP
        + "    with:\n      repository: diazMelgarejo/orama-system\n"
        "      ref: " + "1" * 40 + "\n      path: registry\n"
        "    env:\n      ref: " + "2" * 40 + "\n      path: legacy-map\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    assert producer_refs() == {"sibling.yml": ["1" * 40]}


def test_registry_scan_refuses_a_flow_style_with_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inline ``with: {...}`` is not parsed approximately; it fails closed."""
    (tmp_path / "flow.yml").write_text(
        "steps:\n" + ORAMA_STEP
        + "    with: {repository: diazMelgarejo/orama-system, ref: " + "1" * 40 + "}\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(producer_refs.__globals__, "WORKFLOWS", tmp_path)
    with pytest.raises(AssertionError, match="block mapping"):
        producer_refs()
