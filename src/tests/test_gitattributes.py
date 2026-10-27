"""Governance inputs are hashed over raw bytes, so no checkout may convert their line endings."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PINNED = (
    "requirements/generation-consumers.json",
    "requirements/ACTIVE-GENERATION.json",
    "requirements/compatibility-manifest.json",
    "requirements/compatibility-core-production.txt",
    "requirements/generations/m1-gen2/generation.json",
    "requirements/generations/m1-gen2/inputs/ownership-registry.json",
    "requirements/generations/transitions/0002-activate-m1-gen2.json",
    "requirements/history/m1-gen1/compatibility-manifest.v3.json",
    "src/tests/fixtures/graph-ownership-registry.json",
    "src/tests/fixtures/graph-ownership-registry-m1-gen1.json",
    # Raw-byte digests pinned by scripts and tests outside requirements/.
    "src/tests/fixtures/agate-hardware-profiles-172bfc3.json",
    "src/tests/vectors/dispatch-permit-v1.json",
    "src/tests/vectors/dispatch-events-v1.json",
    "src/tests/interop/c2_slice2_probe.py",
    "src/tests/interop/c2_part3_events_probe.py",
)
NEEDS_GIT = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _git(*args: str) -> str:
    """Run git in the repository root and return its stdout."""
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def _tracked() -> list[str]:
    """Every tracked path, repository-relative with forward slashes."""
    return [line for line in _git("ls-files").splitlines() if line]


def _rules() -> list[str]:
    """The path pattern of every non-comment ``.gitattributes`` line."""
    lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    return [line.split()[0] for line in lines if line.strip() and not line.startswith("#")]


def _matching(pattern: str, tracked: list[str]) -> set[str]:
    """The tracked paths a single gitattributes pattern covers (git's own glob semantics)."""
    out = _git("ls-files", "--", f":(glob){pattern}")
    return {line for line in out.splitlines() if line in set(tracked)}


def _digest_pinned_paths(tracked: list[str]) -> set[str]:
    """Tracked files named by a script or test that also hashes raw ``read_bytes()`` content.

    A name is matched by its basename inside the source text, so a new pin that is not listed in
    ``PINNED`` (and has no ``-text`` rule) fails ``test_every_discovered_digest_pinned_file_is_unset``.
    """
    sources = [
        p for p in tracked
        if p.endswith(".py") and (p.startswith("scripts/") or p.startswith("src/tests/"))
    ]
    data = [
        p for p in tracked
        if p.endswith((".json", ".txt")) or (p.startswith("src/tests/interop/c2_") and p.endswith(".py"))
    ]
    found: set[str] = set()
    for source in sources:
        text = (ROOT / source).read_text(encoding="utf-8", errors="replace")
        if "sha256" not in text or "read_bytes()" not in text:
            continue
        for path in data:
            base = path.rsplit("/", 1)[-1]
            if path != source and len(base) > 12 and f'"{base}"' in text:
                found.add(path)
    return found


@NEEDS_GIT
@pytest.mark.parametrize("name", PINNED)
def test_a_digest_pinned_input_is_never_text_converted(name: str) -> None:
    """``git check-attr text`` reports ``unset`` (``-text``), so core.autocrlf cannot alter it."""
    out = _git("check-attr", "text", "--", name)
    assert out.strip().endswith(": text: unset"), out


def test_the_committed_bytes_of_the_pinned_inputs_are_lf() -> None:
    """The bytes the attribute preserves are LF, the form the digests were computed over."""
    for name in PINNED:
        assert b"\r" not in (ROOT / name).read_bytes(), name


@NEEDS_GIT
def test_every_pinned_path_is_tracked() -> None:
    """A renamed or deleted pinned file must leave this list, not silently stop being checked."""
    assert set(PINNED) <= set(_tracked())


@NEEDS_GIT
def test_every_discovered_digest_pinned_file_is_unset() -> None:
    """Files that sources name next to a raw-byte sha256 are either listed or already ``-text``."""
    tracked = _tracked()
    for name in sorted(_digest_pinned_paths(tracked)):
        out = _git("check-attr", "text", "--", name)
        assert out.strip().endswith(": text: unset"), f"{name} is hashed over its bytes but is not -text"


@NEEDS_GIT
def test_every_rule_matches_a_tracked_file() -> None:
    """A rule that matches nothing is dead text (a rename or typo), not protection."""
    tracked = _tracked()
    for rule in _rules():
        assert _matching(rule, tracked), f"{rule} matches no tracked file"


@NEEDS_GIT
def test_every_rule_is_needed() -> None:
    """Each rule must cover at least one tracked file that no other rule covers (no redundancy)."""
    tracked = _tracked()
    rules = _rules()
    covered = {rule: _matching(rule, tracked) for rule in rules}
    for rule in rules:
        others = set().union(*(covered[r] for r in rules if r != rule)) if len(rules) > 1 else set()
        assert covered[rule] - others, f"{rule} is redundant: every file it covers has another rule"
