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
    "src/tests/fixtures/graph-ownership-registry.json",
    "src/tests/fixtures/graph-ownership-registry-m1-gen1.json",
    "requirements/history/m1-gen1/compatibility-manifest.v3.json",
)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
@pytest.mark.parametrize("name", PINNED)
def test_a_digest_pinned_input_is_never_text_converted(name: str) -> None:
    """``git check-attr text`` reports ``unset`` (``-text``), so core.autocrlf cannot alter it."""
    out = subprocess.run(
        ["git", "check-attr", "text", "--", name], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    assert out.strip().endswith(": text: unset"), out


def test_the_committed_bytes_of_the_pinned_inputs_are_lf() -> None:
    """The bytes the attribute preserves are LF, the form the digests were computed over."""
    for name in PINNED:
        assert b"\r" not in (ROOT / name).read_bytes(), name
