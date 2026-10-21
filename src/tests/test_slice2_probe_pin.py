"""Slice 2 interop probe pin and SHA-256 integrity verification."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = ROOT / "src" / "tests" / "interop" / "c2_slice2_probe.py"
EXPECTED_SHA256 = "682129b1d1f359fa04548c75f2bb362f93648e5673bddb96390453d3b4d8d878"


def test_slice2_probe_file_exists_and_matches_sha256() -> None:
    """Check the probe exists and hashes to the pinned SHA-256.

    The literal is kept equal to the counterpart repository's literal; never change the probe or
    either literal alone.
    """
    assert PROBE_PATH.is_file(), f"probe file missing at {PROBE_PATH}"
    digest = hashlib.sha256(PROBE_PATH.read_bytes()).hexdigest()
    assert digest == EXPECTED_SHA256, f"probe SHA-256 mismatch: got {digest}, expected {EXPECTED_SHA256}"
