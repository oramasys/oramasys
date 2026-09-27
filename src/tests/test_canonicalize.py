"""Unit tests for single-trailing-LF text-metadata canonicalize."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTING = ROOT / "scripts" / "reporting"
sys.path.insert(0, str(REPORTING))

from canonicalize import (  # noqa: E402
    canonicalize_text_metadata_bytes,
    sha256_canonical_bytes,
)


def test_single_trailing_lf_matches_without():
    assert sha256_canonical_bytes(b"x") == sha256_canonical_bytes(b"x\n")


def test_double_trailing_lf_is_distinct():
    assert sha256_canonical_bytes(b"x\n") != sha256_canonical_bytes(b"x\n\n")


def test_canonicalize_removes_at_most_one_lf():
    assert canonicalize_text_metadata_bytes(b"x\n\n") == b"x\n"
    assert canonicalize_text_metadata_bytes(b"x") == b"x"
    assert canonicalize_text_metadata_bytes(b"x\n") == b"x"
