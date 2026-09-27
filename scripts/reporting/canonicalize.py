#!/usr/bin/env python3
"""Single-trailing-LF canonicalization for GitHub PR text-metadata integrity.

Shared by ``report_pr.py`` and ``append_pr_summary.py`` so pre-write and
post-write hashes cannot drift.

Contract (narrowed from an earlier unbounded ``.rstrip(b"\\n")``):

A locally-written file (``printf '%s\\n'``) gains exactly one trailing LF that a
JSON string field / shell command-substitution round-trip does not preserve, so
a single LF must not count as a difference. Stripping an *unbounded* number of
newlines would hash ``b"x"``, ``b"x\\n"`` and ``b"x\\n\\n"`` identically and hide
a real loss of meaningful trailing blank lines. Removing at most one LF is the
actual contract this transport needs.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def canonicalize_text_metadata_bytes(content: bytes) -> bytes:
    """Remove at most one trailing LF; leave all other bytes untouched."""
    if content.endswith(b"\n"):
        return content[:-1]
    return content


def sha256_canonical_bytes(content: bytes) -> str:
    return hashlib.sha256(canonicalize_text_metadata_bytes(content)).hexdigest()


def sha256_canonical_file(path: str | Path) -> str:
    return sha256_canonical_bytes(Path(path).read_bytes())


def sha256_canonical_text(text: str) -> str:
    return sha256_canonical_bytes(text.encode("utf-8"))
