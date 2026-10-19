"""E1 "C2" vendored dispatch-permit vectors: a byte-identical copy with a drift guard."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

VECTOR_PATH = Path(__file__).parent / "vectors" / "dispatch-permit-v1.json"
VECTOR_SHA256 = "f30d3fb675f32bc73ffbf5f7ed40317dfdd2700005a76241b71feeb2825a8e88"


def test_vendored_vector_hash_matches_the_frozen_copy() -> None:
    """The vendored file's SHA-256 equals the recorded constant, so drift fails loudly."""
    digest = hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest()

    assert digest == VECTOR_SHA256


def test_vendored_vector_parses_with_the_expected_schema() -> None:
    """The vendored file is valid JSON naming the conformance schema."""
    parsed = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    assert parsed["schema"] == "phylax.dispatch-permit.conformance.v1"
