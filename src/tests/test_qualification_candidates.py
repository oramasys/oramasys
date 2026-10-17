"""The schema-3 qualification inputs name the selected consumer and the refreshed candidates.

The consumer sha is the commit under qualification (never the commit that holds the manifest).
Candidates are qualification inputs, not production pins: the production Core pin and the
historical schema-2 baseline are untouched.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V3 = json.loads((ROOT / "requirements" / "compatibility-manifest.v3.json").read_text())
V2 = json.loads((ROOT / "requirements" / "compatibility-manifest.json").read_text())
PHYLAX_PIN = (ROOT / "requirements" / "compatibility-phylax-verify-only.txt").read_text().strip()
CONSUMER = "f8898b35d5249e483b2f4a68c097957e675a0ef4"
STALE_PHYLAX = "e41f1e863c65c5f0aae08a6befad21170354b014"


def test_the_consumer_under_qualification_is_the_selected_commit() -> None:
    """The operator selected C; the stale pre-#38 consumer must not remain."""
    assert V3["consumer"] == {"repository": "oramasys/oramasys", "sha": CONSUMER}


def test_the_phylax_candidate_equals_the_composition_pin_in_every_place_it_appears() -> None:
    """Producer entry and both final-producer candidate sets move together, or validation fails."""
    text = json.dumps(V3)
    assert STALE_PHYLAX not in text
    assert V3["producers"]["grant-authority"]["candidate"] == PHYLAX_PIN
    final = [c for c in V3["cells"] if c["profile"] == "final-producers"]
    assert len(final) == 2
    assert all(c["candidate_set"]["grant-authority"] == PHYLAX_PIN for c in final)


def test_phylax_stays_composition_only() -> None:
    """Refreshing the candidate must not turn Phylax into a declared dependency or a pinned one."""
    grant = V3["producers"]["grant-authority"]
    assert grant["declared_dependency"] is False
    assert "production_pin" not in grant


def test_other_candidates_are_the_reviewed_identities_and_production_pins_are_unchanged() -> None:
    """Core, Telos and Agate candidates are the named candidates; production pins are untouched."""
    producers = V3["producers"]
    assert producers["neutral-mechanics"]["candidate"] == "6d75cfe08af95992dddffab13ae3019aa9c41350"
    assert producers["endpoint-policy"]["candidate"] == "931b6347142e8e66b31136e3ac8159d86eb5b2f7"
    assert producers["hardware-eligibility"]["candidate"] == "172bfc3ebf00d507856e70d0f6a0e7dbd577ffbc"
    assert producers["neutral-mechanics"]["production_pin"] == "609ff0ed99cf8eca6c9ef608e764b7a25b6b9973"


def test_the_six_historical_cells_equal_the_schema2_baseline() -> None:
    """Schema 3 adds final-set evidence; it must not alter the historical six cells."""
    historical = [c for c in V3["cells"] if c["profile"] != "final-producers"]
    assert len(historical) == 6
    assert sorted(historical, key=lambda c: (c["profile"], c["python"])) == sorted(
        V2["cells"], key=lambda c: (c["profile"], c["python"])
    )
