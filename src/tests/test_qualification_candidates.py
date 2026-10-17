"""The schema-3 qualification inputs name the selected consumer and the refreshed candidates.

The consumer sha is the commit under qualification (never the commit that holds the manifest).
In generation 1 the candidates were qualification inputs, not production pins. Generation 2
promotes them (``candidate_equals_pin``). Generation 1 stays unchanged under
``requirements/history/m1-gen1/`` as evidence of its own scope.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V3 = json.loads((ROOT / "requirements" / "compatibility-manifest.v3.json").read_text())
V2 = json.loads((ROOT / "requirements" / "compatibility-manifest.json").read_text())
GEN1 = json.loads((ROOT / "requirements" / "history" / "m1-gen1" / "compatibility-manifest.v3.json").read_text())
PHYLAX_PIN = (ROOT / "requirements" / "compatibility-phylax-verify-only.txt").read_text().strip()
CONSUMER = "133553a6d05b8704e6e4010f581d57623829f4b2"
GEN1_CONSUMER = "f8898b35d5249e483b2f4a68c097957e675a0ef4"
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


PROMOTED = {
    "neutral-mechanics": "6d75cfe08af95992dddffab13ae3019aa9c41350",
    "endpoint-policy": "931b6347142e8e66b31136e3ac8159d86eb5b2f7",
    "hardware-eligibility": "172bfc3ebf00d507856e70d0f6a0e7dbd577ffbc",
}
GEN1_PINS = {
    "neutral-mechanics": "609ff0ed99cf8eca6c9ef608e764b7a25b6b9973",
    "endpoint-policy": "b2143083044496d93be3ca2dc88c28135e034d9f",
    "hardware-eligibility": "41a0da9d52e0131049a1469234ac56f6990fc635",
}


def test_other_candidates_are_the_reviewed_identities_and_are_the_promoted_pins() -> None:
    """Generation 2: Core, Telos and Agate candidates are the named ones and are now the pins."""
    producers = V3["producers"]
    for role, sha in PROMOTED.items():
        assert producers[role]["candidate"] == sha
        assert producers[role]["production_pin"] == sha


def test_generation_one_qualified_the_same_candidates_against_the_old_pins() -> None:
    """The archived generation-1 manifest is unchanged: same candidates, old pins, old consumer."""
    assert GEN1["consumer"]["sha"] == GEN1_CONSUMER
    for role, sha in PROMOTED.items():
        assert GEN1["producers"][role]["candidate"] == sha
        assert GEN1["producers"][role]["production_pin"] == GEN1_PINS[role]


def test_the_six_historical_cells_equal_the_schema2_baseline() -> None:
    """Schema 3 adds final-set evidence; it must not alter the historical six cells."""
    historical = [c for c in V3["cells"] if c["profile"] != "final-producers"]
    assert len(historical) == 6
    assert sorted(historical, key=lambda c: (c["profile"], c["python"])) == sorted(
        V2["cells"], key=lambda c: (c["profile"], c["python"])
    )
