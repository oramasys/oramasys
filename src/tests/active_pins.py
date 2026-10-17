"""Two pin contracts that must never be confused: frozen M1 generation one and active.

``CORE_PINS`` in ``test_ownership_registry`` is the ACTIVE contract (generation two). It
agrees with the reviewed registry snapshot, the package, the lane files, CI and the
reproduction recipe. ``M1_GEN1_CORE_PINS`` is the frozen generation-one contract. The
archived inputs under ``requirements/history/m1-gen1/`` and the gen-1 registry archive are
historical evidence bound to it, so it never moves.

Live files are validated against ``ACTIVE_PINS`` (via ``live_lane_files``). Archived
evidence is validated against ``frozen_lane_files()``. Each table is an independent literal:
neither is derived from the manifest it checks.
"""
from __future__ import annotations

from pathlib import Path

from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
LANE_FILES = {
    "production": "compatibility-core-production.txt",
    "policy-r3": "compatibility-core-policy-r3.txt",
    "core-r3": "compatibility-core-candidate.txt",
}
HISTORY = ROOT / "requirements" / "history" / "m1-gen1"

# Generation one, as approved in PR 45 and qualified in run 38916773943.
M1_GEN1_CORE_PINS = {
    "production": "609ff0ed99cf8eca6c9ef608e764b7a25b6b9973",
    "policy-r3": "04759a50c748444ff97136ea95c1e1289eac3a1a",
    "core-r3": "34e4a8d22212d38d6ab100c1ad7fb2b19f56cb68",
}
ACTIVE_PINS = dict(CORE_PINS)


def live_lane_files() -> dict[str, dict[str, str]]:
    """Lane files as the repository holds them now."""
    return {p: {"path": f"requirements/{n}",
                "sha": (ROOT / "requirements" / n).read_text(encoding="utf-8").strip()}
            for p, n in LANE_FILES.items()}


def frozen_lane_files() -> dict[str, dict[str, str]]:
    """Lane files as generation one froze them: the same path, the frozen M1 SHA."""
    return {p: {"path": f"requirements/{n}", "sha": M1_GEN1_CORE_PINS[p]}
            for p, n in LANE_FILES.items()}
