"""Two pin contracts that must never be confused: frozen generation one and active C2.

``CORE_PINS`` in ``test_ownership_registry`` is the M1 (generation one) contract. The
frozen manifests, the registry snapshots and the coverage packet are historical evidence
bound to it, so it never moves. ``ACTIVE_PINS`` is the live consumer contract: what the
package, the production lane file, CI and the reproduction recipe install today. Only the
production Core differs, and only by this declared promotion.

Frozen evidence is validated against ``frozen_lane_files()``; live files are validated
against ``ACTIVE_PINS``. Neither check may read the other's table.
"""
from __future__ import annotations

from tests.test_ownership_registry import CORE_PINS

LANE_FILES = {
    "production": "compatibility-core-production.txt",
    "policy-r3": "compatibility-core-policy-r3.txt",
    "core-r3": "compatibility-core-candidate.txt",
}

# C2: Core main after the M1 pin-promotion generation. Declared here once; every live
# repetition (pyproject, ci.yml, lane file, README recipe) is checked against it.
C2_PRODUCTION_CORE = "6d75cfe08af95992dddffab13ae3019aa9c41350"
ACTIVE_PINS = {**CORE_PINS, "production": C2_PRODUCTION_CORE}


def frozen_lane_files() -> dict[str, dict[str, str]]:
    """Lane files as generation one froze them: the live path, the frozen M1 SHA."""
    return {p: {"path": f"requirements/{n}", "sha": CORE_PINS[p]} for p, n in LANE_FILES.items()}
