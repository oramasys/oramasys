"""Core capability detection shared by tests that must hold on every pinned lane.

The compatibility matrix runs the suite against Core revisions with no gate, a
gate without the start seam, and both. A test that needs a capability asserts
the positive behavior when it exists and the fail-closed refusal when it does
not, so no lane silently skips (the manifest budgets skips per cell).
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

import pytest

from orama.graph.admission import AdmissionRefused
from orama.graph.execution_guard import CORE_GATE_AVAILABLE, core_start_seam_available

T = TypeVar("T")

GATE_REFUSAL = r"gate\.core_seam_unavailable"
START_SEAM_REFUSAL = r"gate\.core_start_seam_unavailable"


async def invoke_or_expect_gate_refusal(call: Callable[[], Awaitable[T]]) -> T | None:
    """Run ``call`` where Core has a gate; elsewhere require the safe refusal.

    Returns the result on a gate-capable Core and None when the refusal was
    asserted, so callers can stop at the capability boundary.
    """
    if CORE_GATE_AVAILABLE:
        return await call()
    with pytest.raises(AdmissionRefused, match=GATE_REFUSAL):
        await call()
    return None


__all__ = [
    "CORE_GATE_AVAILABLE",
    "GATE_REFUSAL",
    "START_SEAM_REFUSAL",
    "core_start_seam_available",
    "invoke_or_expect_gate_refusal",
]
