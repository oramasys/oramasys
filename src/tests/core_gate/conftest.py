"""Collect the scheduler-level gate tests only where Core has the T1 seam.

They are not skipped (skips count against the per-cell result gate); they are not
collected on the pre-T1 production pin. The candidate CI job sets
ORAMA_REQUIRE_CORE_GATE=1, and tests/test_execution_guard.py then asserts the seam is
present, so the suite cannot silently disappear there.
"""
from orama.graph.execution_guard import CORE_GATE_AVAILABLE

collect_ignore_glob = [] if CORE_GATE_AVAILABLE else ["test_*.py"]
