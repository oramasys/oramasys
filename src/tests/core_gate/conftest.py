"""Collect the scheduler-level gate tests only where Core has the needed seam.

They are not skipped (skips count against the per-cell result gate); they are
not collected where the capability is absent. Three capability bands exist:

* no gate (pre-T1 pins): nothing here is collected;
* gate without the start seam (the production pin): only the modules that
  describe the seam-less contract run;
* gate with the start seam: the positive seam modules run.

The candidate CI job sets ORAMA_REQUIRE_CORE_GATE=1 and
ORAMA_REQUIRE_CORE_START_SEAM=1, and tests/test_execution_guard.py then asserts
the capability is present, so the suite cannot silently disappear there.
"""
from orama.graph.execution_guard import CORE_GATE_AVAILABLE, core_start_seam_available

_SEAM_REQUIRED = [
    "test_accounting_start_integration.py",
    "test_start_seam_runtime.py",
    "test_admitted_observation_unknown_disposition.py",
]
_SEAM_ABSENT_ONLY = ["test_start_seam_absent.py"]

collect_ignore_glob = [] if CORE_GATE_AVAILABLE else ["test_*.py"]
collect_ignore = _SEAM_REQUIRED if not core_start_seam_available() else _SEAM_ABSENT_ONLY
