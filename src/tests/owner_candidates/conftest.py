"""Collect the real-owner adapter tests only where the owner candidates are installed.

They need the Phylax, Agate (with ``agate.evidence``) and Telos revisions from the T1
owner PRs. The production and policy oracle cells pin older owners, so there these tests
are not collected (a module-level skip would count against each cell's skip allowance).
The ``T1 Core gate candidate`` job installs the owner candidates and sets
ORAMA_REQUIRE_OWNER_CANDIDATES=1, so a missing owner there is a hard failure.
"""
import importlib.util
import os


def _available() -> bool:
    """Test helper: available."""
    try:
        return all(importlib.util.find_spec(m) is not None
                   for m in ("phylax", "agate.evidence", "telos.authorizer"))
    except ModuleNotFoundError:
        return False


OWNER_CANDIDATES_AVAILABLE = _available()
if os.environ.get("ORAMA_REQUIRE_OWNER_CANDIDATES") == "1" and not OWNER_CANDIDATES_AVAILABLE:
    raise RuntimeError("ORAMA_REQUIRE_OWNER_CANDIDATES=1 but the owner candidates are not installed")

collect_ignore_glob = [] if OWNER_CANDIDATES_AVAILABLE else ["test_*.py"]
