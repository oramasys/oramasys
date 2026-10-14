"""Collect the cross-repository interop tests only where Phylax has the verify-only API.

The default Oramasys install is Phylax-free, and older Phylax revisions lack the read-only
verifier and its lifecycle cleanup. Skipping would add a skipped test to every cell and consume
the manifest skip allowance, so the modules are simply not collected where the capability is
absent. "Absent" is narrow: a missing ``phylax`` package or a missing ``open_grant_verifier`` /
``close``. Any other import failure means the package is present but broken and collection
fails loudly. ``ORAMA_REQUIRE_PHYLAX_INTEROP=1`` makes absence itself an error (the Ubuntu
interop job must run these tests).
"""
from __future__ import annotations

import os


def _verify_only_api_available() -> bool:
    """True when Phylax exposes the read-only verifier with a close path; False when absent."""
    try:
        import phylax
        from phylax.adjustment_grant import PhylaxAdjustmentGrantVerifier
    except ModuleNotFoundError as error:
        if error.name == "phylax" or (error.name or "").startswith("phylax."):
            return False
        raise
    return hasattr(phylax, "open_grant_verifier") and hasattr(
        PhylaxAdjustmentGrantVerifier, "close"
    )


_AVAILABLE = _verify_only_api_available()
if not _AVAILABLE and os.environ.get("ORAMA_REQUIRE_PHYLAX_INTEROP") == "1":
    raise RuntimeError(
        "ORAMA_REQUIRE_PHYLAX_INTEROP=1 but Phylax does not expose the verify-only API"
    )

collect_ignore_glob = [] if _AVAILABLE else ["test_*.py"]
