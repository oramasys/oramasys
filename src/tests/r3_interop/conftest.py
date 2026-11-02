"""Keep optional R3 producer composition separate from the Phylax-free base install."""

from __future__ import annotations

import importlib.util
import os


def available() -> bool:
    """Detect the required public publication API without hiding broken installations."""
    try:
        return importlib.util.find_spec("phylax.revocation_publication") is not None
    except ModuleNotFoundError as error:
        if error.name == "phylax":
            return False
        raise


_AVAILABLE = available()
if not _AVAILABLE and os.environ.get("ORAMA_R3_INTEROP_REQUIRED") == "1":
    raise RuntimeError("required R3 Phylax publication API is unavailable")
collect_ignore_glob = [] if _AVAILABLE else ["test_*.py"]
