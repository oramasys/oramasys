"""Collect real effect interop only in the opt-in producer candidate lane.

Absence is not a skipped oracle cell. Broken installed dependencies still fail
collection, and the required candidate lane refuses absent capability.
"""
import importlib.util
import os


def available() -> bool:
    """Detect the optional v2 module without hiding failures inside installed code."""
    try:
        return importlib.util.find_spec("phylax.effect_grant") is not None
    except ModuleNotFoundError as error:
        if error.name == "phylax":
            return False
        raise


_AVAILABLE = available()
if not _AVAILABLE and os.environ.get("ORAMA_EFFECT_INTEROP_REQUIRED") == "1":
    raise RuntimeError("required Phylax effect-grant API is unavailable")
collect_ignore_glob = [] if _AVAILABLE else ["test_*.py"]
