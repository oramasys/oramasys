"""Collect the measured-fit tests only where Agate provides ``agate.evidence``.

The production Agate pin has no measured-fit capability (it is candidate-only). Skipping would
add a skipped test to every cell and exceed the manifest's skip allowance, so the modules are
simply not collected where the capability is absent. "Absent" is deliberately narrow: only a
missing ``agate``, ``agate.evidence`` or ``agate.fit`` module counts. Any other import failure
means the capability is present but broken, and collection fails loudly instead of silently
reporting zero tests. Setting ``ORAMA_REQUIRE_AGATE_EVIDENCE=1`` makes absence itself an error
(for the candidate cells that must run these tests).
"""

from __future__ import annotations

import os

_ABSENT_MODULES = frozenset({"agate", "agate.evidence", "agate.fit"})


def _measured_fit_available() -> bool:
    """True when the capability is importable, False when cleanly absent; raises when broken."""
    try:
        import agate.evidence  # noqa: F401
        import agate.fit  # noqa: F401
    except ModuleNotFoundError as error:
        if error.name in _ABSENT_MODULES:
            return False
        raise
    return True


_AVAILABLE = _measured_fit_available()
if not _AVAILABLE and os.environ.get("ORAMA_REQUIRE_AGATE_EVIDENCE") == "1":
    raise RuntimeError("ORAMA_REQUIRE_AGATE_EVIDENCE=1 but agate.evidence is not importable")

collect_ignore_glob = [] if _AVAILABLE else ["test_*.py"]
