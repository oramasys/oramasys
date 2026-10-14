"""Composition root: serve Oramasys with Phylax's managed verifier injected.

This is the one place that imports both packages. Neither library may import the
other: Oramasys defines the verifier port and carries no cryptography, while
Phylax owns issuance and verification. Grant-backed serving is off unless the
operator requests the exact ``enabled`` value below. This process opens only a
read-only verifier and owns only its shutdown callback; it never opens an
issuer authority or falls back to privileged operations.

Phylax is delivered only through the opt-in extra: ``pip install 'oramasys[grant-serving]'``.
A default install is Phylax-free; with the flag set and no Phylax installed the process stays up,
``/health`` reports ``grants: unavailable`` and the log names ``phylax_not_installed``. Check
``/health`` for ``grants: ready`` rather than assuming the flag took effect.

Configuration names paths and labels only:

    ORAMA_GRANT_SERVING       exact "enabled" to request grant-backed serving
    ORAMA_LEDGER_PATH         SQLite ledger shared with the run controller
    PHYLAX_STATE_DIR          existing private Phylax verifier state directory
    PHYLAX_VERIFIER_ID        optional label recorded in every receipt
"""
from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from orama.api.authz import resolve_bind_host
from orama.api.server import create_app
from orama.graph.execution_guard import StepLedger
from orama.graph.grant_verifier import AdjustmentGrantConsumer, AdjustmentGrantVerifier

_log = logging.getLogger("orama.serve")

ENABLE_VARIABLE = "ORAMA_GRANT_SERVING"
ENABLED = "enabled"
_REQUIRED_WHEN_ENABLED = (
    "ORAMA_LEDGER_PATH",
    "PHYLAX_STATE_DIR",
)
ManagedVerifier = tuple[AdjustmentGrantVerifier, Callable[[], None]]
VerifierOpener = Callable[[Mapping[str, str]], ManagedVerifier]


def open_phylax_verifier(environ: Mapping[str, str]) -> ManagedVerifier:
    """Open Phylax's read-only verifier and return its explicit close callback."""
    from phylax import GrantVerifierConfig, open_grant_verifier

    verifier: Any = open_grant_verifier(
        GrantVerifierConfig(
            state_dir=Path(environ["PHYLAX_STATE_DIR"]),
            verifier_id=environ.get("PHYLAX_VERIFIER_ID", "phylax-primary"),
        )
    )
    close = getattr(verifier, "close", None)
    if not callable(close):
        raise RuntimeError("Phylax verifier does not expose lifecycle cleanup")
    return verifier, close


def _cause(error: BaseException) -> str:
    """Name why the verifier could not open without exposing paths or messages."""
    if isinstance(error, ModuleNotFoundError) and (error.name or "").split(".")[0] == "phylax":
        return "phylax_not_installed"
    return type(error).__name__


def close_resources(verifier_close: Callable[[], None], ledger: StepLedger) -> None:
    """Close verifier and ledger even when verifier shutdown reports a failure."""
    try:
        verifier_close()
    finally:
        ledger.close()


def _release_verifier(close: Callable[[], None]) -> None:
    """Close a verifier that was opened but will not be wired; never raise from startup."""
    try:
        close()
    except Exception as error:  # noqa: BLE001 - cleanup of an unused resource
        _log.warning("verifier cleanup failed", extra={"reason": type(error).__name__})


def build_app(
    environ: Mapping[str, str], *, open_verifier: VerifierOpener = open_phylax_verifier
) -> FastAPI:
    """Build a disabled, ready or unavailable grant capability without fallback."""
    if environ.get(ENABLE_VARIABLE) != ENABLED:
        return create_app(grant_capability="disabled")
    missing = [name for name in _REQUIRED_WHEN_ENABLED if not environ.get(name, "").strip()]
    if missing:
        raise SystemExit(f"missing configuration: {', '.join(missing)}")
    try:
        verifier, close = open_verifier(environ)
    except Exception as error:  # noqa: BLE001 - public state is only unavailable
        # Only a cause label is logged: no state paths or low-level text.
        _log.warning("grant verifier unavailable", extra={"reason": _cause(error)})
        return create_app(grant_capability="unavailable")
    try:
        ledger = StepLedger(Path(environ["ORAMA_LEDGER_PATH"]))
    except Exception as error:  # noqa: BLE001 - a ledger that cannot open is "unavailable"
        _log.warning("grant ledger unavailable", extra={"reason": type(error).__name__})
        _release_verifier(close)
        return create_app(grant_capability="unavailable")
    return create_app(
        adjustment_consumer=AdjustmentGrantConsumer(ledger, verifier),
        grant_capability="ready",
        grant_cleanup=lambda: close_resources(close, ledger),
    )


def main() -> None:
    """Serve on the glass-window bind host; LAN binding keeps its token rules."""
    import uvicorn

    uvicorn.run(
        build_app(os.environ),
        host=resolve_bind_host(),
        port=int(os.environ.get("ORAMA_PORT", "8000")),
    )


if __name__ == "__main__":
    sys.exit(main())
