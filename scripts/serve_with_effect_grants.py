"""Opt-in composition of authenticated inert dispatch with a public v2 verifier.

Two independent conditions must BOTH hold before an inert sender is wired:

1. ``ORAMA_INERT_EFFECTS=enabled`` requests composition (exact value only); and
2. the R0-2 capability record (``ORAMA_CAPABILITY_RECORD`` with its expected digests, read by
   ``capability_config_from_environ``) makes the ``effects`` bit effective under ``evaluate`` and
   the startup refusal matrix.

A true bit needs a verified operator signature and this repository wires no signature verifier, so
in R0-2 ``effects`` is never effective and no sender is ever wired: the route stays
``404 serving.route_not_exposed`` and nothing is dispatched. Anything else fails closed: a record the
startup matrix refuses raises ``StartupRefused``, and an effective ``effects`` bit without the
final-boundary ports (approval verifier, revocation view, issuer id) is refused with
``startup.effects_without_permit_verifier``. When everything holds, the only sender is the
canonical ``FinalBoundarySender`` (verify-and-bind composer plus the sealed final boundary).

PHYLAX_STATE_DIR and ORAMA_EFFECT_STORE identify existing provisioned state. Configuration is never
activated by importing this module or installing its candidate dependencies.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from orama.api.capabilities import (
    STARTUP_EFFECTS_WITHOUT_PERMIT_VERIFIER,
    CapabilityConfig,
    StartupRefused,
    capability_config_from_environ,
    evaluate,
)
from orama.api.server import create_app
from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_grant_composition import (
    FinalBoundaryPorts,
    FinalBoundarySender,
    TrustedEffectGrantComposer,
)
from orama.graph.sealed_inert_driver import SealedInertDriver

_log = logging.getLogger(__name__)

ENABLE_VARIABLE = "ORAMA_INERT_EFFECTS"
ENABLED = "enabled"
VerifierOpener = Callable[[Path], Any]


def open_public_verifier(state_dir: Path) -> Any:
    """Open the public Phylax v2 effect-grant verifier (imported only on the effective path)."""
    from phylax import GrantVerifierConfig, open_effect_grant_verifier
    return open_effect_grant_verifier(GrantVerifierConfig(state_dir=state_dir))


def build_app(
    environ: Mapping[str, str],
    *,
    capability_config: CapabilityConfig | None = None,
    final_boundary: FinalBoundaryPorts | None = None,
    open_verifier: VerifierOpener = open_public_verifier,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Wire the canonical inert sender only when requested AND the effects bit is effective.

    ``capability_config`` defaults to ``capability_config_from_environ(environ)``; it is a seam for
    tests and never bypasses ``evaluate``. ``final_boundary`` supplies the final-boundary ports; R0-2
    wires none. ``clock`` (default: the wall clock) is shared by the composer and the sealed driver.
    When (and only when) the effect store is opened it is also passed to ``create_app`` as the
    ``attempt_store``, so the startup reconciliation report lists its in-doubt attempts (report only).
    """
    config = capability_config if capability_config is not None else capability_config_from_environ(environ)
    if environ.get(ENABLE_VARIABLE) != ENABLED:
        return create_app(capability_config=config)
    view = evaluate(config, verify_authority_available=False)
    if not view.is_effective("effects"):
        _log.warning("inert effects requested without an effective effects capability; no sender wired")
        return create_app(capability_config=config)
    if final_boundary is None:
        raise StartupRefused(STARTUP_EFFECTS_WITHOUT_PERMIT_VERIFIER)
    verifier = open_verifier(Path(environ["PHYLAX_STATE_DIR"]))
    try:
        store_path = Path(environ["ORAMA_EFFECT_STORE"])
        if not store_path.is_file():
            raise ValueError("an existing effect store is required")
        store = SqliteAttemptStore(store_path, governed=True)
    except BaseException:
        verifier.close()
        raise

    def close() -> None:
        """Close both owned resources even if verifier cleanup fails."""
        try:
            verifier.close()
        finally:
            store.close()

    try:
        driver = SealedInertDriver(
            store, effects_allowed=lambda: view.is_effective("effects"),
            approval_verifier=final_boundary.approval_verifier,
            revocations=final_boundary.revocations, issuer_id=final_boundary.issuer_id,
            clock=clock,
        )
        sender = FinalBoundarySender(TrustedEffectGrantComposer(verifier, clock=clock), driver)
        # The store this root opened is the effect store: its in-doubt rows are reported at startup.
        app = create_app(capability_config=config, inert_sender=sender, attempt_store=store)
    except BaseException:
        close()
        raise
    # The cleanup belongs to the effect composition, independently of recovery.
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        """Drain the original application lifecycle before releasing authority readers."""
        try:
            async with previous_lifespan(application):
                yield
        finally:
            close()

    app.router.lifespan_context = lifespan
    return app
