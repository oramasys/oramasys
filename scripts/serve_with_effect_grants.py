"""Opt-in composition of authenticated inert dispatch with a public v2 verifier.

ORAMA_INERT_EFFECTS=enabled requests composition. PHYLAX_STATE_DIR and
ORAMA_EFFECT_STORE identify existing provisioned state. Configuration is never
activated by importing this module or installing its candidate dependencies.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI
from orama.api.server import create_app
from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_grant_composition import TrustedEffectGrantComposer


def build_app(environ: Mapping[str, str]) -> FastAPI:
    """Wire the public verifier and durable sender only for explicit inert composition."""
    if environ.get("ORAMA_INERT_EFFECTS") != "enabled":
        return create_app()
    from phylax import GrantVerifierConfig, open_effect_grant_verifier
    verifier = open_effect_grant_verifier(GrantVerifierConfig(state_dir=Path(environ["PHYLAX_STATE_DIR"])))
    try:
        store_path = Path(environ["ORAMA_EFFECT_STORE"])
        if not store_path.is_file():
            raise ValueError("an existing effect store is required")
        store = SqliteAttemptStore(store_path, governed=True)
    except BaseException:
        verifier.close()
        raise
    composer = TrustedEffectGrantComposer(verifier)

    def close() -> None:
        """Close both owned resources even if verifier cleanup fails."""
        try:
            verifier.close()
        finally:
            store.close()

    # The cleanup belongs to the effect composition, independently of recovery.
    from contextlib import asynccontextmanager
    app = create_app(inert_sender=lambda attempt, principal: composer.send(store, attempt, authenticated_principal=principal))
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
