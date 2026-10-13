"""Composition root: serve Oramasys with Phylax's grant verifier injected.

This is the one place that imports both packages. Neither library may import the
other: Oramasys defines the verifier port and carries no cryptography, Phylax
issues and verifies and never sees a balance. A process that needs adjustments
runs this entry point (or one shaped like it); a process that does not run
``orama.api.server`` as before and every grant stays denied.

Configuration names PATHS and FILE NAMES only. Secrets are read from private
files by Phylax's ``FileSeedProvider`` and never from the environment:

    ORAMA_LEDGER_PATH         SQLite ledger shared with the run controller
    PHYLAX_STATE_DIR          durable Phylax stores (created 0700)
    PHYLAX_SEED_ROOT          0700 directory of 0600 hex seed files
    PHYLAX_KEY_ID             active issuer key id
    PHYLAX_SEED_REF           file name of the issuer seed inside SEED_ROOT
    PHYLAX_P5_SECRET_REF      file name of the P5 secret inside SEED_ROOT
    PHYLAX_VERIFIER_ID        optional label recorded in every receipt
"""
from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI

from orama.api.authz import resolve_bind_host
from orama.api.server import create_app
from orama.graph.execution_guard import StepLedger
from orama.graph.grant_verifier import AdjustmentGrantConsumer
from phylax import GrantAuthorityConfig, open_grant_authority

_REQUIRED = (
    "ORAMA_LEDGER_PATH",
    "PHYLAX_STATE_DIR",
    "PHYLAX_SEED_ROOT",
    "PHYLAX_KEY_ID",
    "PHYLAX_SEED_REF",
    "PHYLAX_P5_SECRET_REF",
)


def build_app(environ: Mapping[str, str]) -> FastAPI:
    """Build the API with the Phylax verifier injected; refuse on missing config."""
    missing = [name for name in _REQUIRED if not environ.get(name, "").strip()]
    if missing:
        raise SystemExit(f"missing configuration: {', '.join(missing)}")
    authority = open_grant_authority(
        GrantAuthorityConfig(
            state_dir=Path(environ["PHYLAX_STATE_DIR"]),
            seed_root=Path(environ["PHYLAX_SEED_ROOT"]),
            key_id=environ["PHYLAX_KEY_ID"],
            seed_ref=environ["PHYLAX_SEED_REF"],
            p5_secret_ref=environ["PHYLAX_P5_SECRET_REF"],
            verifier_id=environ.get("PHYLAX_VERIFIER_ID", "phylax-primary"),
        )
    )
    ledger = StepLedger(Path(environ["ORAMA_LEDGER_PATH"]))
    consumer = AdjustmentGrantConsumer(ledger, authority.verifier_adapter())
    return create_app(adjustment_consumer=consumer)


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
