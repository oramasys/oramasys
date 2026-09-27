"""The only composition writer that may mark a backend from a live probe."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from perpetua_core.discovery import Backend, BackendRegistry

from .probe import health_probe


async def record_probed(registry: BackendRegistry, candidate: Backend) -> Backend:
    """Probe ``candidate.base_url`` and store that result.

    ``candidate.health`` is ignored. A caller-supplied ``ONLINE`` value never
    becomes the stored observation.
    """
    probed = await health_probe(candidate.base_url)
    observed = replace(
        candidate,
        models=probed.models,
        health=probed.health,
        last_seen=datetime.now(timezone.utc),
    )
    registry.record(observed)
    return observed
