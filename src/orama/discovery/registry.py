"""Composition-owned discovery registry with Telos-backed probing.

Candidate topology is supplied by the caller. This module never embeds LAN
seeds or workstation-specific network layout.
"""
from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timezone

from perpetua_core.discovery.backend import Backend, BackendHealth, BackendKind
from perpetua_core.discovery.errors import BackendOfflineError
from perpetua_core.discovery.registry import BackendRegistry

from .probe import health_probe

Seed = tuple[str, str, BackendKind]


class DiscoveryBackendRegistry(BackendRegistry):
    """BackendRegistry that can probe caller-supplied candidates via Telos."""

    async def autodetect(self, seeds: Sequence[Seed]) -> list[Backend]:
        results = await asyncio.gather(
            *(self._probe_and_record(name, url, kind) for name, url, kind in seeds),
            return_exceptions=False,
        )
        return [backend for backend in results if backend is not None]

    async def register_by_ip(
        self,
        ip: str,
        port: int,
        kind: BackendKind,
        *,
        name: str | None = None,
    ) -> Backend:
        url = f"http://{ip}:{port}/v1"
        name = name or f"{kind.value}-{ip}"
        backend = await self._probe_and_record(name, url, kind)
        if backend is None or backend.health is not BackendHealth.ONLINE:
            raise BackendOfflineError(f"{name} @ {url} did not respond")
        return backend

    async def _probe_and_record(
        self, name: str, url: str, kind: BackendKind
    ) -> Backend | None:
        probe = await health_probe(url)
        now = datetime.now(timezone.utc)
        backend = Backend(
            name=name,
            base_url=url,
            kind=kind,
            models=probe.models,
            health=probe.health,
            last_seen=now,
        )
        if probe.health is BackendHealth.ONLINE:
            # Prefer Core's pure store API when present; fall back for pin lag.
            record = getattr(self, "record", None)
            if callable(record):
                record(backend)
            else:
                self._backends[backend.name] = backend
        return backend
