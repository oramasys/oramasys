"""Caller-supplied health must not survive the composition probe writer."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from perpetua_core.discovery import Backend, BackendHealth, BackendKind

from orama.discovery.observe import record_probed
from orama.discovery.probe import ProbeResult


class _Store:
    def __init__(self) -> None:
        self.saved: dict[str, Backend] = {}

    def record(self, backend: Backend) -> None:
        self.saved[backend.name] = backend


def _candidate(health: BackendHealth) -> Backend:
    return Backend(
        name="ollama-local",
        base_url="http://127.0.0.1:11434/v1",
        kind=BackendKind.OLLAMA,
        models=("claimed",),
        health=health,
        last_seen=datetime.now(UTC),
    )


def test_record_probed_discards_supplied_online_health(monkeypatch: pytest.MonkeyPatch) -> None:
    async def offline(base_url: str, *, timeout: float = 1.5) -> ProbeResult:
        assert base_url == "http://127.0.0.1:11434/v1"
        return ProbeResult(BackendHealth.OFFLINE, ())

    monkeypatch.setattr("orama.discovery.observe.health_probe", offline)
    store = _Store()
    store.record(_candidate(BackendHealth.ONLINE))

    observed = asyncio.run(record_probed(store, _candidate(BackendHealth.ONLINE)))

    assert observed.health is BackendHealth.OFFLINE
    assert observed.models == ()
    assert store.saved == {"ollama-local": observed}
