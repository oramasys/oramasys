"""Telos-backed health probe for composition. Core does not own this path."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from secrets import token_urlsafe

from perpetua_core.discovery import BackendHealth
from telos import (
    EndpointAuthorizer,
    EndpointPolicyError,
    EndpointPurpose,
    TransportPolicy,
    endpoint_from_url,
    request,
)
from telos.resolver import _stdlib_resolver

_TIMEOUT_S = 1.5
_POLICY = TransportPolicy(
    allow_public=False,
    allow_private=True,
    allow_loopback=True,
    require_https_for_public=True,
)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    health: BackendHealth
    models: tuple[str, ...]


def _candidate_authorizer(url: str) -> EndpointAuthorizer:
    """Authorize only this candidate for HEALTH_PROBE.

    Telos remains the authority: the normalized endpoint is admitted for
    this purpose, and transport policy constrains the resolved destination.
    """
    candidate = endpoint_from_url(url)
    return EndpointAuthorizer.from_exact_rules(
        {EndpointPurpose.HEALTH_PROBE: {candidate.key}},
        version="oramasys-health-probe-v1",
    )


def _offline() -> ProbeResult:
    return ProbeResult(BackendHealth.OFFLINE, ())


def _transport_failure(exc: Exception) -> bool:
    return isinstance(exc, (EndpointPolicyError, OSError)) or type(exc).__module__ == "http.client"


async def health_probe(base_url: str, *, timeout: float = _TIMEOUT_S) -> ProbeResult:
    """Probe ``base_url`` through Telos and return advisory health plus model ids."""
    url = base_url.rstrip("/") + "/models"
    try:
        response = await asyncio.to_thread(
            request,
            "GET",
            url,
            authorizer=_candidate_authorizer(url),
            transport_policy=_POLICY,
            actor_id="oramasys-discovery",
            workflow_id="health-probe",
            purpose=EndpointPurpose.HEALTH_PROBE,
            run_id=token_urlsafe(12),
            timeout=timeout,
            resolver=_stdlib_resolver,
        )
    except Exception as exc:
        if not _transport_failure(exc):
            raise
        return _offline()
    if response.status != 200:
        return _offline()
    try:
        body = json.loads(response.body)
        models = tuple(item["id"] for item in body.get("data", []) if "id" in item)
    except (ValueError, KeyError, TypeError):
        return ProbeResult(BackendHealth.DEGRADED, ())
    return ProbeResult(BackendHealth.ONLINE, models)
