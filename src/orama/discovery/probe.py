"""Telos-backed discovery health probe owned by Oramasys composition.

Perpetua-Core retains pure backend types and selection logic. Outbound
endpoint-policy and SSRF authority stay in Telos; this module only expresses
discovery intent and maps Telos outcomes into BackendHealth.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from secrets import token_urlsafe

from perpetua_core.discovery.backend import BackendHealth
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
    """Authorize only the explicit discovery candidate for HEALTH_PROBE.

    Discovery supplies intent for one concrete endpoint. Telos remains the
    semantic authority: the exact normalized endpoint is admitted for this
    purpose, while transport policy independently constrains the resolved
    destination classes and secure connection behavior.
    """

    candidate = endpoint_from_url(url)
    return EndpointAuthorizer.from_exact_rules(
        {EndpointPurpose.HEALTH_PROBE: {candidate.key}},
        version="orama-health-probe-v1",
    )


def _is_http_client_error(exc: BaseException) -> bool:
    # Telos uses stdlib http.client under the hood. Malformed responses raise
    # http.client.HTTPException subclasses. Importing http.client here would
    # violate Oramasys's Telos-only outbound network authority gate.
    return exc.__class__.__module__ == "http.client"


async def health_probe(base_url: str, *, timeout: float = _TIMEOUT_S) -> ProbeResult:
    url = base_url.rstrip("/") + "/models"
    try:
        response = await asyncio.to_thread(
            request,
            "GET",
            url,
            authorizer=_candidate_authorizer(url),
            transport_policy=_POLICY,
            actor_id="orama-discovery",
            workflow_id="health-probe",
            purpose=EndpointPurpose.HEALTH_PROBE,
            run_id=token_urlsafe(12),
            timeout=timeout,
            resolver=_stdlib_resolver,
        )
    except EndpointPolicyError:
        return ProbeResult(BackendHealth.OFFLINE, ())
    except OSError:
        return ProbeResult(BackendHealth.OFFLINE, ())
    except Exception as exc:
        if _is_http_client_error(exc):
            return ProbeResult(BackendHealth.OFFLINE, ())
        raise
    if response.status != 200:
        return ProbeResult(BackendHealth.OFFLINE, ())
    try:
        body = json.loads(response.body)
        models = tuple(item["id"] for item in body.get("data", []) if "id" in item)
    except (ValueError, KeyError, TypeError):
        return ProbeResult(BackendHealth.DEGRADED, ())
    return ProbeResult(BackendHealth.ONLINE, models)
