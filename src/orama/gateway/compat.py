"""Transitional Perpetua-Tools compatibility façade."""

from __future__ import annotations

from orama.gateway.contracts import GatewayLifecycleRequest, GatewayLifecycleResult
from orama.gateway.lifecycle import GatewayLifecycle


class PerpetuaToolsGatewayFacade:
    def __init__(self, lifecycle: GatewayLifecycle) -> None:
        self._lifecycle = lifecycle

    async def run(self, request: GatewayLifecycleRequest) -> GatewayLifecycleResult:
        return await self._lifecycle.run(request)
