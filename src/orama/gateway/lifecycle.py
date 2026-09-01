"""Fail-closed Gateway Lifecycle orchestrator."""

from __future__ import annotations

import asyncio
import hashlib

from orama.gateway.contracts import (
    AgatePort,
    ClaudeProviderPort,
    GatewayLifecycleRequest,
    GatewayLifecycleResult,
    GatewayProgressEvent,
    PhylaxPort,
    ProgressEventSink,
    RoutingState,
    RoutingStateStore,
    TelosPort,
)


class GatewayLifecycle:
    def __init__(
        self,
        *,
        telos: TelosPort,
        phylax: PhylaxPort,
        agate: AgatePort,
        claude: ClaudeProviderPort,
        store: RoutingStateStore,
        events: ProgressEventSink,
    ) -> None:
        self._telos = telos
        self._phylax = phylax
        self._agate = agate
        self._claude = claude
        self._store = store
        self._event_sink = events

    async def run(self, request: GatewayLifecycleRequest) -> GatewayLifecycleResult:
        run_events: list[GatewayProgressEvent] = []
        key: str | None = None
        claimed = False

        async def emit(
            phase: str, status: str, details: dict[str, object] | None = None
        ) -> None:
            safe_details = await self._phylax.redact(details) if details else {}
            event = GatewayProgressEvent(
                sequence=len(run_events) + 1,
                phase=phase,
                status=status,
                details=safe_details,
            )
            run_events.append(event)
            await self._event_sink.emit(event.model_copy(deep=True))

        async def fail(
            status: str,
            reason_code: str,
            routing_state: RoutingState | None = None,
        ) -> GatewayLifecycleResult:
            nonlocal claimed
            if claimed and key is not None:
                try:
                    await self._store.abort(key)
                except Exception:
                    reason_code = "state_claim_abort_failed"
                claimed = False
            try:
                await emit("failed", status)
            except Exception:
                pass
            return GatewayLifecycleResult(
                status=status,
                reason_code=reason_code,
                routing_state=routing_state,
                events=tuple(run_events),
            )

        try:
            await emit("started", "running")
            consent = request.operator_consent
            if not (
                consent.accepted
                and consent.artifact_id == request.artifact.artifact_id
                and consent.version == request.artifact.version
            ):
                return await fail("denied", "operator_consent_required")

            key = self._idempotency_key(request)
            existing = await self._store.claim(key)
            if existing is not None:
                if not self._stored_state_matches(existing, request, key):
                    return await fail("error", "routing_state_corrupt")
                await emit("already_ready", "already_ready")
                return GatewayLifecycleResult(
                    status="already_ready",
                    reason_code="idempotent_replay",
                    routing_state=existing,
                    events=tuple(run_events),
                )
            claimed = True

            config = await self._telos.authorize(
                purpose="config", endpoint=request.config_endpoint
            )
            if not config.allowed or not config.endpoint_ref:
                return await fail("denied", config.reason_code)

            health = await self._telos.authorize(
                purpose="health", endpoint=request.health_endpoint
            )
            if not health.allowed or not health.endpoint_ref:
                return await fail("denied", health.reason_code)
            await emit(
                "endpoints_authorized",
                "running",
                {"policy_version": health.policy_version},
            )

            artifact = await self._phylax.verify_artifact(request.artifact)
            if not artifact.allowed or not artifact.decision_ref:
                return await fail("denied", artifact.reason_code)
            await emit(
                "artifact_verified",
                "running",
                {"decision_ref": artifact.decision_ref or ""},
            )

            placement = await self._agate.resolve_placement(
                provider_kind=request.provider_kind,
                model_hint=request.model_hint,
            )
            if not placement.allowed or not placement.placement_ref:
                return await fail("denied", placement.reason_code)
            await emit(
                "placement_resolved",
                "running",
                {"placement_ref": placement.placement_ref},
            )

            admission = await self._phylax.admit_runtime(
                artifact=request.artifact,
                placement_ref=placement.placement_ref,
            )
            if not admission.allowed or not admission.decision_ref:
                return await fail("denied", admission.reason_code)
            await emit(
                "runtime_admitted",
                "running",
                {"decision_ref": admission.decision_ref or ""},
            )

            try:
                async with asyncio.timeout(request.readiness_timeout_seconds):
                    readiness = await self._claude.ensure_ready(
                        provider_kind=request.provider_kind,
                        placement_ref=placement.placement_ref,
                        config_endpoint_ref=config.endpoint_ref,
                        health_endpoint_ref=health.endpoint_ref,
                        timeout_seconds=request.readiness_timeout_seconds,
                    )
            except TimeoutError:
                return await fail("timed_out", "readiness_timeout")
            if readiness.timed_out:
                return await fail("timed_out", readiness.reason_code)
            if not readiness.ready or not readiness.provider_ref:
                return await fail("error", readiness.reason_code)
            await emit(
                "provider_ready",
                "running",
                {"provider_ref": readiness.provider_ref},
            )

            routing_state = RoutingState(
                gateway_id=request.gateway_id,
                idempotency_key=key,
                artifact=request.artifact,
                provider_kind=request.provider_kind,
                provider_ref=readiness.provider_ref,
                placement_ref=placement.placement_ref,
                placement_policy_version=placement.policy_version,
                config_endpoint_ref=config.endpoint_ref,
                health_endpoint_ref=health.endpoint_ref,
                config_telos_policy_version=config.policy_version,
                health_telos_policy_version=health.policy_version,
                artifact_decision_ref=artifact.decision_ref,
                admission_decision_ref=admission.decision_ref,
                artifact_phylax_policy_version=artifact.policy_version,
                admission_phylax_policy_version=admission.policy_version,
            )
            await self._store.complete(key, routing_state)
            claimed = False
            try:
                await emit("routing_state_written", "running")
                await emit("completed", "ready")
                reason_code = "ready"
            except Exception:
                reason_code = "ready_with_event_delivery_error"
            return GatewayLifecycleResult(
                status="ready",
                reason_code=reason_code,
                routing_state=routing_state,
                events=tuple(run_events),
            )
        except asyncio.CancelledError:
            if claimed and key is not None:
                try:
                    await asyncio.shield(self._store.abort(key))
                finally:
                    claimed = False
            raise
        except Exception:
            return await fail("error", "owner_unavailable")

    @staticmethod
    def _idempotency_key(request: GatewayLifecycleRequest) -> str:
        payload = request.model_dump_json(exclude={"operator_consent"})
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _stored_state_matches(
        state: RoutingState, request: GatewayLifecycleRequest, key: str
    ) -> bool:
        return (
            state.idempotency_key == key
            and state.gateway_id == request.gateway_id
            and state.artifact == request.artifact
            and state.provider_kind == request.provider_kind
        )
