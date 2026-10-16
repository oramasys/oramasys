"""oramasys FastAPI glass-window — handlers ≤ 10 lines each."""
import asyncio
import logging
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from orama.api.authz import authenticated_control_plane_principal, install_authz
from orama.api.contracts import (
    AdjustmentReceiptResponse,
    AdjustmentRequest,
    RunRequest,
    RunResponse,
)
from orama.graph.admission import AdmissionRefused
from orama.graph.admission_runtime import (
    AuthenticatedGraphRunnerFactory,
    GraphRunner,
    UnconfiguredGraphRunner,
)
from orama.graph.grant_verifier import (
    VERIFICATION_REFUSAL_CODES,
    AdjustmentGrantConsumer,
    AdjustmentGrantRefused,
)
from orama.graph.perpetua_graph import graph

_log = logging.getLogger(__name__)


# Every verification-side refusal is 503 (the authority could not vouch for the grant);
# 409 is reserved for definitive ledger answers, i.e. the consumption refusals.


GRANT_CAPABILITY_STATES = ("disabled", "ready", "unavailable")


def create_app(
    *,
    runner: GraphRunner | None = None,
    compiled_graph: object | None = None,
    adjustment_consumer: AdjustmentGrantConsumer | None = None,
    grant_capability: str | None = None,
    grant_cleanup: Callable[[], None] | None = None,
) -> FastAPI:
    """Build the API with an explicit graph runner; absent admission refuses work.

    ``adjustment_consumer`` is the only way grants can be spent. Without one the
    adjustment route refuses every request, so an unwired deployment is inert by
    construction rather than by omission.

    ``grant_capability`` is the non-sensitive composition state reported by
    ``/health``. Only ``ready`` carries a consumer. ``grant_cleanup`` belongs to
    the composition root that opened a managed verifier; it releases retained
    read resources at shutdown and does not expose issuer operations to the API.
    """
    state = grant_capability if grant_capability is not None else (
        "ready" if adjustment_consumer is not None else "disabled"
    )
    if state not in GRANT_CAPABILITY_STATES:
        raise ValueError(f"unknown grant capability state {state!r}")
    if (state == "ready") != (adjustment_consumer is not None):
        raise ValueError("grant capability 'ready' requires exactly a wired consumer")
    if grant_cleanup is not None and state != "ready":
        raise ValueError("grant cleanup requires a ready capability")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        """Release the composition-owned verifier after serving has stopped."""
        try:
            yield
        finally:
            if grant_cleanup is not None:
                await asyncio.to_thread(grant_cleanup)

    app = FastAPI(title="oramasys", version="2.0.0-alpha.1", lifespan=lifespan)
    install_authz(app)
    from orama.workspace.api import router as workspace_router
    app.include_router(workspace_router)
    active_runner = runner or UnconfiguredGraphRunner()
    active_graph = graph if compiled_graph is None else compiled_graph

    @app.post("/run", response_model=RunResponse)
    async def run(req: RunRequest, request: Request) -> RunResponse:
        """Run only through the configured admission-aware invocation boundary."""
        try:
            request_runner = active_runner
            if isinstance(active_runner, AuthenticatedGraphRunnerFactory):
                principal = authenticated_control_plane_principal(request)
                if principal is None:
                    raise AdmissionRefused("admission.authenticated_context_required")
                request_runner = active_runner.for_authenticated_principal(principal)
            result = await request_runner.invoke(active_graph, req.to_state())
        except AdmissionRefused as error:
            correlation_id = str(uuid.uuid4())
            _log.warning(
                "run refused",
                extra={"correlation_id": correlation_id, "reason": error.reason},
            )
            raise HTTPException(
                status_code=503,
                detail={"code": "run_unavailable", "correlation_id": correlation_id},
            ) from error
        return RunResponse.from_state(result)

    @app.post("/adjustments", response_model=AdjustmentReceiptResponse)
    async def adjust(req: AdjustmentRequest, request: Request) -> AdjustmentReceiptResponse:
        """Spend one Phylax-issued grant against an unknown hold, as the caller."""
        principal = authenticated_control_plane_principal(request)
        if principal is None:
            raise HTTPException(status_code=401, detail={"code": "authentication_required"})
        correlation_id = str(uuid.uuid4())
        if adjustment_consumer is None:
            _log.warning("adjustment refused", extra={"correlation_id": correlation_id, "reason": "not_wired"})
            raise HTTPException(
                status_code=503,
                detail={"code": "adjustments_unavailable", "correlation_id": correlation_id},
            )
        try:
            receipt = await asyncio.to_thread(
                adjustment_consumer.consume, req.grant.encode("utf-8"), caller_principal=principal
            )
        except AdjustmentGrantRefused as refused:
            _log.warning(
                "adjustment refused",
                extra={"correlation_id": correlation_id, "reason": refused.code},
            )
            status = 503 if refused.code in VERIFICATION_REFUSAL_CODES else 409
            raise HTTPException(
                status_code=status,
                detail={"code": refused.code, "correlation_id": correlation_id},
            ) from refused
        return AdjustmentReceiptResponse(
            grant_id=receipt.grant_id,
            run_id=receipt.run_id,
            hold_id=receipt.hold_id,
            kind=receipt.kind,
            units_basis=receipt.units_basis,
            balance_delta=receipt.balance_delta,
            verifier_id=receipt.verifier_id,
            payload_digest=receipt.payload_digest,
        )

    @app.get("/health")
    async def health() -> dict:
        """Report process availability and non-sensitive grant composition state."""
        return {"status": "ok", "version": "2.0.0-alpha.1", "grants": state}

    return app


app = create_app()
