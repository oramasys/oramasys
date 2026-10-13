"""oramasys FastAPI glass-window — handlers ≤ 10 lines each."""
import asyncio
import logging
import uuid

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


def create_app(
    *,
    runner: GraphRunner | None = None,
    compiled_graph: object | None = None,
    adjustment_consumer: AdjustmentGrantConsumer | None = None,
) -> FastAPI:
    """Build the API with an explicit graph runner; absent admission refuses work.

    ``adjustment_consumer`` is the only way grants can be spent. Without one the
    adjustment route refuses every request, so an unwired deployment is inert by
    construction rather than by omission.
    """
    app = FastAPI(title="oramasys", version="2.0.0-alpha.1")
    install_authz(app)
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
        """Report process availability without revealing admission configuration."""
        return {"status": "ok", "version": "2.0.0-alpha.1"}

    return app


app = create_app()
