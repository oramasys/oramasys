"""oramasys FastAPI glass-window — handlers ≤ 10 lines each."""
import uuid

from fastapi import FastAPI, HTTPException, Request
from orama.api.authz import authenticated_control_plane_principal, install_authz
from orama.api.contracts import RunRequest, RunResponse
from orama.graph.admission import AdmissionRefused
from orama.graph.admission_runtime import (
    AuthenticatedGraphRunnerFactory,
    GraphRunner,
    UnconfiguredGraphRunner,
)
from orama.graph.perpetua_graph import graph


def create_app(*, runner: GraphRunner | None = None, compiled_graph: object | None = None) -> FastAPI:
    """Build the API with an explicit graph runner; absent admission refuses work."""
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
            raise HTTPException(
                status_code=503,
                detail={"code": "run_unavailable", "correlation_id": str(uuid.uuid4())},
            ) from error
        return RunResponse.from_state(result)

    @app.get("/health")
    async def health() -> dict:
        """Report process availability without revealing admission configuration."""
        return {"status": "ok", "version": "2.0.0-alpha.1"}

    return app


app = create_app()
