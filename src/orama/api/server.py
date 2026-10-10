"""oramasys FastAPI glass-window — handlers ≤ 10 lines each."""
from fastapi import FastAPI, HTTPException
from orama.api.authz import install_authz
from orama.api.contracts import RunRequest, RunResponse
from orama.graph.admission import AdmissionRefused
from orama.graph.admission_runtime import GraphRunner, UnconfiguredGraphRunner
from orama.graph.perpetua_graph import graph


def create_app(*, runner: GraphRunner | None = None, compiled_graph: object | None = None) -> FastAPI:
    """Build the API with an explicit graph runner; absent admission refuses work."""
    app = FastAPI(title="oramasys", version="2.0.0-alpha.1")
    install_authz(app)
    active_runner = runner or UnconfiguredGraphRunner()
    active_graph = graph if compiled_graph is None else compiled_graph

    @app.post("/run", response_model=RunResponse)
    async def run(req: RunRequest) -> RunResponse:
        """Run only through the configured admission-aware invocation boundary."""
        try:
            result = await active_runner.invoke(active_graph, req.to_state())
        except AdmissionRefused as error:
            raise HTTPException(status_code=503, detail=error.reason) from error
        return RunResponse.from_state(result)

    @app.get("/health")
    async def health() -> dict:
        """Report process availability without revealing admission configuration."""
        return {"status": "ok", "version": "2.0.0-alpha.1"}

    return app


app = create_app()
