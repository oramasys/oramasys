"""oramasys FastAPI glass-window — handlers ≤ 10 lines each."""
from fastapi import FastAPI
from orama.api.contracts import RunRequest, RunResponse
from orama.graph.perpetua_graph import graph

app = FastAPI(title="oramasys", version="2.0.0-alpha.1")


@app.post("/run", response_model=RunResponse)
async def run(req: RunRequest) -> RunResponse:
    state = req.to_state()
    result = await graph.ainvoke(state)
    return RunResponse.from_state(result)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "2.0.0-alpha.1"}
