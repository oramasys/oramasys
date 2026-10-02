"""Thin HTTP handlers for the Knowledge Portal (each ≤ 10 lines)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from starlette.responses import HTMLResponse, JSONResponse

from orama.knowledge import a2a as a2a_mod
from orama.knowledge import mcp as mcp_mod
from orama.knowledge.jsonrpc import QUERY_MAX, rpc_body, rpc_error
from orama.knowledge.search import SearchUnavailable, bounded_search

router = APIRouter()
# Isolated public shell: data-free HTML only. Drop this route + PUBLIC spec to revert D2.
_PAGE = Path(__file__).resolve().with_name("static") / "index.html"


@router.get("/api/knowledge/search", tags=["knowledge"])
async def knowledge_search(
    q: str = Query(..., min_length=2, max_length=QUERY_MAX),
    limit: int = Query(8, ge=1, le=20),
) -> dict[str, Any]:
    try:
        hits = await bounded_search(q, limit)
    except SearchUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {"query": q, "hits": hits, "read_only": True}


@router.post("/api/mcp", tags=["knowledge"], response_class=Response)
async def mcp(request: Request) -> Response:
    body, error = await rpc_body(request)
    if error is not None or body is None:
        return JSONResponse(error or rpc_error(None, -32600, "Invalid Request"))
    result = await mcp_mod.dispatch(body, request.headers)
    return Response(status_code=202) if result is None else JSONResponse(result)


@router.post("/api/a2a", tags=["knowledge"])
async def a2a(request: Request) -> dict[str, Any]:
    body, error = await rpc_body(request)
    if error is not None or body is None:
        return error or rpc_error(None, -32600, "Invalid Request")
    return await a2a_mod.dispatch(body)


@router.get("/.well-known/agent-card.json", tags=["knowledge"])
async def well_known_agent_card(request: Request) -> dict[str, Any]:
    return a2a_mod.agent_card(str(request.base_url).rstrip("/"))


@router.get("/knowledge", include_in_schema=False, tags=["knowledge"])
async def knowledge_page() -> HTMLResponse:
    return HTMLResponse(_PAGE.read_text(encoding="utf-8"))
