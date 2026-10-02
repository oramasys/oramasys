"""Shared JSON-RPC helpers for MCP and A2A (A2A must not import MCP)."""
from __future__ import annotations

import json
from typing import Any

from fastapi import Request

QUERY_MAX = 200
QUERY_INVALID = "query must be a string of 2 to 200 characters"


def rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


async def rpc_body(request: Request) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None, rpc_error(None, -32700, "Parse error")
    if not isinstance(body, dict):
        return None, rpc_error(None, -32600, "Invalid Request")
    return body, None


def bounded_query(query: Any, *, already_stripped: bool = False) -> str:
    if not isinstance(query, str):
        raise ValueError(QUERY_INVALID)
    candidate = query.strip() if not already_stripped else query
    if len(candidate) < 2 or len(query) > QUERY_MAX:
        raise ValueError(QUERY_INVALID)
    return query
