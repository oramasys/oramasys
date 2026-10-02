"""Read-only MCP JSON-RPC: initialize / tools/list / tools/call search_docs."""
from __future__ import annotations

import json
from typing import Any, Mapping

from orama.knowledge.jsonrpc import QUERY_INVALID, bounded_query, rpc_error, rpc_result
from orama.knowledge.search import SearchUnavailable, bounded_search

PROTOCOL = "2026-07-28"
_SERVER_INFO = {"name": "orama-knowledge", "version": "1.0.0"}
_SERVER_INFO_META = "io.modelcontextprotocol/serverInfo"
_SEARCH_DOCS_TOOL = {
    "name": "search_docs",
    "description": "Search local Orama project documentation (read-only)",
    "annotations": {"readOnlyHint": True},
    "inputSchema": {
        "type": "object",
        "properties": {"query": {"type": "string", "minLength": 2, "maxLength": 200}},
        "required": ["query"],
        "additionalProperties": False,
    },
}


def _hello() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": dict(_SERVER_INFO),
    }


def _with_meta(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result")
    if isinstance(result, dict):
        meta = dict(result.get("_meta") or {})
        meta.setdefault(_SERVER_INFO_META, _SERVER_INFO)
        payload = {**payload, "result": {**result, "_meta": meta}}
    return payload


def _header(headers: Mapping[str, str], name: str) -> str | None:
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    return getter(name)


async def dispatch(body: dict[str, Any], headers: Mapping[str, str]) -> dict[str, Any] | None:
    request_id = body.get("id")
    method = body.get("method")
    if _header(headers, "Mcp-Protocol-Version") != PROTOCOL:
        return rpc_error(request_id, -32600, f"Mcp-Protocol-Version must be {PROTOCOL}")
    if _header(headers, "Mcp-Method") != method:
        return rpc_error(request_id, -32600, "Mcp-Method header must match the JSON-RPC method")
    if method == "notifications/initialized":
        return None
    if method in {"initialize", "server/discover"}:
        return _with_meta(rpc_result(request_id, _hello()))
    if method == "tools/list":
        return _with_meta(rpc_result(request_id, {"tools": [_SEARCH_DOCS_TOOL]}))
    if method == "tools/call":
        return await _call_tool(request_id, body, headers)
    return rpc_error(request_id, -32601, "Method not found")


async def _call_tool(
    request_id: Any, body: dict[str, Any], headers: Mapping[str, str]
) -> dict[str, Any]:
    params = body.get("params", {})
    if not isinstance(params, dict):
        return rpc_error(request_id, -32602, "Invalid params")
    if _header(headers, "Mcp-Name") != params.get("name"):
        return rpc_error(request_id, -32600, "Mcp-Name header must match params.name")
    if params.get("name") != "search_docs":
        return rpc_error(request_id, -32601, "Unknown tool")
    arguments = params.get("arguments", {})
    query = arguments.get("query", "") if isinstance(arguments, dict) else ""
    try:
        query = bounded_query(query)
    except ValueError:
        return rpc_error(request_id, -32602, QUERY_INVALID)
    try:
        hits = await bounded_search(query)
    except SearchUnavailable as exc:
        return rpc_error(request_id, -32000, str(exc))
    return _with_meta(
        rpc_result(
            request_id,
            {
                "content": [{"type": "text", "text": json.dumps(hits)}],
                "structuredContent": {"hits": hits},
                "isError": False,
            },
        )
    )
