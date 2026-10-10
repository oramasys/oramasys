"""A2A agent-card metadata and synchronous message/send docs search."""
from __future__ import annotations

import uuid
from typing import Any

from orama.knowledge.jsonrpc import QUERY_INVALID, bounded_query, rpc_error, rpc_result
from orama.knowledge.search import SearchUnavailable, bounded_search

_TEXT_PARTS_INVALID = "text parts must be strings"
_NO_TASK = "No task exists: read-only searches return a direct Message"


def agent_card(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/")
    return {
        "name": "Orama Knowledge Gateway",
        "description": "Read-only search over curated project documentation",
        "url": f"{base}/api/a2a",
        "version": "1.0.0",
        "protocolVersion": "0.3.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["application/json"],
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "security": [{"bearer": []}],
        "skills": [
            {
                "id": "search-docs",
                "name": "Search documentation",
                "description": "Returns ranked excerpts from local Markdown documentation",
                "tags": ["docs", "search"],
                "examples": ["human approval gate"],
            }
        ],
    }


def _text_from_message(params: Any) -> str:
    message = params.get("message", {}) if isinstance(params, dict) else {}
    parts = message.get("parts", []) if isinstance(message, dict) else []
    texts: list[str] = []
    for part in parts:
        if not isinstance(part, dict) or part.get("kind", part.get("type")) != "text":
            continue
        text = part.get("text", "")
        if not isinstance(text, str):
            raise ValueError(_TEXT_PARTS_INVALID)
        texts.append(text)
    return " ".join(texts).strip()


async def dispatch(body: dict[str, Any]) -> dict[str, Any]:
    request_id = body.get("id")
    method = body.get("method")
    if method == "message/send":
        return await _message_send(request_id, body.get("params", {}))
    if method in {"tasks/get", "tasks/cancel"}:
        return rpc_error(request_id, -32001, _NO_TASK)
    return rpc_error(request_id, -32601, "Method not found")


async def _message_send(request_id: Any, params: Any) -> dict[str, Any]:
    try:
        query = _text_from_message(params)
    except ValueError:
        return rpc_error(request_id, -32602, _TEXT_PARTS_INVALID)
    try:
        query = bounded_query(query, already_stripped=True)
    except ValueError:
        return rpc_error(request_id, -32602, QUERY_INVALID)
    try:
        hits = await bounded_search(query)
    except SearchUnavailable as exc:
        return rpc_error(request_id, -32000, str(exc))
    return rpc_result(
        request_id,
        {
            "kind": "message",
            "messageId": str(uuid.uuid4()),
            "role": "agent",
            "parts": [{"kind": "data", "data": {"hits": hits, "read_only": True}}],
        },
    )
