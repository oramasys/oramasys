"""Knowledge Portal: Bearer on data routes, public metadata/shell, bounded search."""
from __future__ import annotations

import os
import threading
import time

import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from orama.api.authz.manifest import RouteCapability, capability_for
from orama.api.server import app
from orama.knowledge import search as search_mod
from orama.knowledge.page import shell_headers

_TOKEN = "test-control-plane-token-32b"
_MCP_HEADERS = {
    "Mcp-Protocol-Version": "2026-07-28",
    "Mcp-Method": "tools/call",
    "Mcp-Name": "search_docs",
}


@pytest.fixture
def docs_root(tmp_path, monkeypatch):
    root = tmp_path / "docs"
    root.mkdir()
    (root / "guide.md").write_text(
        "# Human Approval\nThe Amplifier Principle requires a human gate.",
        encoding="utf-8",
    )
    (root / "deploiement.md").write_text(
        "# Déploiement\nLe déploiement Nêxtwork est documenté ici.",
        encoding="utf-8",
    )
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(root))
    return root


@pytest.fixture
def bearer_env(monkeypatch):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", _TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    return _TOKEN


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {_TOKEN}"}


async def _client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_knowledge_routes_require_bearer(docs_root, bearer_env):
    async with await _client() as client:
        search = await client.get("/api/knowledge/search?q=human")
        mcp = await client.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        a2a = await client.post("/api/a2a", json={"jsonrpc": "2.0", "id": 1, "method": "message/send"})
        wrong = await client.get(
            "/api/knowledge/search?q=human",
            headers={"Authorization": "Bearer wrong-token-value-here!!"},
        )
    assert search.status_code == 401
    assert mcp.status_code == 401
    assert a2a.status_code == 401
    assert wrong.status_code == 401


async def test_knowledge_routes_503_when_token_unconfigured(docs_root, monkeypatch):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with await _client() as client:
        resp = await client.get("/api/knowledge/search?q=human")
    assert resp.status_code == 503


async def test_agent_card_public_metadata_only(docs_root, monkeypatch):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with await _client() as client:
        resp = await client.get("/.well-known/agent-card.json")
    assert resp.status_code == 200
    card = resp.json()
    assert card["skills"][0]["id"] == "search-docs"
    assert card["url"].endswith("/api/a2a")
    assert card["securitySchemes"]["bearer"]["scheme"] == "bearer"
    assert card["capabilities"]["pushNotifications"] is False
    assert "Amplifier" not in resp.text


async def test_knowledge_page_public_and_data_free(docs_root, monkeypatch, bearer_env):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    async with await _client() as client:
        resp = await client.get("/knowledge")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert "Search documentation" in body
    assert "unsafe-inline" not in body
    assert "Amplifier" not in body
    assert _TOKEN not in body
    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "connect-src 'self'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert csp == shell_headers(body)["Content-Security-Policy"]
    assert "sha256-" in csp
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"


async def test_authenticated_search_returns_hits(docs_root, bearer_env):
    async with await _client() as client:
        resp = await client.get("/api/knowledge/search?q=human", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["hits"][0]["path"] == "guide.md"
    assert body["read_only"] is True


async def test_accented_query_matches_folded_docs(docs_root, bearer_env):
    async with await _client() as client:
        resp = await client.get("/api/knowledge/search?q=deploiement", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["hits"][0]["path"] == "deploiement.md"


async def test_mcp_initialize_tools_list_and_search_docs(docs_root, bearer_env):
    headers = {**_auth(), "Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "initialize"}
    async with await _client() as client:
        init = await client.post(
            "/api/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
        )
        listed = await client.post(
            "/api/mcp",
            headers={**_auth(), "Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        discovered = await client.post(
            "/api/mcp",
            headers={**_auth(), "Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"},
            json={"jsonrpc": "2.0", "id": "d", "method": "server/discover", "params": {}},
        )
        called = await client.post(
            "/api/mcp",
            headers={**_auth(), **_MCP_HEADERS},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"query": "Amplifier"}},
            },
        )
    assert init.status_code == 200
    assert init.json()["result"]["protocolVersion"] == "2026-07-28"
    assert discovered.json()["result"]["serverInfo"]["name"] == "orama-knowledge"
    tools = listed.json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["search_docs"]
    assert tools[0]["annotations"]["readOnlyHint"] is True
    assert called.json()["result"]["structuredContent"]["hits"][0]["path"] == "guide.md"


async def test_mcp_initialized_notification_202(docs_root, bearer_env):
    async with await _client() as client:
        resp = await client.post(
            "/api/mcp",
            headers={
                **_auth(),
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Method": "notifications/initialized",
            },
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
    assert resp.status_code == 202
    assert resp.content == b""


async def test_mcp_protocol_errors(docs_root, bearer_env):
    async with await _client() as client:
        missing = await client.post(
            "/api/mcp",
            headers=_auth(),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"query": "Amplifier"}},
            },
        )
        malformed = await client.post(
            "/api/mcp",
            headers={
                **_auth(),
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Method": "initialize",
                "Content-Type": "application/json",
            },
            content="{not-json",
        )
        too_long = await client.post(
            "/api/mcp",
            headers={**_auth(), **_MCP_HEADERS},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"query": "ab" + "x" * 199}},
            },
        )
        unknown = await client.post(
            "/api/mcp",
            headers={
                **_auth(),
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "not_a_tool",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "not_a_tool", "arguments": {"query": "Amplifier"}},
            },
        )
    assert missing.json()["error"]["code"] == -32600
    assert malformed.status_code == 200
    assert malformed.json()["error"]["code"] == -32700
    assert too_long.json()["error"]["code"] == -32602
    assert unknown.json()["error"]["code"] == -32601


async def test_a2a_message_send_and_task_methods(docs_root, bearer_env):
    payload = {
        "jsonrpc": "2.0",
        "id": "a2a-1",
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "m-1",
                "role": "user",
                "parts": [{"kind": "text", "text": "Amplifier Principle"}],
            }
        },
    }
    async with await _client() as client:
        sent = await client.post("/api/a2a", headers=_auth(), json=payload)
        tasks_get = await client.post(
            "/api/a2a",
            headers=_auth(),
            json={"jsonrpc": "2.0", "id": "t", "method": "tasks/get", "params": {}},
        )
        tasks_cancel = await client.post(
            "/api/a2a",
            headers=_auth(),
            json={"jsonrpc": "2.0", "id": "c", "method": "tasks/cancel", "params": {}},
        )
        push = await client.post(
            "/api/a2a",
            headers=_auth(),
            json={
                "jsonrpc": "2.0",
                "id": "p",
                "method": "tasks/pushNotificationConfig/set",
                "params": {},
            },
        )
        bad_part = await client.post(
            "/api/a2a",
            headers=_auth(),
            json={
                "jsonrpc": "2.0",
                "id": "a2a-bad",
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": "m-bad",
                        "role": "user",
                        "parts": [{"kind": "text", "text": 42}],
                    }
                },
            },
        )
    result = sent.json()["result"]
    assert result["kind"] == "message"
    assert result["parts"][0]["data"]["hits"]
    assert "_meta" not in result
    assert "_meta" not in sent.json()
    assert tasks_get.json()["error"]["code"] == -32001
    assert tasks_cancel.json()["error"]["code"] == -32001
    assert push.json()["error"]["code"] == -32601
    assert bad_part.json()["error"]["code"] == -32602


def test_symlink_escape_is_not_indexed(tmp_path, monkeypatch):
    secret_dir = tmp_path / "outside"
    docs = tmp_path / "docs"
    secret_dir.mkdir()
    docs.mkdir()
    secret = secret_dir / "secret.md"
    secret.write_text("# Secret\nUNIQUE_SYMLINK_ESCAPE_TERM\n", encoding="utf-8")
    link = docs / "escape.md"
    try:
        os.symlink(secret, link)
    except OSError:
        pytest.skip("symlinks unsupported")
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(docs.resolve()))
    hits = search_mod.search_docs("UNIQUE_SYMLINK_ESCAPE_TERM")
    assert hits == []


def test_search_respects_max_files_scan(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    for index in range(5):
        (docs / f"doc-{index}.md").write_text(f"# Doc {index}\nneedle-{index}", encoding="utf-8")
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(docs))
    monkeypatch.setenv("ORAMA_KNOWLEDGE_MAX_FILES_SCAN", "2")
    hits = search_mod.search_docs("needle")
    assert len(hits) <= 2


async def test_search_timeout_maps_to_503_and_minus_32000(docs_root, bearer_env, monkeypatch):
    def _slow(query: str, limit: int = 8, deadline: float | None = None):
        time.sleep(1.5)
        return []

    monkeypatch.setenv("ORAMA_KNOWLEDGE_SEARCH_TIMEOUT_S", "0.5")
    monkeypatch.setattr(search_mod, "search_docs", _slow)
    async with await _client() as client:
        http = await client.get("/api/knowledge/search?q=human", headers=_auth())
        mcp = await client.post(
            "/api/mcp",
            headers={**_auth(), **_MCP_HEADERS},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search_docs", "arguments": {"query": "human"}},
            },
        )
        a2a = await client.post(
            "/api/a2a",
            headers=_auth(),
            json={
                "jsonrpc": "2.0",
                "id": "t",
                "method": "message/send",
                "params": {
                    "message": {"messageId": "m", "role": "user", "parts": [{"kind": "text", "text": "human"}]}
                },
            },
        )
    assert http.status_code == 503
    assert mcp.json()["error"]["code"] == -32000
    assert a2a.json()["error"]["code"] == -32000


async def test_search_busy_maps_to_503(docs_root, bearer_env):
    original = search_mod._slots
    slots = threading.BoundedSemaphore(1)
    assert slots.acquire(blocking=False)
    search_mod._slots = slots
    try:
        async with await _client() as client:
            resp = await client.get("/api/knowledge/search?q=human", headers=_auth())
        assert resp.status_code == 503
        assert "busy" in resp.json()["detail"]
    finally:
        search_mod._slots = original
        slots.release()


async def test_insecure_dev_loopback_reads_without_token(docs_root, monkeypatch):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://127.0.0.1"
    ) as client:
        resp = await client.get("/api/knowledge/search?q=human")
    assert resp.status_code == 200
    assert resp.json()["hits"][0]["path"] == "guide.md"


def test_every_app_route_is_declared():
    expected = {
        ("GET", "/api/knowledge/search"): RouteCapability.READ,
        ("POST", "/api/mcp"): RouteCapability.READ,
        ("POST", "/api/a2a"): RouteCapability.READ,
        ("GET", "/.well-known/agent-card.json"): RouteCapability.PUBLIC,
        ("GET", "/knowledge"): RouteCapability.PUBLIC,
    }
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            if method == "HEAD" and "GET" in route.methods:
                continue
            cap = capability_for(method, route.path)
            assert cap is not None, f"undeclared {(method, route.path)}"
    for key, cap in expected.items():
        assert capability_for(*key) is cap


def test_env_helpers_fall_back_on_garbage(monkeypatch):
    monkeypatch.setenv("ORAMA_KNOWLEDGE_MAX_FILES_SCAN", "nope")
    monkeypatch.setenv("ORAMA_KNOWLEDGE_SEARCH_TIMEOUT_S", "nope")
    monkeypatch.setenv("ORAMA_KNOWLEDGE_MAX_CONCURRENT_SEARCHES", "")
    assert search_mod._max_files_scan() == 2000
    assert search_mod._search_timeout_s() == 8.0
    assert search_mod._max_concurrent_searches() == 4


def test_excerpt_centers_on_late_match(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    prefix = "Opening prose. " * 40
    body = f"# Intro\n{prefix}Accented Déploiement UNIQUE_NEEDLE sits far from the opening.\n"
    (docs / "late.md").write_text(body, encoding="utf-8")
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(docs))
    hits = search_mod.search_docs("UNIQUE_NEEDLE")
    excerpt = hits[0]["excerpt"]
    leading = " ".join(body.split())[:280]
    assert hits[0]["path"] == "late.md"
    assert "UNIQUE_NEEDLE" in excerpt
    assert excerpt != leading
    assert excerpt.startswith("…")


def test_search_empty_terms_missing_root_and_deadline(tmp_path, monkeypatch):
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(tmp_path / "missing"))
    assert search_mod.search_docs("human") == []
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text("# Human\nhuman gate\n", encoding="utf-8")
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(docs))
    assert search_mod.search_docs("??") == []
    assert search_mod.search_docs("human", deadline=time.monotonic() - 1) == []


def test_search_skips_oversized_file(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "tiny.md").write_text("# Tiny\nkeep-me-token\n", encoding="utf-8")
    (docs / "huge.md").write_text("# Huge\nkeep-me-token\n", encoding="utf-8")
    monkeypatch.setenv("ORAMA_DOCS_ROOT", str(docs))
    monkeypatch.setattr(search_mod, "_MAX_DOC_BYTES", 8)
    hits = search_mod.search_docs("keep-me-token")
    assert hits == []


def test_search_walk_oserror_does_not_raise(monkeypatch):
    class _Boom:
        def is_dir(self) -> bool:
            return True

        def rglob(self, pattern: str):
            raise OSError("walk failed")

    monkeypatch.setattr(search_mod, "docs_root", lambda: _Boom())
    assert search_mod.search_docs("human") == []


async def test_mcp_method_not_found_and_bad_params(docs_root, bearer_env):
    async with await _client() as client:
        missing_method = await client.post(
            "/api/mcp",
            headers={**_auth(), "Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "nope"},
            json={"jsonrpc": "2.0", "id": 9, "method": "nope"},
        )
        bad_params = await client.post(
            "/api/mcp",
            headers={**_auth(), **_MCP_HEADERS},
            json={"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": []},
        )
        array_body = await client.post(
            "/api/a2a",
            headers=_auth(),
            json=["not", "an", "object"],
        )
        malformed = await client.post(
            "/api/a2a",
            headers={**_auth(), "Content-Type": "application/json"},
            content="{not-json",
        )
    assert missing_method.json()["error"]["code"] == -32601
    assert bad_params.json()["error"]["code"] == -32602
    assert array_body.json()["error"]["code"] == -32600
    assert malformed.json()["error"]["code"] == -32700
