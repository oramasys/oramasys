from __future__ import annotations

import ast
import inspect

from perpetua_core.discovery import probe


def _has_httpx_import(tree: ast.AST) -> bool:
    """AST-based, not substring: catches every import form, including
    aliases (`import httpx as h`, `from httpx import AsyncClient as C`),
    which a literal "import httpx" substring check would miss entirely."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "httpx" or alias.name.startswith("httpx.") for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "httpx" or node.module.startswith("httpx.")):
                return True
    return False


def _calls_exact_rules_authorizer(tree: ast.AST) -> bool:
    """AST-based: matches a call to `EndpointAuthorizer.from_exact_rules`
    (or an aliased import of it) rather than a literal source substring."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "from_exact_rules":
                return True
    return False


def test_core_health_probe_has_no_raw_httpx_transport() -> None:
    source = inspect.getsource(probe)
    tree = ast.parse(source)

    assert not _has_httpx_import(tree)
    assert _calls_exact_rules_authorizer(tree)
    assert "AlwaysAllowHealthProbeAuthorizer" not in source


def test_core_health_probe_uses_telos_request_transport() -> None:
    source = inspect.getsource(probe)
    tree = ast.parse(source)

    telos_imported = any(
        isinstance(node, ast.ImportFrom) and node.module == "telos"
        for node in ast.walk(tree)
    )
    request_imported = any(
        isinstance(node, ast.ImportFrom) and node.module == "telos"
        and any(alias.name == "request" for alias in node.names)
        for node in ast.walk(tree)
    )

    assert telos_imported
    assert request_imported
    assert "allow_public=False" in source
    assert "allow_private=True" in source
    assert "allow_loopback=True" in source
