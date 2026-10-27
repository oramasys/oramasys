"""Layering: the graph layer never imports the serving (api) layer."""
from __future__ import annotations

import ast
from pathlib import Path

import orama.graph as graph_package
from orama.api import public_errors
from orama.graph import effect_denial_codes


def _imported_modules(path: Path) -> set[str]:
    """Return every module name imported anywhere in the file, including inside functions."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def test_no_graph_module_imports_the_api_layer() -> None:
    """A lazy import counts: the dependency must point from api to graph only."""
    root = Path(graph_package.__file__).parent
    offenders = {
        path.name: sorted(n for n in _imported_modules(path) if n == "orama.api" or n.startswith("orama.api."))
        for path in root.rglob("*.py")
    }
    assert {name: found for name, found in offenders.items() if found} == {}


def test_the_api_layer_serves_the_same_mapping() -> None:
    """The api re-exports are the graph-layer functions, so the recorded code is the served code."""
    assert public_errors.public_effect_denial_code is effect_denial_codes.public_effect_denial_code
    assert public_errors.public_denial_code is effect_denial_codes.public_denial_code
    assert public_errors.public_effect_denial_code("approval_not_verified") == "deny.malformed_grant"
    assert public_errors.public_effect_denial_code("something_new") == "deny.verifier_unavailable"
