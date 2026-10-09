"""Framework-free package invariant with adversarial tests of the scanner itself."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import subprocess
import sys
import tomllib

import pytest

ROOTS = {"langchain", "langchain_core", "langchain_community", "langchain_openai",
         "langgraph", "pydantic_ai", "pydantic_ai_slim"}
PACKAGE = "orama"
ALLOWLIST = {"compat/pydantic_ai_bridge.py": {"pydantic_ai"}}
SOURCE = Path(__file__).resolve().parents[1] / PACKAGE


def classify(source: str) -> list[tuple[str, str]]:
    """Classify framework imports without exempting else bodies or defaults."""
    findings: list[tuple[str, str]] = []

    def walk(node: ast.AST, lazy: bool = False, typing: bool = False) -> None:
        """Treat function defaults/decorators as eager and only TYPE_CHECKING bodies as typing."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for child in ast.iter_child_nodes(node):
                if child in (node.body if isinstance(node.body, list) else [node.body]):
                    walk(child, True, typing)
                else:
                    walk(child, lazy, typing)
            return
        if isinstance(node, ast.If):
            is_typing = (isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING") or (
                isinstance(node.test, ast.Attribute) and isinstance(node.test.value, ast.Name)
                and node.test.value.id == "typing" and node.test.attr == "TYPE_CHECKING")
            walk(node.test, lazy, typing)
            for child in node.body:
                walk(child, lazy, typing or is_typing)
            for child in node.orelse:
                walk(child, lazy, typing)
            return
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        elif isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name in {"import_module", "__import__"} and node.args and isinstance(node.args[0], ast.Constant):
                value = node.args[0].value
                if isinstance(value, str) and value.split(".")[0] in ROOTS:
                    findings.append((value.split(".")[0], "TYPING" if typing else "DYNAMIC"))
        for name in names:
            if name.split(".")[0] in ROOTS:
                findings.append((name.split(".")[0], "TYPING" if typing else "LAZY" if lazy else "EAGER"))
        for child in ast.iter_child_nodes(node):
            walk(child, lazy, typing)

    walk(ast.parse(source))
    return findings


def test_ast_and_live_allowlist() -> None:
    """No eager dependency or stale call-time permission is allowed."""
    seen: set[tuple[str, str]] = set()
    for path in SOURCE.rglob("*.py"):
        relative = path.relative_to(SOURCE).as_posix()
        for root, kind in classify(path.read_text(encoding="utf-8")):
            if kind == "TYPING":
                continue
            assert kind == "LAZY" and root in ALLOWLIST.get(relative, set()), (relative, root, kind)
            seen.add((relative, root))
    assert seen == {(path, root) for path, roots in ALLOWLIST.items() for root in roots}


def test_tripwire_imports_every_module() -> None:
    """A blocker both records and prevents computed import-time imports."""
    code = f'''
import importlib, importlib.abc, pkgutil, sys
hits = []
class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {ROOTS!r}:
            hits.append(fullname)
            raise ModuleNotFoundError('framework import blocked', name=fullname)
sys.meta_path.insert(0, Blocker())
sys.path.insert(0, {str(SOURCE.parent)!r})
top = importlib.import_module({PACKAGE!r})
for info in pkgutil.walk_packages(top.__path__, top.__name__ + '.'):
    importlib.import_module(info.name)
assert not hits, hits
'''
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


def test_published_metadata_has_no_framework_dependencies() -> None:
    """Published runtime, extra, and build dependencies remain framework-free."""
    data = tomllib.loads((SOURCE.parents[1] / "pyproject.toml").read_text())
    project = data["project"]
    dependencies = project.get("dependencies", []) + data["build-system"].get("requires", [])
    dependencies += [item for group in project.get("optional-dependencies", {}).values() for item in group]
    for dependency in dependencies:
        name = re.split(r"[ <>=!~;\[@]", dependency.strip(), maxsplit=1)[0].lower().replace("_", "-")
        assert not any(name == family or name.startswith(family + "-")
                       for family in ("langchain", "langgraph", "pydantic-ai")), dependency


@pytest.mark.parametrize(("source", "kind"), [
    ("import langgraph", "EAGER"),
    ("from langchain_core.runnables import Runnable", "EAGER"),
    ("def f():\n import langgraph", "LAZY"),
    ("class C:\n def f(self):\n  import pydantic_ai", "LAZY"),
    ("importlib.import_module('langgraph')", "DYNAMIC"),
    ("def f(x=__import__('langgraph')): pass", "DYNAMIC"),
    ("if NOT_TYPE_CHECKING:\n import langgraph", "EAGER"),
    ("if TYPE_CHECKING:\n pass\nelse:\n import langgraph", "EAGER"),
    ("if TYPE_CHECKING:\n import langgraph", "TYPING"),
])
def test_scanner_adversarial_cases(source: str, kind: str) -> None:
    """Planted violations and exact typing exemptions test the checker itself."""
    assert classify(source)[0][1] == kind


def test_lookalikes_are_not_frameworks() -> None:
    """Do not flag Pydantic itself or similarly named independent modules."""
    assert classify("import pydantic\nimport langgraphish") == []
