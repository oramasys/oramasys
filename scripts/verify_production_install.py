"""Prove the production install is the pinned Core, installed cleanly and runnable.

Run from outside the checkout in an isolated interpreter (``python -I``) after
``pip install .``. Candidate checkouts and editable overlays are oracle evidence and are
rejected here. Identity comes from the PEP 610 ``direct_url.json`` record, because Core
exports no commit or version attribute. Exit status is 0 only if every check passes.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

CORE_DISTRIBUTION = "perpetua-core"
CORE_MODULE = "perpetua_core"
CORE_URL = "https://github.com/oramasys/perpetua-core.git"
ORAMA_DISTRIBUTION = "oramasys"
ORAMA_MODULE = "orama"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
PACKAGE_SYMBOLS = {CORE_MODULE: ("MiniGraph", "START", "END", "PerpetuaState"),
                   "perpetua_core.graph.spec": ("GraphSpec", "ReducerSpec", "JoinSpec")}


class InstallError(RuntimeError):
    """The environment is not a clean, non-editable install of the pinned Core."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise InstallError(message)


def _direct_url(dist: Any, label: str, *, required: bool) -> dict[str, Any] | None:
    raw = dist.read_text("direct_url.json")
    if raw is None:
        _need(not required, f"{label}: no direct_url.json, so the installed commit is unproven")
        return None
    try:
        record = json.loads(raw)
    except ValueError as error:
        raise InstallError(f"{label}: direct_url.json is not valid JSON") from error
    _need(isinstance(record, dict), f"{label}: direct_url.json is not an object")
    dir_info = record.get("dir_info")
    _need(not (isinstance(dir_info, dict) and dir_info.get("editable")),
          f"{label}: editable install is not production evidence")
    return record


def _check_core_identity(dist: Any, expected: str) -> None:
    record = _direct_url(dist, CORE_DISTRIBUTION, required=True)
    assert record is not None
    vcs = record.get("vcs_info")
    _need(isinstance(vcs, dict) and vcs.get("vcs") == "git",
          f"{CORE_DISTRIBUTION}: not a git installation (local or archive source rejected)")
    _need(record.get("url") == CORE_URL, f"{CORE_DISTRIBUTION}: unexpected source repository")
    _need(vcs.get("commit_id") == expected,
          f"{CORE_DISTRIBUTION}: installed commit {vcs.get('commit_id')!r} is not {expected}")


def _check_location(dist: Any, module: str, module_file: Callable[[str], str]) -> None:
    site = Path(dist.locate_file("")).resolve()
    origin = Path(module_file(module)).resolve()
    _need(origin.is_relative_to(site),
          f"{module} is imported from outside its installed distribution ({origin})")


def _check_symbols(import_module: Callable[[str], Any]) -> None:
    for name, symbols in PACKAGE_SYMBOLS.items():
        loaded = import_module(name)
        for symbol in symbols:
            _need(hasattr(loaded, symbol), f"{name} does not export {symbol}")


def _check_graph(import_module: Callable[[str], Any]) -> None:
    core = import_module(CORE_MODULE)
    spec_module = import_module("perpetua_core.graph.spec")
    try:
        graph = core.MiniGraph().add_node("verify", lambda state: {"scratchpad": {"ok": True}})
        graph.add_edge(core.START, "verify").add_edge("verify", core.END)
        final = asyncio.run(graph.compile().ainvoke(core.PerpetuaState(session_id="verify")))
        built = import_module("orama.graph.perpetua_graph").build_graph_spec()
    except Exception as error:  # any failure means the installed graph engine is unusable
        raise InstallError(f"graph smoke failed: {type(error).__name__}: {error}") from error
    _need(final.scratchpad.get("ok") is True, "graph smoke: node output was not applied")
    _need(isinstance(built, spec_module.GraphSpec), "graph smoke: Oramasys spec is not a GraphSpec")


def verify_production_install(
    expected_core_sha: str,
    *,
    distribution: Callable[[str], Any] = importlib.metadata.distribution,
    module_file: Callable[[str], str] | None = None,
    import_module: Callable[[str], Any] = importlib.import_module,
) -> None:
    """Raise InstallError unless the active environment is the clean production install."""
    _need(FULL_SHA.fullmatch(expected_core_sha or "") is not None,
          "expected Core revision must be a full lowercase commit SHA")
    locate = module_file or (lambda name: str(import_module(name).__file__))
    try:
        core, orama = distribution(CORE_DISTRIBUTION), distribution(ORAMA_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError as error:
        raise InstallError(f"distribution not installed: {error}") from error
    _check_core_identity(core, expected_core_sha)
    _direct_url(orama, ORAMA_DISTRIBUTION, required=False)
    _check_location(core, CORE_MODULE, locate)
    _check_location(orama, ORAMA_MODULE, locate)
    _check_symbols(import_module)
    _check_graph(import_module)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_production_install.py <full-core-sha>", file=sys.stderr)
        return 2
    try:
        verify_production_install(argv[1])
    except InstallError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"OK: clean non-editable install of Core {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
