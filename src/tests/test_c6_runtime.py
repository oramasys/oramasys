"""Qualify the actual SQLite library without importing the optional producer."""
from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the benchmark runtime helper independently of Phylax."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts"))
    return importlib.import_module("c6_runtime")


@pytest.mark.parametrize("version", [(3, 45, 3), (3, 50, 7), (3, 51, 2)])
def test_old_or_unverified_backport_refuses(runtime: ModuleType, version: tuple[int, ...]) -> None:
    """Unpatched mainline and unverified backports cannot qualify WAL."""
    with pytest.raises(RuntimeError, match="SQLite"):
        runtime.require_sqlite_version(version)


@pytest.mark.parametrize("version", [(3, 51, 3), (3, 53, 1), (3, 54, 0)])
def test_newer_patched_runtime_is_accepted(runtime: ModuleType, version: tuple[int, ...]) -> None:
    """The safety gate is a floor, not brittle equality with one artifact."""
    runtime.require_sqlite_version(version)


def test_receipt_identifies_embedded_library(runtime: ModuleType) -> None:
    """Capture the serving/benchmark library, not the separate CLI."""
    receipt = runtime.runtime_receipt()
    assert receipt["sqlite_version"]
    assert receipt["sqlite_source_id"]
    assert receipt["python"]
    assert receipt["compile_options"]


def test_runtime_gate_reads_python_library(runtime: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """A safe standalone CLI does not override Python's vulnerable embedded library."""
    monkeypatch.setattr(runtime.sqlite3, "sqlite_version_info", (3, 45, 3))
    with pytest.raises(RuntimeError, match="SQLite"):
        runtime.require_c6_runtime()
