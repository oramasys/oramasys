"""Final qualification cannot pass missing collection, inactive gates or skips."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def gate_module():
    spec = importlib.util.spec_from_file_location(
        "collection_gate", ROOT / "scripts/collection_gate.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def packet() -> dict:
    return {
        "required_modules": ["src/tests/core_gate/test_ready.py"],
        "historical_only_modules": ["src/tests/core_gate/test_absent.py"],
        "required_environment": ["ORAMA_REQUIRE_CORE_GATE"],
        "required_setup_inputs": ["ORAMA_DOCS_V2_REGISTRY"],
        "final_cell_skips_allowed": 0,
    }


def environment() -> dict[str, str]:
    return {"ORAMA_REQUIRE_CORE_GATE": "1", "ORAMA_DOCS_V2_REGISTRY": "registry.json"}


def test_collection_accepts_only_real_required_tests() -> None:
    assert (
        gate_module().check_collection(
            packet(), ["src/tests/core_gate/test_ready.py::test_run"], environment()
        )
        == []
    )


@pytest.mark.parametrize(
    "nodes",
    [
        [],
        ["src/tests/other.py::test_run"],
        [
            "src/tests/core_gate/test_ready.py::test_run",
            "src/tests/core_gate/test_absent.py::test_old",
        ],
        ["src/tests/core_gate/test_ready.py::test_run"] * 2,
        [None],
    ],
)
def test_collection_rejects_empty_missing_historical_duplicate_or_malformed(
    nodes: list,
) -> None:
    assert gate_module().check_collection(packet(), nodes, environment())


@pytest.mark.parametrize("value", ["", "0", "false"])
def test_named_gate_must_be_active(value: str) -> None:
    env = environment()
    env["ORAMA_REQUIRE_CORE_GATE"] = value
    assert gate_module().check_collection(
        packet(), ["src/tests/core_gate/test_ready.py::test_run"], env
    )


def test_setup_input_is_required() -> None:
    env = environment()
    del env["ORAMA_DOCS_V2_REGISTRY"]
    assert gate_module().check_collection(
        packet(), ["src/tests/core_gate/test_ready.py::test_run"], env
    )


@pytest.mark.parametrize(
    "xml",
    [
        "<testsuites/>",
        '<testsuite tests="0"/>',
        '<testsuite tests="1" skipped="1"/>',
        '<testsuite tests="1" failures="1"/>',
        "<bad",
    ],
)
def test_result_gate_rejects_empty_skipped_failed_or_invalid(xml: str) -> None:
    with pytest.raises(ValueError):
        gate_module().check_results(xml)


def test_result_gate_accepts_nonempty_success() -> None:
    assert (
        gate_module().check_results(
            '<testsuite tests="2" failures="0" errors="0" skipped="0"/>'
        )
        == 2
    )
