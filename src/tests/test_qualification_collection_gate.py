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


def test_junit_count_must_equal_collected_node_count() -> None:
    nodes = ["src/tests/core_gate/test_ready.py::test_a", "src/tests/core_gate/test_ready.py::test_b"]
    assert gate_module().check_count_agreement(nodes, 2) == []


@pytest.mark.parametrize("junit_total", [1, 3])
def test_junit_count_mismatch_is_refused_with_both_counts(junit_total: int) -> None:
    nodes = ["src/tests/core_gate/test_ready.py::test_a", "src/tests/core_gate/test_ready.py::test_b"]
    problems = gate_module().check_count_agreement(nodes, junit_total)
    assert len(problems) == 1
    assert "collected 2" in problems[0]
    assert f"junit {junit_total}" in problems[0]


def test_refusal_reason_reaches_stderr_and_stdout_verdict_stays_stable(
    tmp_path, capsys, monkeypatch
) -> None:
    import json

    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet()))
    collection_path = tmp_path / "collection.json"
    collection_path.write_text(
        json.dumps({"schema": 1, "node_ids": ["src/tests/core_gate/test_ready.py::test_a", "src/tests/core_gate/test_ready.py::test_b", "src/tests/core_gate/test_ready.py::test_c"]})
    )
    junit_path = tmp_path / "junit.xml"
    junit_path.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"/>')
    monkeypatch.setattr(
        "sys.argv", ["collection_gate.py", str(junit_path), str(packet_path), str(collection_path)]
    )
    monkeypatch.setenv("ORAMA_REQUIRE_CORE_GATE", "1")
    monkeypatch.setenv("ORAMA_DOCS_V2_REGISTRY", "registry.json")

    assert gate_module().main() == 1
    captured = capsys.readouterr()
    assert captured.out.strip() == "collection-refused: ValueError"
    assert "collected 3 nodes but junit 1 tests ran" in captured.err


def test_execution_must_match_collection_by_membership_not_count() -> None:
    collected = ["src/tests/a.py::test_one", "src/tests/a.py::test_two"]
    other = ["src/tests/a.py::test_one", "src/tests/b.py::test_three"]
    assert gate_module().check_execution(collected, collected) == []
    problems = gate_module().check_execution(collected, other)
    assert any("missing" in p for p in problems)
    assert any("unexpected" in p for p in problems)


def test_execution_refuses_duplicates_and_absent_tests() -> None:
    collected = ["src/tests/a.py::test_one", "src/tests/a.py::test_two"]
    assert gate_module().check_execution(collected, collected[:1])
    assert gate_module().check_execution(collected, collected + collected[:1])


def test_collection_report_without_executed_ids_is_refused(tmp_path, capsys, monkeypatch) -> None:
    import json

    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet()))
    collection_path = tmp_path / "collection.json"
    collection_path.write_text(
        json.dumps({"schema": 1, "node_ids": ["src/tests/core_gate/test_ready.py::test_a"]})
    )
    junit_path = tmp_path / "junit.xml"
    junit_path.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"/>')
    monkeypatch.setattr(
        "sys.argv", ["collection_gate.py", str(junit_path), str(packet_path), str(collection_path)]
    )
    monkeypatch.setenv("ORAMA_REQUIRE_CORE_GATE", "1")
    monkeypatch.setenv("ORAMA_DOCS_V2_REGISTRY", "registry.json")

    assert gate_module().main() == 1
    assert "executed_node_ids" in capsys.readouterr().err
