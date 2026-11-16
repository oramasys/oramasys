"""Platform-keyed C6 latency budgets: native Windows scheduled p95 differs, nothing else does.

Operator decision 2026-11-16: native Windows scheduled p95 <= 150 ms (provisional until the
service-account re-measure). Mac/POSIX keeps the 2026-11-07 amendment: scheduled and
successful-call send p95 <= 60 ms. Scheduled p99 <= 250 ms everywhere.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def budget(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the scripts-level budget module the way the harness tests do."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts"))
    return importlib.import_module("c6_latency_budget")


def _result(scheduled_p95: float | None, send_p95: float | None = 40.0,
            scheduled_p99: float | None = 160.0) -> dict:
    """Shape of benchmark_revocation_availability output that the budget reads."""
    return {
        "scheduled_latency": {"p95_ms": scheduled_p95, "p99_ms": scheduled_p99},
        "send_latency": {"p95_ms": send_p95},
    }


def test_windows_scheduled_p95_at_150_passes(budget: ModuleType) -> None:
    assert budget.violations(_result(150.0), "windows-native") == []


def test_windows_scheduled_p95_at_151_fails(budget: ModuleType) -> None:
    assert budget.violations(_result(151.0), "windows-native") == ["scheduled_p95_ms 151.0 > 150"]


def test_posix_scheduled_p95_keeps_60(budget: ModuleType) -> None:
    assert budget.violations(_result(60.0), "posix") == []
    assert budget.violations(_result(61.0), "posix") == ["scheduled_p95_ms 61.0 > 60"]


def test_posix_does_not_inherit_the_windows_budget(budget: ModuleType) -> None:
    assert budget.violations(_result(139.2), "posix")


def test_windows_send_p95_stays_60(budget: ModuleType) -> None:
    assert budget.violations(_result(100.0, send_p95=61.0), "windows-native") == [
        "send_p95_ms 61.0 > 60"]


@pytest.mark.parametrize("key", ["posix", "windows-native"])
def test_scheduled_p99_stays_250_everywhere(budget: ModuleType, key: str) -> None:
    assert budget.violations(_result(50.0, scheduled_p99=251.0), key) == [
        "scheduled_p99_ms 251.0 > 250"]


@pytest.mark.parametrize("missing", ["scheduled", "send", "p99"])
def test_missing_measurement_fails_closed(budget: ModuleType, missing: str) -> None:
    values = {"scheduled": (None, 40.0, 160.0), "send": (50.0, None, 160.0),
              "p99": (50.0, 40.0, None)}[missing]
    assert budget.violations(_result(*values), "posix")


def test_unknown_platform_key_is_refused(budget: ModuleType) -> None:
    with pytest.raises(ValueError):
        budget.violations(_result(10.0), "darwin")


def test_platform_key_maps_only_nt_to_windows(budget: ModuleType) -> None:
    assert budget.platform_key("nt") == "windows-native"
    assert budget.platform_key("posix") == "posix"


def test_windows_budget_is_recorded_as_provisional(budget: ModuleType) -> None:
    entry = budget.BUDGETS["windows-native"]
    assert entry["status"] == "provisional"
    assert "service-account" in entry["pending"]
    assert budget.BUDGETS["posix"]["status"] == "ratified"


def test_pr100_evidence_runs_fit_the_windows_budget(budget: ModuleType) -> None:
    """The four PR 100 runs (scheduled p95 / p99) sit inside the new Windows budget."""
    for p95, p99 in ((139.2, 162.8), (138.4, 164.7), (139.1, 168.5), (136.3, 166.7)):
        assert budget.violations(_result(p95, scheduled_p99=p99), "windows-native") == []


def test_cli_exit_code_and_no_qualification_claim(budget: ModuleType, tmp_path: Path,
                                                  capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(_result(61.0)))
    assert budget.main([str(path), "--platform", "posix"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["within_budget"] is False
    assert report["qualifies_run"] is False
