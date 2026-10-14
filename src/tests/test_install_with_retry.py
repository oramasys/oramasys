"""Bounded pip retries with non-sensitive durable reports."""
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def helper():
    spec = importlib.util.spec_from_file_location("install_with_retry", ROOT / "scripts/install_with_retry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(helper, tmp_path, monkeypatch, errors):
    calls = []
    def fake(command, **kwargs):
        calls.append(command)
        error = errors[min(len(calls) - 1, len(errors) - 1)]
        return subprocess.CompletedProcess(command, bool(error), "", error)
    monkeypatch.setattr(helper.subprocess, "run", fake)
    monkeypatch.setattr(helper.time, "sleep", lambda _: None)
    report = tmp_path / "report.json"
    rc = helper.main(["--python", "/venv/bin/python", "--report", str(report), "--", "--no-deps", "package"])
    assert all(c == ["/venv/bin/python", "-m", "pip", "install", "--no-deps", "package"] for c in calls)
    return rc, json.loads(report.read_text()), calls


def test_transient_then_success(helper, tmp_path, monkeypatch):
    rc, report, calls = run(helper, tmp_path, monkeypatch, ["Temporary failure in name resolution secret-token", ""])
    assert rc == 0 and len(calls) == 2
    assert report == {"schema": 1, "attempts": 2, "classification": "success", "returncode": 0, "status": "success"}
    assert "secret-token" not in json.dumps(report)


@pytest.mark.parametrize("message", ["Temporary failure in name resolution", "Connection reset by peer", "ReadTimeoutError: timed out", "Network is unreachable"])
def test_transient_exhaustion(helper, tmp_path, monkeypatch, message):
    rc, report, calls = run(helper, tmp_path, monkeypatch, [message])
    assert rc != 0 and len(calls) == 3
    assert report["attempts"] == 3 and report["classification"] == "transient-network"
    assert report["status"] == "failed"


@pytest.mark.parametrize("message", [
    "ResolutionImpossible", "THESE PACKAGES DO NOT MATCH THE HASHES", "Invalid requirement: bad pin",
    "Could not find a version that satisfies the requirement", "fatal: reference is not a tree",
    "test failure", "401 Unauthorized", "unknown error", "SSL: CERTIFICATE_VERIFY_FAILED",
    "ResolutionImpossible; Connection reset by peer", "hash mismatch; Temporary failure in name resolution",
])
def test_permanent_and_unknown_never_retry(helper, tmp_path, monkeypatch, message):
    rc, report, calls = run(helper, tmp_path, monkeypatch, [message])
    assert rc != 0 and len(calls) == 1
    assert report["classification"] == "non-retryable"


def test_report_creation_fails_before_install(helper, tmp_path, monkeypatch):
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: pytest.fail("pip must not run"))
    assert helper.main(["--python", "python", "--report", str(tmp_path), "x"]) != 0


def test_report_update_failure_stops_retries(helper, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(helper.time, "sleep", lambda _: None)
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: calls.append(a) or subprocess.CompletedProcess(a, 1, "", "Connection reset by peer"))
    count = 0
    original = helper.write_report
    def writer(path, report):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("disk full")
        original(path, report)
    monkeypatch.setattr(helper, "write_report", writer)
    assert helper.main(["--python", "python", "--report", str(tmp_path / "r.json"), "x"]) != 0
    assert len(calls) == 1


def test_process_error_is_reported_without_details(helper, tmp_path, monkeypatch):
    def fail(*a, **k):
        raise OSError("secret executable path")
    monkeypatch.setattr(helper.subprocess, "run", fail)
    path = tmp_path / "r.json"
    assert helper.main(["--python", "python", "--report", str(path), "x"]) != 0
    report = json.loads(path.read_text())
    assert report["classification"] == "process-error" and report["attempts"] == 1
    assert "secret" not in json.dumps(report)
