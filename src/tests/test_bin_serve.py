"""Launcher tests: bin/serve host-flag last-wins and duplicate stripping."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

SERVE = Path(__file__).resolve().parents[2] / "bin" / "serve"


def _run_lib(script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ORAMA_SERVE_LIB"] = "1"
    return subprocess.run(
        ["bash", "-c", f'source "{SERVE}"\n{script}'],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_parse_explicit_host_last_wins():
    result = _run_lib(
        'parse_explicit_host --reload --host 127.0.0.1 --host=::1 --port 9\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "::1"


def test_parse_explicit_host_equals_then_space_last_wins():
    result = _run_lib(
        'parse_explicit_host --host=127.0.0.1 --host 0.0.0.0\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0.0.0.0"


def test_collect_non_host_args_strips_all_host_flags():
    result = _run_lib(
        "collect_non_host_args rest --reload --host 127.0.0.1 --host=0.0.0.0 --port 8080\n"
        'printf "%s\\n" "${rest[@]}"\n'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["--reload", "--port", "8080"]
