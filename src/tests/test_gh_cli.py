"""Local gh helper: one transport LF, and a timeout that still exits."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPORTING = ROOT / "scripts" / "reporting"
sys.path.insert(0, str(REPORTING))

from gh_cli import GH_TIMEOUT_SECONDS, run_gh, strip_transport_newline  # noqa: E402


def test_strip_transport_newline_drops_exactly_one_lf():
    assert strip_transport_newline("body\n") == "body"
    assert strip_transport_newline("body\n\n") == "body\n"
    assert strip_transport_newline("body") == "body"


def test_default_timeout_is_two_minutes():
    assert GH_TIMEOUT_SECONDS == 120


def test_run_gh_timeout_exits(tmp_path: Path):
    gh = tmp_path / "gh"
    gh.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    gh.chmod(0o755)
    with pytest.raises(SystemExit, match="timed out after 0.05s"):
        run_gh([str(gh)], timeout=0.05)
