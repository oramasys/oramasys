"""Runtime-proven coverage of append_pr_summary.py integrity checkpoints.

Port of the v1 ledgered-fake-transport + explicit-manifest + bidirectional
structural pattern. REQUIRED_CHECKPOINTS is hand-maintained policy — never
derived from the script (deletion must stay visible).
"""
from __future__ import annotations

import json as jsonlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
APPEND_PY = ROOT / "scripts" / "reporting" / "append_pr_summary.py"
GRANT_LIB = ROOT / "scripts" / "reporting" / "grant_lib.py"

CURSOR_END = "<!-- CURSOR_AGENT_PR_BODY_END -->"
ORIGINAL_BODY = f"## Summary\n\noriginal operator summary\n{CURSOR_END}"


@dataclass(frozen=True)
class GuardScenario:
    expected_code: str
    mutate_before_view: int | None = None
    edit_mode: str = "normal"
    expected_edit_count: int = 0


REQUIRED_CHECKPOINTS: dict[str, GuardScenario] = {
    "PR_BODY_E_STALE_ON_REREAD": GuardScenario(
        expected_code="PR_BODY_E_STALE_ON_REREAD",
        mutate_before_view=2,
        expected_edit_count=0,
    ),
    "PR_BODY_E_STALE_PREWRITE": GuardScenario(
        expected_code="PR_BODY_E_STALE_PREWRITE",
        mutate_before_view=3,
        expected_edit_count=0,
    ),
    "PR_BODY_E_POSTWRITE_MISMATCH": GuardScenario(
        expected_code="PR_BODY_E_POSTWRITE_MISMATCH",
        edit_mode="corrupt",
        expected_edit_count=1,
    ),
}


def _run(cmd: list[str], env: dict[str, str] | None = None):
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        cmd, cwd=ROOT, env=merged, text=True, capture_output=True, check=False
    )


@pytest.fixture()
def ledgered_gh(tmp_path: Path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    body_file = tmp_path / "remote_body.txt"
    body_file.write_text(ORIGINAL_BODY, encoding="utf-8")
    ledger = tmp_path / "ledger.txt"
    ledger.write_text("", encoding="utf-8")
    count_file = tmp_path / "view_count.txt"
    count_file.write_text("0", encoding="utf-8")

    gh = bin_dir / "gh"
    gh.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == pr && "$2" == view ]]; then
  count=$(cat '{count_file}')
  count=$((count + 1))
  printf '%s' "$count" > '{count_file}'
  printf 'view:%s\\n' "$count" >> '{ledger}'
  if [[ -n "${{FAKE_GH_MUTATE_BEFORE_VIEW:-}}" \\
        && "$count" == "${{FAKE_GH_MUTATE_BEFORE_VIEW}}" ]]; then
    printf '%s\\n' 'remote_mutation' >> '{ledger}'
    printf '%s' '## Summary

concurrent operator edit
{CURSOR_END}' > '{body_file}'
  fi
  printf '%s' "$(cat '{body_file}')"
  exit 0
fi
if [[ "$1" == pr && "$2" == edit ]]; then
  printf '%s\\n' 'edit_attempt' >> '{ledger}'
  body_path=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == --body-file ]]; then body_path="$2"; shift 2; continue; fi
    shift
  done
  if [[ "${{FAKE_GH_EDIT_MODE:-normal}}" == corrupt ]]; then
    printf '%s' 'corrupted by transport' > '{body_file}'
  else
    printf '%s' "$(cat "$body_path")" > '{body_file}'
  fi
  printf '%s\\n' 'edit_commit' >> '{ledger}'
  exit 0
fi
exit 0
""",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    return gh, body_file, ledger


def _mint_grant(gh_bin: Path, append: Path, tmp_path: Path) -> dict[str, str]:
    env = {
        "PR_BODY_GRANT_HMAC_SECRET": "ledger-secret",
        "GH_BIN": str(gh_bin),
        "HOME": str(tmp_path),
    }
    mint = _run(
        [
            sys.executable,
            str(GRANT_LIB),
            "mint",
            "--repo",
            "owner/repo",
            "--pr",
            "99",
            "--file",
            str(append),
        ],
        env=env,
    )
    assert mint.returncode == 0, mint.stderr
    return env


@pytest.mark.parametrize(
    "code", sorted(REQUIRED_CHECKPOINTS), ids=sorted(REQUIRED_CHECKPOINTS)
)
def test_required_integrity_checkpoint_is_reachable_at_runtime(
    code: str, ledgered_gh, tmp_path: Path
):
    scenario = REQUIRED_CHECKPOINTS[code]
    gh_bin, _body_file, ledger = ledgered_gh
    append = tmp_path / "note.md"
    append.write_text("operator note", encoding="utf-8")
    env = _mint_grant(gh_bin, append, tmp_path)

    trace = tmp_path / "guard_trace.txt"
    env["PR_BODY_GUARD_TRACE_FILE"] = str(trace)
    env["FAKE_GH_EDIT_MODE"] = scenario.edit_mode
    if scenario.mutate_before_view is not None:
        env["FAKE_GH_MUTATE_BEFORE_VIEW"] = str(scenario.mutate_before_view)

    proc = _run(
        [
            sys.executable,
            str(APPEND_PY),
            "owner/repo",
            "99",
            "--file",
            str(append),
            "--title",
            "Follow-up: test",
        ],
        env=env,
    )

    assert proc.returncode != 0, f"guard {code} did not fail: {proc.stdout}{proc.stderr}"

    traced = trace.read_text(encoding="utf-8").split() if trace.exists() else []
    assert traced == [scenario.expected_code], (
        f"expected exactly one guard event {scenario.expected_code!r}, got {traced!r}"
    )

    events = ledger.read_text(encoding="utf-8").split()
    edits = events.count("edit_attempt")
    assert edits == scenario.expected_edit_count, (
        f"expected {scenario.expected_edit_count} edit(s), saw {edits}; ledger={events!r}"
    )


def test_stale_detection_leaves_the_remote_body_untouched(ledgered_gh, tmp_path: Path):
    gh_bin, body_file, ledger = ledgered_gh
    append = tmp_path / "note.md"
    append.write_text("operator note", encoding="utf-8")
    env = _mint_grant(gh_bin, append, tmp_path)
    env["FAKE_GH_MUTATE_BEFORE_VIEW"] = "3"

    proc = _run(
        [
            sys.executable,
            str(APPEND_PY),
            "owner/repo",
            "99",
            "--file",
            str(append),
            "--title",
            "Follow-up: test",
        ],
        env=env,
    )

    assert proc.returncode != 0
    remote = body_file.read_text(encoding="utf-8")
    assert "concurrent operator edit" in remote
    assert "operator note" not in remote
    assert "edit_attempt" not in ledger.read_text(encoding="utf-8")


def test_manifest_and_implementation_agree_in_both_directions():
    script = APPEND_PY.read_text(encoding="utf-8")
    implemented = set(re.findall(r'guard_trace\("?(PR_BODY_E_[A-Z_]+)"?\)', script))
    # Also accept keyword form guard_trace("CODE")
    implemented |= set(re.findall(r"guard_trace\([\"'](PR_BODY_E_[A-Z_]+)[\"']\)", script))
    required = set(REQUIRED_CHECKPOINTS)

    assert implemented == required, (
        f"manifest/implementation drift.\n"
        f"  implemented but not required: {sorted(implemented - required)}\n"
        f"  required but not implemented: {sorted(required - implemented)}"
    )


def test_postwrite_mismatch_does_not_release_the_grant_reservation(
    ledgered_gh, tmp_path: Path
):
    gh_bin, _body_file, _ledger = ledgered_gh
    append = tmp_path / "note.md"
    append.write_text("operator note", encoding="utf-8")
    env = _mint_grant(gh_bin, append, tmp_path)
    env["FAKE_GH_EDIT_MODE"] = "corrupt"

    proc = _run(
        [
            sys.executable,
            str(APPEND_PY),
            "owner/repo",
            "99",
            "--file",
            str(append),
            "--title",
            "Follow-up: test",
        ],
        env=env,
    )

    assert proc.returncode != 0

    state_path = tmp_path / ".cursor" / "pr-body-grant-nonces.json"
    assert state_path.is_file(), "expected a nonce-state file after a write attempt"
    state = jsonlib.loads(state_path.read_text(encoding="utf-8"))
    reservations = state.get("reservations", {})
    assert reservations, (
        "reservation was deleted after a write that genuinely reached the remote"
    )
    (entry,) = reservations.values()
    assert entry.get("remote_applied") is True


def test_happy_path_appends_follow_up(ledgered_gh, tmp_path: Path):
    gh_bin, body_file, ledger = ledgered_gh
    append = tmp_path / "note.md"
    append.write_text("operator note", encoding="utf-8")
    env = _mint_grant(gh_bin, append, tmp_path)

    proc = _run(
        [
            sys.executable,
            str(APPEND_PY),
            "owner/repo",
            "99",
            "--file",
            str(append),
            "--title",
            "Follow-up: test",
        ],
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    remote = body_file.read_text(encoding="utf-8")
    assert "## Follow-up: test" in remote
    assert "operator note" in remote
    assert "original operator summary" in remote
    assert ledger.read_text(encoding="utf-8").count("edit_attempt") == 1


def test_gh_not_routed_via_telos_is_documented():
    for path in (APPEND_PY, ROOT / "scripts" / "reporting" / "report_pr.py"):
        text = path.read_text(encoding="utf-8")
        assert "not" in text.lower() and "Telos" in text
        assert "local trusted" in text.lower() or "trusted subprocess" in text.lower()
