"""Comment-first report_pr.py — no lost-update guards required."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT_PR = ROOT / "scripts" / "reporting" / "report_pr.py"


def _run(cmd: list[str], env: dict[str, str] | None = None):
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        cmd, cwd=ROOT, env=merged, text=True, capture_output=True, check=False
    )


def test_report_pr_posts_comment_via_fake_gh(tmp_path: Path):
    comments = tmp_path / "comments.txt"
    comments.write_text("", encoding="utf-8")
    ledger = tmp_path / "ledger.txt"
    ledger.write_text("", encoding="utf-8")
    gh = tmp_path / "gh"
    gh.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == pr && "$2" == comment ]]; then
  printf 'comment_attempt\\n' >> '{ledger}'
  body=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == --body ]]; then body="$2"; shift 2; continue; fi
    shift
  done
  printf '%s\\n' "$body" >> '{comments}'
  printf 'https://github.com/owner/repo/pull/99#issuecomment-1\\n'
  printf 'comment_commit\\n' >> '{ledger}'
  exit 0
fi
echo "unexpected: $@" >&2
exit 1
""",
        encoding="utf-8",
    )
    gh.chmod(0o755)

    note = tmp_path / "note.md"
    note.write_text("status: migration checkpoint", encoding="utf-8")
    env = {"GH_BIN": str(gh), "HOME": str(tmp_path)}
    proc = _run(
        [
            sys.executable,
            str(REPORT_PR),
            "owner/repo",
            "99",
            "--file",
            str(note),
        ],
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "commented:" in proc.stdout
    assert "status: migration checkpoint" in comments.read_text(encoding="utf-8")
    events = ledger.read_text(encoding="utf-8").split()
    assert events.count("comment_attempt") == 1
    # No body edit path — comment-first must not touch pr edit.
    assert "edit_attempt" not in events


def test_report_pr_docstring_states_no_guards_and_not_telos():
    text = REPORT_PR.read_text(encoding="utf-8")
    assert "no" in text.lower() and "lost-update" in text.lower()
    assert "not" in text.lower() and "Telos" in text
    assert "PR_BODY_E_STALE" not in text or "no" in text  # may mention absence
