#!/usr/bin/env python3
"""Comment-first PR status reporting for oramasys (v2 default).

v2 default path for findings / status updates: post an independent PR *comment*
via the local ``gh`` CLI. Comments are their own objects — there is no
lost-update race against the PR body, so this tool intentionally carries
**no** ``PR_BODY_E_STALE_*`` / ``PR_BODY_E_POSTWRITE_MISMATCH`` integrity
guards. Those guards live only on the secondary body-edit path
(``append_pr_summary.py``), which exists solely for the repo-enforced
``## Summary`` convention.

Transport decision (decided, not open):

    ``gh`` is a local trusted subprocess. Do **not** route it through Telos.
    Telos owns IdP and purpose-scoped HTTP dials; ``gh`` auth (stored token /
    ``GH_TOKEN``) is a different trust surface.

Usage:
  scripts/reporting/report_pr.py <owner/repo> <pr-number> --file <note.md>
  scripts/reporting/report_pr.py <owner/repo> <pr-number> --message "markdown"
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Shared canonicalize import keeps one SSoT even though comments need no hash
# guards today — future comment digests / grant bindings reuse the same helper.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from canonicalize import sha256_canonical_text  # noqa: E402
from grant_lib import (  # noqa: E402
    GrantError,
    content_digest_for_append,
)


def _resolve_gh() -> str:
    gh = os.environ.get("GH_BIN", "gh")
    if shutil.which(gh) is None and not Path(gh).is_file():
        raise SystemExit("error: gh CLI required (local trusted subprocess, not Telos)")
    return gh


def _load_body(file_path: str | None, message: str | None) -> str:
    if file_path and message is not None:
        raise SystemExit("error: provide --file or --message, not both")
    if not file_path and message is None:
        raise SystemExit("error: provide --file or --message")
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise SystemExit(f"error: file not found: {path}")
        return path.read_text(encoding="utf-8")
    return message or ""


def post_comment(
    repo: str,
    pr_number: str,
    body: str,
    *,
    gh_bin: str | None = None,
) -> str:
    """Post ``body`` as a PR comment. Returns the comment URL from gh stdout."""
    gh = gh_bin or _resolve_gh()
    # Digest available for operators / future grant binding; comments themselves
    # do not require lost-update guards.
    _ = sha256_canonical_text(body)
    proc = subprocess.run(
        [
            gh,
            "pr",
            "comment",
            str(pr_number),
            "--repo",
            repo,
            "--body",
            body,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise SystemExit(f"error: gh pr comment failed: {err}")
    return (proc.stdout or "").strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Post a PR comment (v2 comment-first reporting). "
            "No body lost-update guards — comments are independent objects. "
            "gh is a local trusted subprocess, not Telos."
        )
    )
    parser.add_argument("repo", help="owner/repo")
    parser.add_argument("pr", help="PR number")
    parser.add_argument("--file")
    parser.add_argument("--message")
    args = parser.parse_args(argv)

    body = _load_body(args.file, args.message)
    if not body.strip():
        print("error: empty comment body", file=sys.stderr)
        return 1

    # Optional digest echo for operators correlating grants; grant is NOT
    # required for comments (low blast radius). Body-edit path requires it.
    try:
        digest = content_digest_for_append(args.file, args.message)
    except GrantError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    url = post_comment(args.repo, args.pr, body)
    print(f"commented: {url or f'https://github.com/{args.repo}/pull/{args.pr}'}")
    print(f"content-digest: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
