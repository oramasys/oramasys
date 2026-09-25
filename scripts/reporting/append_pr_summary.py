#!/usr/bin/env python3
"""Append-only PR *body* updates for the repo-enforced ``## Summary`` case.

Secondary v2 path — prefer ``report_pr.py`` (comment-first) for status updates.
Body replacement is kept only because CI elsewhere requires ``## Summary`` in
the PR body specifically, not in a comment.

Integrity guards (stable codes, ``guard_trace`` test seam):

  * ``PR_BODY_E_STALE_ON_REREAD`` — body changed after initial read
  * ``PR_BODY_E_STALE_PREWRITE`` — body digest changed immediately before write
  * ``PR_BODY_E_POSTWRITE_MISMATCH`` — remote body != merged body after write
    (compared via single-trailing-LF canonicalize — see ``canonicalize.py``)

Honest bound (Rule 7): GitHub's PR-body PATCH has no usable server-side CAS.
A pre-write re-read detects a concurrent edit *before* the check runs; the
window between the final check and the write is real and currently unclosable.

Transport decision (decided, not open):

    ``gh`` is a local trusted subprocess. Do **not** route it through Telos.
    Telos owns IdP and purpose-scoped HTTP dials; ``gh`` auth (stored token /
    ``GH_TOKEN``) is a different trust surface.

Usage:
  scripts/reporting/append_pr_summary.py <owner/repo> <pr> --file <append.md>
  scripts/reporting/append_pr_summary.py <owner/repo> <pr> --message "markdown"
  scripts/reporting/append_pr_summary.py <owner/repo> <pr> --title "..." --file <append.md>
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from canonicalize import sha256_canonical_file  # noqa: E402
from grant_lib import (  # noqa: E402
    follow_up_already_present,
    mark_remote_applied_for_append,
    reconcile_pending_consume,
    release_grant_for_append,
    reserve_grant_for_append,
    verify_grant_for_append,
)

CURSOR_BODY_END = "<!-- CURSOR_AGENT_PR_BODY_END -->"
CODERABBIT_MARKER = (
    "<!-- This is an auto-generated comment: release notes by coderabbit.ai -->"
)


def guard_trace(code: str) -> None:
    """Test-only seam: record which integrity guard was reached at runtime."""
    path = os.environ.get("PR_BODY_GUARD_TRACE_FILE")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(code + "\n")


def _resolve_gh() -> str:
    gh = os.environ.get("GH_BIN", "gh")
    if shutil.which(gh) is None and not Path(gh).is_file():
        raise SystemExit("error: gh CLI required (local trusted subprocess, not Telos)")
    return gh


def _normalize_follow_up_title(raw: str) -> str:
    rest = raw or ""
    if rest.startswith("Follow-up:"):
        rest = rest[len("Follow-up:") :]
    elif rest.startswith("Follow-up "):
        rest = rest[len("Follow-up ") :]
    elif rest.startswith("Follow-up"):
        rest = rest[len("Follow-up") :]
    return f"Follow-up: {rest.lstrip()}"


def _count_substring(haystack: str, needle: str) -> int:
    count = 0
    rest = haystack
    while needle in rest:
        count += 1
        rest = rest.split(needle, 1)[1]
    return count


def _resolve_git_backup_dir() -> Path:
    proc = subprocess.run(
        ["git", "rev-parse", "--git-common-dir"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit("error: must run inside a git repository")
    git_common = proc.stdout.strip()
    if not git_common.startswith("/"):
        top = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
        git_common = str(Path(top) / git_common)
    return Path(git_common).resolve() / "pr-body-backups"


def _gh_view_body(gh: str, repo: str, pr: str) -> str:
    proc = subprocess.run(
        [gh, "pr", "view", pr, "--repo", repo, "--json", "body", "--jq", ".body"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"error: gh pr view failed: {(proc.stderr or '').strip()}")
    return proc.stdout


def _gh_edit_body(gh: str, repo: str, pr: str, body_file: Path) -> None:
    proc = subprocess.run(
        [gh, "pr", "edit", pr, "--repo", repo, "--body-file", str(body_file)],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"error: gh pr edit failed: {(proc.stderr or '').strip()}")


def _merge_follow_up(current_body: str, title: str, append_block: str) -> str:
    follow_up = f"\n## {title}\n\n{append_block}"
    if CURSOR_BODY_END in current_body:
        return current_body.replace(
            CURSOR_BODY_END, f"{follow_up}\n{CURSOR_BODY_END}", 1
        )
    if CODERABBIT_MARKER in current_body:
        return current_body.replace(
            CODERABBIT_MARKER, f"{follow_up}\n\n{CODERABBIT_MARKER}", 1
        )
    return current_body + follow_up


def run_append(
    repo: str,
    pr: str,
    *,
    file_path: str | None,
    message: str | None,
    title: str | None = None,
) -> int:
    gh = _resolve_gh()

    ok, err = verify_grant_for_append(repo, pr, file_path, message, consume=False)
    if not ok:
        print(f"error: {err}", file=sys.stderr)
        print(
            "hint: mint a grant via scripts/reporting/grant_lib.py mint "
            "with the same --file|--message",
            file=sys.stderr,
        )
        return 1

    if not title:
        title = _normalize_follow_up_title(
            f"Follow-up ({datetime.now(timezone.utc).date().isoformat()})"
        )
    else:
        title = _normalize_follow_up_title(title)

    if file_path:
        append_block = Path(file_path).read_text(encoding="utf-8")
    else:
        append_block = message or ""

    grant_finalized = False
    remote_tmp = Path(tempfile.mkstemp(prefix="pr-remote-")[1])
    prewrite_tmp = Path(tempfile.mkstemp(prefix="pr-prewrite-")[1])
    postwrite_tmp = Path(tempfile.mkstemp(prefix="pr-postwrite-")[1])
    out = Path(tempfile.mkstemp(prefix="pr-out-")[1])

    def _cleanup() -> None:
        if not grant_finalized:
            release_grant_for_append(repo, pr, file_path, message)
        for path in (remote_tmp, prewrite_tmp, postwrite_tmp, out):
            path.unlink(missing_ok=True)

    try:
        remote_tmp.write_text(_gh_view_body(gh, repo, pr), encoding="utf-8")
        current_body_digest = sha256_canonical_file(remote_tmp)
        remote_body = remote_tmp.read_text(encoding="utf-8")

        if follow_up_already_present(remote_body, append_block, title):
            ok, err = reconcile_pending_consume(
                repo, pr, file_path, message, remote_body, title
            )
            if ok:
                grant_finalized = True
                print("OK: grant reconciled and consumed")
                print(f"updated: https://github.com/{repo}/pull/{pr}")
                return 0
            # Missing follow-up falls through; other reconcile errors abort.
            if "missing expected follow-up" not in err:
                print(f"error: {err}", file=sys.stderr)
                return 1

        ok, err = reserve_grant_for_append(repo, pr, file_path, message)
        if not ok:
            print(f"error: {err}", file=sys.stderr)
            return 1

        if CURSOR_BODY_END in append_block or CODERABBIT_MARKER in append_block:
            print(
                "error: append content must not contain reserved PR body delimiters",
                file=sys.stderr,
            )
            return 1

        backup_dir = _resolve_git_backup_dir()
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_slug = repo.replace("/", "-")
        backup_path = backup_dir / f"{safe_slug}-pr{pr}-{ts}.md"
        backup_path.write_text(remote_body + "\n", encoding="utf-8")
        print(f"backup: {backup_path}")

        if _count_substring(remote_body, CURSOR_BODY_END) > 1:
            print(
                "error: PR body contains multiple CURSOR_AGENT_PR_BODY_END markers; "
                "manual repair required",
                file=sys.stderr,
            )
            return 1
        if _count_substring(remote_body, CODERABBIT_MARKER) > 1:
            print(
                "error: PR body contains multiple CodeRabbit markers; "
                "manual repair required",
                file=sys.stderr,
            )
            return 1

        merged = _merge_follow_up(remote_body, title, append_block)

        # Guard 1: string equality re-read (matches v1 STALE_ON_REREAD).
        reread = _gh_view_body(gh, repo, pr)
        if reread != remote_body:
            guard_trace("PR_BODY_E_STALE_ON_REREAD")
            print(
                "error: [PR_BODY_E_STALE_ON_REREAD] PR body changed since initial "
                "read; aborting to avoid overwrite",
                file=sys.stderr,
            )
            return 1

        # Guard 2: digest immediately before write.
        prewrite_tmp.write_text(_gh_view_body(gh, repo, pr), encoding="utf-8")
        if sha256_canonical_file(prewrite_tmp) != current_body_digest:
            guard_trace("PR_BODY_E_STALE_PREWRITE")
            print(
                "error: [PR_BODY_E_STALE_PREWRITE] PR body changed immediately "
                "before write; aborting to avoid stale overwrite",
                file=sys.stderr,
            )
            return 1

        out.write_text(merged + "\n", encoding="utf-8")
        _gh_edit_body(gh, repo, pr, out)

        # Mark remote_applied immediately once the write is accepted — BEFORE
        # post-write verification (see grant_lib / Rule 7 grant-release timing).
        ok, err = mark_remote_applied_for_append(repo, pr, file_path, message)
        if not ok:
            print(
                "error: [PR_BODY_E_MARK_APPLIED_FAILED] grant mark-applied failed "
                f"immediately after PR body write — treat as security incident: {err}",
                file=sys.stderr,
            )
            return 1

        postwrite_tmp.write_text(_gh_view_body(gh, repo, pr), encoding="utf-8")
        if sha256_canonical_file(postwrite_tmp) != sha256_canonical_file(out):
            guard_trace("PR_BODY_E_POSTWRITE_MISMATCH")
            print(
                "error: [PR_BODY_E_POSTWRITE_MISMATCH] remote PR body does not "
                "match the merged body after write; treat as concurrency/integrity "
                "incident",
                file=sys.stderr,
            )
            return 1

        ok, err = verify_grant_for_append(
            repo, pr, file_path, message, consume=True
        )
        if not ok:
            print(
                "error: grant consume failed AFTER the PR body update. "
                f"The remote write already landed: {err}",
                file=sys.stderr,
            )
            return 1

        grant_finalized = True
        print(f"updated: https://github.com/{repo}/pull/{pr}")
        return 0
    finally:
        _cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Append-only PR body update for ## Summary convention. "
            "Prefer report_pr.py for status comments. "
            "gh is a local trusted subprocess, not Telos."
        )
    )
    parser.add_argument("repo")
    parser.add_argument("pr")
    parser.add_argument("--file")
    parser.add_argument("--message")
    parser.add_argument("--title")
    args = parser.parse_args(argv)
    if bool(args.file) == bool(args.message is not None):
        if args.file and args.message is not None:
            parser.error("provide --file or --message, not both")
        parser.error("provide --file or --message")
    return run_append(
        args.repo,
        args.pr,
        file_path=args.file,
        message=args.message,
        title=args.title,
    )


if __name__ == "__main__":
    raise SystemExit(main())
