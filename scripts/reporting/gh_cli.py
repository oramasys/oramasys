#!/usr/bin/env python3
"""Local ``gh`` subprocess helper.

``gh`` is a trusted local CLI (stored token / ``GH_TOKEN``). Do **not** route
it through Telos. Telos owns purpose-scoped HTTP dials; this is a different
trust surface.

``gh pr view --json body --jq .body`` appends one trailing LF that is not part
of the stored body. Callers that compare that text to a file written with
exactly one trailing LF must drop that transport newline and no others:
canonicalize already ignores a single LF, so a second one survives and fails
the post-write hash.
"""
from __future__ import annotations

import subprocess

GH_TIMEOUT_SECONDS = 120


def strip_transport_newline(text: str) -> str:
    """Drop exactly one trailing LF. Leave a meaningful extra blank line."""
    if text.endswith("\n"):
        return text[:-1]
    return text


def run_gh(
    args: list[str],
    *,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``gh`` with a bounded wait. Timeout becomes ``SystemExit``.

    ``SystemExit`` is a ``BaseException``, so a caller's ``finally`` (grant
    release) still runs and the process exits instead of hanging.
    """
    limit = GH_TIMEOUT_SECONDS if timeout is None else timeout
    try:
        return subprocess.run(
            args,
            text=True,
            capture_output=True,
            check=False,
            timeout=limit,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"error: gh timed out after {limit}s") from exc
