"""Seal the retained qualification records into ``evidence-status.json``.

Usage: stamp_evidence_status.py --directory DIR --mode MODE --job-status STATUS
       --head-sha SHA --run-id ID --run-attempt N [--output PATH]

A reviewer can only audit an M1 receipt if the records behind it are still there and can be tied
to the exact run. This script hashes every retained record, binds the result to the harness head
and the workflow run, and marks the run as evidence only when the mode is ``evidence``, the job
succeeded and every required record is present. Exit 0 when the seal was written and the run is
sound, 1 when a successful job lost required records, 2 on a usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SCHEMA = 2
REQUIRED_FILES = (
    "identity.json",
    "collection-gate.json",
    "scenarios.json",
    "provenance-one.json",
    "provenance-two.json",
    "collection.json",
    "final-results.xml",
    "rebuild-comparison.json",
)
REQUIRED_DIRECTORIES = ("scenario-traces", "install-reports")
STATUS_FILE = "evidence-status.json"


def sha256_of(path: Path) -> str:
    """Return the SHA-256 hex digest of one file, read in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(directory: Path) -> tuple[dict[str, str], list[str]]:
    """Hash the required records; return ``(digests, problems)``.

    A required file must be a regular, non-empty file. A required directory must hold at least one
    regular file. Symlinks are never followed, so a retained record cannot point outside the
    directory, and each one is reported as a problem.
    """
    digests: dict[str, str] = {}
    problems: list[str] = []
    for name in REQUIRED_FILES:
        path = directory / name
        if path.is_symlink():
            problems.append(f"{name}: is a symlink")
        elif not path.is_file():
            problems.append(f"{name}: missing")
        elif path.stat().st_size == 0:
            problems.append(f"{name}: empty")
        else:
            digests[name] = sha256_of(path)
    for name in REQUIRED_DIRECTORIES:
        root = directory / name
        if root.is_symlink() or not root.is_dir():
            problems.append(f"{name}/: missing")
            continue
        members = sorted(root.rglob("*"))
        problems.extend(f"{name}/{m.relative_to(root).as_posix()}: is a symlink"
                        for m in members if m.is_symlink())
        files = [m for m in members if m.is_file() and not m.is_symlink()]
        if not files:
            problems.append(f"{name}/: no records")
        for member in files:
            digests[f"{name}/{member.relative_to(root).as_posix()}"] = sha256_of(member)
    return digests, problems


def build_status(directory: Path, *, mode: str, job_status: str, head_sha: str,
                 run_id: str, run_attempt: str) -> dict[str, Any]:
    """Return the sealed status document for one qualification run."""
    digests, problems = collect(directory)
    complete = not problems
    return {
        "schema": SCHEMA,
        "mode": mode,
        "job_status": job_status,
        "evidence": mode == "evidence" and job_status == "success" and complete,
        "complete": complete,
        "problems": problems,
        "head_sha": head_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "files": dict(sorted(digests.items())),
    }


def main(argv: Sequence[str]) -> int:
    """Write the sealed status and return the process exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--job-status", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output", type=Path)
    try:
        args = parser.parse_args(list(argv[1:]))
    except SystemExit:
        return 2
    if not args.directory.is_dir():
        print(f"error: {args.directory} is not a directory", file=sys.stderr)
        return 2
    status = build_status(args.directory, mode=args.mode, job_status=args.job_status,
                          head_sha=args.head_sha, run_id=args.run_id,
                          run_attempt=args.run_attempt)
    output = args.output or args.directory / STATUS_FILE
    output.write_text(json.dumps(status, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if not status["complete"] and args.job_status == "success":
        for problem in status["problems"]:
            print(f"::error::retained record {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
