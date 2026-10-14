"""Run pip install at most three times, retrying only recognized network failures."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

TRANSIENT = (
    "temporary failure in name resolution", "name or service not known", "nodename nor servname provided",
    "connection reset by peer", "connection aborted", "network is unreachable",
    "readtimeouterror", "connecttimeouterror", "connection timed out",
    "remote end closed connection without response",
)
PERMANENT = (
    "resolutionimpossible", "dependency conflict", "conflicting dependencies", "hash mismatch",
    "do not match the hashes", "invalid requirement", "invalid revision", "reference is not a tree",
    "unknown revision", "could not find a version that satisfies", "no matching distribution found",
    "test failure", "failed tests", "certificate_verify_failed", "certificate verify failed",
    "401 unauthorized", "403 forbidden", "authentication failed", "repository not found",
    "subprocess-exited-with-error", "failed building wheel", "metadata-generation-failed",
)


def classify_error(text):
    lower = text.lower()
    if any(marker in lower for marker in PERMANENT):
        return "non-retryable"
    return "transient-network" if any(marker in lower for marker in TRANSIENT) else "non-retryable"


def write_report(path, report):
    destination = Path(path)
    if destination.is_symlink():
        raise OSError("report must not be a symlink")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         prefix=".install-report-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--python", required=True)
    parser.add_argument("--report", required=True)
    args, pip_args = parser.parse_known_args(argv)
    if pip_args[:1] == ["--"]:
        pip_args = pip_args[1:]
    if not pip_args:
        parser.error("pip install arguments required")
    report = {"schema": 1, "attempts": 0, "classification": "pending", "returncode": None, "status": "running"}
    try:
        write_report(args.report, report)
        for attempt in range(1, 4):
            report["attempts"] = attempt
            try:
                result = subprocess.run([args.python, "-m", "pip", "install", *pip_args],
                                        capture_output=True, text=True, check=False, timeout=600)
            except (OSError, subprocess.SubprocessError):
                report.update(classification="process-error", returncode=None, status="failed")
                write_report(args.report, report)
                return 1
            classification = "success" if result.returncode == 0 else classify_error(result.stdout + "\n" + result.stderr)
            retry = classification == "transient-network" and attempt < 3
            report.update(classification=classification, returncode=result.returncode,
                          status="running" if retry else ("success" if result.returncode == 0 else "failed"))
            write_report(args.report, report)
            if not retry:
                return 0 if result.returncode == 0 else 1
            time.sleep(attempt)
    except OSError:
        print(json.dumps({"status": "failed", "classification": "report-error"}), file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
