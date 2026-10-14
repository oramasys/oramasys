"""Build a minimal, sanitized receipt for the Phylax interop job.

Usage: ``phylax_interop_receipt.py <junit.xml> <pin-file> <observed-url> <observed-commit>``.
Prints JSON with ONLY: outcome, expected pin, observed URL and commit, per-test identifier
and outcome, counts and a UTC timestamp. It never carries SQLite state, grant wire,
environment values, local paths, or any captured output from the run.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.\[\]-]")
_BAD = ("failure", "error")


def build_receipt(
    junit_text: str, *, expected_pin: str, observed_url: str, observed_commit: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Return the sanitized receipt; raise ValueError on a malformed pin or report."""
    if not _FULL_SHA.fullmatch(expected_pin) or not _FULL_SHA.fullmatch(observed_commit):
        raise ValueError("pin and observed commit must be full lowercase SHAs")
    root = ET.fromstring(junit_text)
    tests: list[dict[str, str]] = []
    for case in root.iter("testcase"):
        name = _SAFE_ID.sub("_", f"{case.get('classname', '')}.{case.get('name', '')}")
        children = {child.tag for child in case}
        if children & set(_BAD):
            outcome = "fail"
        elif "skipped" in children:
            outcome = "skipped"
        else:
            outcome = "pass"
        tests.append({"id": name, "outcome": outcome})
    failed = sum(1 for t in tests if t["outcome"] == "fail")
    skipped = sum(1 for t in tests if t["outcome"] == "skipped")
    overall = "pass" if tests and failed == 0 and skipped == 0 else "fail"
    return {
        "outcome": overall,
        "expected_pin": expected_pin,
        "observed_url": observed_url,
        "observed_commit": observed_commit,
        "pin_matches": observed_commit == expected_pin,
        "counts": {"total": len(tests), "failed": failed, "skipped": skipped},
        "tests": tests,
        "generated_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main(argv: list[str]) -> int:
    """Write the receipt to stdout; exit 1 when the run did not pass."""
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        receipt = build_receipt(
            Path(argv[1]).read_text(encoding="utf-8"),
            expected_pin=Path(argv[2]).read_text(encoding="utf-8").strip(),
            observed_url=argv[3], observed_commit=argv[4],
        )
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"unreadable: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["outcome"] == "pass" and receipt["pin_matches"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
