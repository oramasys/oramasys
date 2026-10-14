"""Build a minimal, sanitized receipt for the Phylax interop job.

Usage: ``phylax_interop_receipt.py <junit.xml> <pin-file> <observed-url> <observed-commit>``.
Prints JSON with ONLY: outcome, expected pin, observed URL and commit, fixed public scenario
labels with outcomes, counts and a UTC timestamp. It never carries SQLite state, grant wire,
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
_URL = re.compile(r"https://[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){1,3}")
_BAD = ("failure", "error")
# The only classname pytest emits for the interop module when run from the repository root
# (rootdir-relative dotted node id); anything else, including a matching final component, is
# untrusted.
CANONICAL_CLASSNAME = "src.tests.interop.test_verify_only_serving"
# Exact testcase names mapped to fixed public labels. Raw JUnit text (class names, test names,
# parameters) is never copied into the receipt; anything not listed is "unrecognized".
SCENARIOS = {
    "test_a_grant_issued_by_phylax_is_spent_through_the_read_only_verifier": "issue_verify_consume",
    "test_a_revocation_after_open_is_refused_and_readiness_does_not_change": "revocation_refused",
    "test_missing_verifier_state_is_unavailable_and_never_opens_the_ledger": "unavailable_no_ledger",
    "test_shutdown_closes_the_verifier_and_the_ledger_exactly_once": "shutdown_closes_resources",
    "test_a_missing_phylax_is_logged_as_not_installed_not_as_a_mystery": "missing_phylax_labelled",
}
UNRECOGNIZED = "unrecognized"


def _label(classname: str, name: str) -> str:
    """Return the fixed public label for a known interop test, else ``unrecognized``."""
    if classname != CANONICAL_CLASSNAME:
        return UNRECOGNIZED
    return SCENARIOS.get(name, UNRECOGNIZED)


def build_receipt(
    junit_text: str, *, expected_pin: str, observed_url: str, observed_commit: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Return the sanitized receipt; raise ValueError on a malformed pin or report.

    The run passes only when every expected scenario ran exactly once and passed and nothing
    unrecognized, failed or skipped appeared. Unrecognized cases are counted, never described.
    """
    if not _FULL_SHA.fullmatch(expected_pin) or not _FULL_SHA.fullmatch(observed_commit):
        raise ValueError("pin and observed commit must be full lowercase SHAs")
    if not _URL.fullmatch(observed_url):
        raise ValueError("observed url must be a plain https repository URL")
    root = ET.fromstring(junit_text)
    scenarios: list[dict[str, str]] = []
    unrecognized = 0
    for case in root.iter("testcase"):
        label = _label(case.get("classname", ""), case.get("name", ""))
        children = {child.tag for child in case}
        if children & set(_BAD):
            outcome = "fail"
        elif "skipped" in children:
            outcome = "skipped"
        else:
            outcome = "pass"
        if label == UNRECOGNIZED:
            unrecognized += 1
            continue
        scenarios.append({"scenario": label, "outcome": outcome})
    seen = sorted(s["scenario"] for s in scenarios)
    complete = seen == sorted(SCENARIOS.values())
    failed = sum(1 for s in scenarios if s["outcome"] == "fail")
    skipped = sum(1 for s in scenarios if s["outcome"] == "skipped")
    ok = complete and unrecognized == 0 and failed == 0 and skipped == 0
    return {
        "outcome": "pass" if ok else "fail",
        "expected_pin": expected_pin,
        "observed_url": observed_url,
        "observed_commit": observed_commit,
        "pin_matches": observed_commit == expected_pin,
        "counts": {
            "expected": len(SCENARIOS), "recognized": len(scenarios),
            "unrecognized": unrecognized, "failed": failed, "skipped": skipped,
        },
        "scenarios": sorted(scenarios, key=lambda item: item["scenario"]),
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
