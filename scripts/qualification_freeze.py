"""Compute a freeze proposal, or verify a separately approved immutable input pair."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def digest(value: object) -> str:
    """Hash canonical UTF-8 JSON using the manifest's encoding rules."""
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _commit(value: str, label: str) -> str:
    """Require one immutable full Git commit identifier."""
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError(f"{label} must be a full commit SHA")
    return value


def proposal(manifest: object, coverage: object, consumer: str, harness: str) -> dict:
    """Prepare inputs for operator review without manufacturing an approval."""
    _commit(consumer, "consumer")
    _commit(harness, "harness")
    return {
        "schema": 2,
        "status": "proposed",
        "approval_ref": None,
        "consumer_commit": consumer,
        "harness_commit": harness,
        "manifest_digest": digest(manifest),
        "coverage_digest": digest(coverage),
    }


def verify(
    record: dict, manifest: object, coverage: object, consumer: str, harness: str
) -> None:
    """Refuse unapproved or changed inputs; the reference is audited separately."""
    expected = proposal(manifest, coverage, consumer, harness)
    if type(record.get("schema")) is not int or record["schema"] != 2:
        raise ValueError("unsupported freeze schema")
    if record.get("status") != "approved":
        raise ValueError("freeze has not been approved")
    if (
        not isinstance(record.get("approval_ref"), str)
        or not record["approval_ref"].strip()
    ):
        raise ValueError("approval reference required")
    for field in (
        "consumer_commit",
        "harness_commit",
        "manifest_digest",
        "coverage_digest",
    ):
        if record.get(field) != expected[field]:
            raise ValueError(f"freeze mismatch: {field}")


def main(argv: list[str] | None = None) -> int:
    """Emit a proposal or verify an approved record supplied by the workflow."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("propose", "verify"))
    parser.add_argument("manifest")
    parser.add_argument("coverage")
    parser.add_argument("--consumer", required=True)
    parser.add_argument("--harness", required=True)
    parser.add_argument("--record")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(Path(args.manifest).read_text())
        coverage = json.loads(Path(args.coverage).read_text())
        if args.action == "verify":
            if args.record is None:
                raise ValueError("record required")
            record = json.loads(Path(args.record).read_text())
            verify(record, manifest, coverage, args.consumer, args.harness)
        else:
            record = proposal(manifest, coverage, args.consumer, args.harness)
        output = json.dumps(record, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(output)
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"freeze-refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
