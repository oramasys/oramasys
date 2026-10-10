"""Fail the oracle cell unless its JUnit report meets the manifest's result gate.

Usage: verify_cell_results.py <manifest.json> <junit.xml> <profile> <python>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from orama.compat.manifest import ManifestError, check_cell_results


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    manifest = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    cells = [c for c in manifest["cells"] if (c["profile"], c["python"]) == (argv[3], argv[4])]
    if len(cells) != 1:
        print(f"FAIL: no unique manifest cell for {argv[3]} on {argv[4]}", file=sys.stderr)
        return 1
    try:
        check_cell_results(Path(argv[2]).read_text(encoding="utf-8"), cells[0])
    except (ManifestError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"OK: {argv[3]} on {argv[4]} met its result gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
