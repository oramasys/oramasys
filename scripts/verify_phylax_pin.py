"""Verify the installed Phylax is exactly the pinned immutable source.

Run under ``python -I`` from outside the checkout, so a workspace path cannot satisfy the
import. Usage: ``verify_phylax_pin.py <pin-file> [expected-url]``. Exit 0 and print
``OK <url> <commit>`` when the distribution's ``direct_url.json`` records the expected
repository URL and the exact commit AND the imported package lives under site-packages.
Exit 1 and print the problem codes otherwise; exit 2 on a usage or read error.
"""
from __future__ import annotations

import json
import re
import sys
from importlib import metadata
from pathlib import Path

DISTRIBUTION = "oramasys-phylax"
EXPECTED_URL = "https://github.com/oramasys/phylax.git"
_FULL_SHA = re.compile(r"[0-9a-f]{40}")


def _same_url(observed: object, expected: str) -> bool:
    """Compare repository URLs ignoring a trailing slash and an optional ``.git``."""
    if not isinstance(observed, str):
        return False

    def norm(value: str) -> str:
        value = value.rstrip("/")
        return value[:-4] if value.endswith(".git") else value

    return norm(observed) == norm(expected)


def check_direct_url(text: str | None, *, expected_url: str, expected_commit: str) -> list[str]:
    """Return problem codes for a ``direct_url.json`` document (empty means bound)."""
    if not _FULL_SHA.fullmatch(expected_commit):
        return ["pin.invalid"]
    if not text:
        return ["direct_url.missing"]
    try:
        data = json.loads(text)
    except ValueError:
        return ["direct_url.malformed"]
    if not isinstance(data, dict):
        return ["direct_url.malformed"]
    problems: list[str] = []
    vcs = data.get("vcs_info")
    if not isinstance(vcs, dict) or vcs.get("vcs") != "git":
        problems.append("source.not_git")
    elif vcs.get("commit_id") != expected_commit:
        problems.append("commit.mismatch")
    if not _same_url(data.get("url"), expected_url):
        problems.append("url.mismatch")
    return problems


def check_location(module_file: str | None) -> list[str]:
    """Return a problem unless the module was imported from an installed location."""
    if not module_file:
        return ["location.unknown"]
    parts = Path(module_file).parts
    if "site-packages" not in parts and "dist-packages" not in parts:
        return ["location.not_installed"]
    return []


def main(argv: list[str]) -> int:
    """Check the installed distribution and imported module against the pin."""
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        expected_commit = Path(argv[1]).read_text(encoding="utf-8").strip()
        expected_url = argv[2] if len(argv) == 3 else EXPECTED_URL
        text = metadata.distribution(DISTRIBUTION).read_text("direct_url.json")
        import phylax

        module_file = getattr(phylax, "__file__", None)
    except (OSError, metadata.PackageNotFoundError, ImportError) as error:
        print(f"unreadable: {type(error).__name__}", file=sys.stderr)
        return 2
    problems = [
        *check_direct_url(text, expected_url=expected_url, expected_commit=expected_commit),
        *check_location(module_file),
    ]
    if problems:
        print(" ".join(problems), file=sys.stderr)
        return 1
    print(f"OK {expected_url} {expected_commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
