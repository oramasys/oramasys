"""Fail unless the harness commit H adds nothing the qualified consumer commit C would not contain.

Usage: check_harness_consumer_drift.py <C> <H> [--repo DIR]

Qualification tests the consumer at C using the harness at H. That is only sound when
``C`` is an ancestor of ``H`` and ``git diff C..H`` touches nothing the consumer's runtime
depends on. Allowed paths are the requirements, scripts, workflows and tests. Anything under
``src/orama/``, ``pyproject.toml`` or any path not listed is refused, which forces C to be
re-selected and the freeze recomputed. The checkout must retain history for both revisions and
their merge base (the final-producers workflow uses ``fetch-depth: 0``).
Compares COMMITTED C and H only; it says nothing about checkout cleanliness, so the final runner
must also check staged and untracked contamination. Prints a JSON verdict (C, H, the classified
paths). Exit 0 allowed, 1 refused, 2 usage or git error.
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterable, Sequence

ALLOWED_PREFIXES = ("requirements/", "scripts/", ".github/", "src/tests/", "tests/")
FORBIDDEN_PREFIXES = ("src/orama/",)
FORBIDDEN_FILES = frozenset({"pyproject.toml"})


def classify(paths: Iterable[str]) -> dict[str, list[str]]:
    """Split changed paths into allowed, forbidden (runtime) and unclassified."""
    result: dict[str, list[str]] = {"allowed": [], "forbidden": [], "unclassified": []}
    for path in paths:
        if path in FORBIDDEN_FILES or path.startswith(FORBIDDEN_PREFIXES):
            result["forbidden"].append(path)
        elif path.startswith(ALLOWED_PREFIXES):
            result["allowed"].append(path)
        else:
            result["unclassified"].append(path)
    return result


def permitted(classified: dict[str, list[str]]) -> bool:
    """True only when no runtime and no unclassified path changed."""
    return not classified["forbidden"] and not classified["unclassified"]


def changed_paths(repo: str, consumer: str, harness: str) -> list[str]:
    """Return the canonical changed-path inventory between two commits.

    ``consumer`` must be an ancestor of ``harness``: a directional diff cannot prove soundness
    across divergent histories. The inventory must not depend on local presentation or
    configuration: NUL-delimited names (no quoting, no newline splitting), submodule changes never
    ignored even when the user's ``diff.ignoreSubmodules`` says otherwise, no rename folding, no
    external diff or textconv.
    """
    ancestry = subprocess.run(
        ["git", "-C", repo, "merge-base", "--is-ancestor", consumer, harness],
        capture_output=True, check=False,
    )
    if ancestry.returncode == 1:
        raise RuntimeError("consumer is not an ancestor of harness")
    if ancestry.returncode != 0:
        detail = ancestry.stderr.decode("utf-8", "replace").strip()[:200]
        raise RuntimeError(f"git merge-base failed: {detail}")
    done = subprocess.run(
        ["git", "-C", repo, "-c", "diff.ignoreSubmodules=none", "-c", "diff.renames=false",
         "-c", "core.quotePath=false", "diff", "--name-only", "-z", "--no-renames",
         "--ignore-submodules=none", "--no-ext-diff", "--no-textconv", f"{consumer}..{harness}"],
        capture_output=True, check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"git diff failed: {done.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return [name.decode("utf-8", "surrogateescape") for name in done.stdout.split(b"\0") if name]


def main(argv: Sequence[str]) -> int:
    """Run the guard and print the verdict."""
    args = list(argv[1:])
    repo = "."
    if "--repo" in args:
        index = args.index("--repo")
        if index + 1 >= len(args):
            print(__doc__, file=sys.stderr)
            return 2
        repo = args[index + 1]
        del args[index:index + 2]
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    consumer, harness = args
    try:
        classified = classify(changed_paths(repo, consumer, harness))
    except (RuntimeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    ok = permitted(classified)
    print(json.dumps({"consumer": consumer, "harness": harness, "permitted": ok, **classified},
                     indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
