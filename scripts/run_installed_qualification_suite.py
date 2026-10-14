"""Run the final test suite against installed runtime code and emit collected node ids.

The bundle is an archive of harness tests and helpers with ``src/orama`` removed.
It is intentionally allowed to add only the bundle root for test helpers; it never
adds a runtime source directory.  A selected consumer source tree may be supplied
only through ``ORAMA_QUALIFICATION_SOURCE_ROOT`` for static-inspection tests.
"""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys
import sysconfig
from typing import Any


def validate_bundle(bundle: Path) -> None:
    """Refuse a bundle capable of shadowing the installed application package."""
    if (bundle / "src/orama").exists():
        raise ValueError("qualification bundle contains runtime source")
    if not bundle.is_dir() or not (bundle / "src/tests").is_dir():
        raise ValueError("qualification bundle is incomplete")


def assert_installed_origin() -> None:
    """Require ``orama`` to load from a configured site-packages directory."""
    module = importlib.import_module("orama")
    origin = getattr(module, "__file__", None)
    if not isinstance(origin, str):
        raise ValueError("installed application origin is unavailable")
    resolved = Path(origin).resolve()
    roots = {
        Path(value).resolve()
        for value in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib"))
        if value
    }
    if not any(resolved.is_relative_to(root) for root in roots):
        raise ValueError("application import is outside installed site-packages")


class _Collected:
    """Minimal pytest plugin that records the exact test collection."""

    def __init__(self) -> None:
        self.node_ids: list[str] = []

    def pytest_collection_finish(self, session: Any) -> None:
        self.node_ids = [item.nodeid for item in session.items]


def run(bundle: Path, junit: Path, collection: Path) -> int:
    """Collect then run once, preserving the observed collection on all outcomes."""
    validate_bundle(bundle)
    if collection.exists() or collection.is_symlink():
        raise FileExistsError("collection output already exists")
    if junit.exists() or junit.is_symlink():
        raise FileExistsError("JUnit output already exists")
    assert_installed_origin()
    import pytest

    sys.path.insert(0, str(bundle))
    plugin = _Collected()
    arguments = [
        "-q",
        "--import-mode=importlib",
        "-o",
        "pythonpath=",
        "-p",
        "no:cacheprovider",
        "--junitxml",
        str(junit),
        str(bundle / "src/tests"),
    ]
    result = pytest.main(arguments, plugins=[plugin])
    collection.write_text(
        json.dumps({"schema": 1, "node_ids": plugin.node_ids}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return int(result)


def main(argv: list[str] | None = None) -> int:
    """Run only when the caller has already built an application-free bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--junit", required=True)
    parser.add_argument("--collection", required=True)
    args = parser.parse_args(argv)
    try:
        return run(Path(args.bundle), Path(args.junit), Path(args.collection))
    except (OSError, ValueError, TypeError):
        print("installed-qualification-suite-refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
