"""Fingerprint the actual process runtime and refuse unqualified WAL libraries."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import hashlib
import json
import platform
import sqlite3
import sys


def require_sqlite_version(version: tuple[int, ...]) -> None:
    """Require fixed mainline SQLite; backports need separately verified provenance."""
    if version < (3, 51, 3):
        raise RuntimeError("SQLite >= 3.51.3 required; backport provenance not established")


def runtime_receipt() -> dict[str, object]:
    """Describe the embedded library without exposing environment variables."""
    with sqlite3.connect(":memory:") as db:
        source = db.execute("SELECT sqlite_source_id()").fetchone()[0]
        options = [row[0] for row in db.execute("PRAGMA compile_options")]
    packages: dict[str, str] = {}
    for name in ("PyNaCl", "cffi"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "not-installed"
    crypto_build: dict[str, str] = {"libsodium_version": "not-exposed-by-binding"}
    try:
        spec = importlib.util.find_spec("nacl._sodium")
    except ModuleNotFoundError:
        spec = None
    if spec is not None and spec.origin is not None:
        with open(spec.origin, "rb") as binary:
            crypto_build["extension_sha256"] = hashlib.file_digest(binary, "sha256").hexdigest()
    return {"python": platform.python_version(), "executable": sys.executable,
            "sqlite_version": sqlite3.sqlite_version, "sqlite_source_id": source,
            "compile_options": options, "platform": platform.platform(), "crypto_packages": packages,
            "crypto_build": crypto_build}


def require_c6_runtime() -> dict[str, object]:
    """Gate on the actual Python-linked library, not a separately installed CLI."""
    require_sqlite_version(sqlite3.sqlite_version_info)
    return runtime_receipt()


if __name__ == "__main__":
    print(json.dumps(require_c6_runtime(), indent=2))
