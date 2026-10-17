"""Record clean Git source and artifact identities; compare two build records.

Build artifacts and the record output must live outside the source checkout.
The record describes the recording environment; orchestration must run this in
the actual build environment. Equality is artifact reproducibility evidence,
not a claim that this tool executed or independently attested the build.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

TOOLS = ("build", "pip", "setuptools", "wheel", "hatchling", "hatch-vcs")
FIELDS = {
    "schema",
    "source_commit",
    "source_tree",
    "build_inputs",
    "source_date_epoch",
    "sdist_sha256",
    "wheel_sha256",
}
HEX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
DIGEST = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+_-]{0,79}")


class ProvenanceError(ValueError):
    """Invalid, unbound, or dirty build input; messages never include paths."""


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ProvenanceError("invalid arguments")


def _git(repo: Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    result = subprocess.run(
        ["git", "-C", str(repo), *args], env=env, capture_output=True, check=False
    )
    if result.returncode:
        raise ProvenanceError("source verification failed")
    return result.stdout.decode("utf-8").strip()


def _source(repo: Path, commit: str) -> tuple[str, int]:
    if not HEX.fullmatch(commit) or _git(repo, "rev-parse", "HEAD") != commit:
        raise ProvenanceError("source HEAD does not equal source commit")
    if Path(_git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
        raise ProvenanceError("source repository must be the checkout root")
    _git(repo, "diff", "--quiet", "HEAD", "--")
    for flags in (
        ("--others", "--exclude-standard"),
        ("--others", "--ignored", "--exclude-standard"),
    ):
        if _git(repo, "ls-files", "-z", *flags):
            raise ProvenanceError("source tree contains untracked or ignored files")
    epoch = int(_git(repo, "show", "-s", "--format=%ct", commit))
    supplied = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch < 0 or (
        supplied is not None
        and (
            not supplied.isascii() or not supplied.isdecimal() or int(supplied) != epoch
        )
    ):
        raise ProvenanceError("build epoch differs from commit epoch")
    return _git(repo, "rev-parse", "HEAD^{tree}"), epoch


def _outside(path: Path, repo: Path) -> None:
    if path == repo or repo in path.parents:
        raise ProvenanceError("build outputs must be outside source checkout")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not path.is_file() or before.st_size == 0:
            raise ProvenanceError("artifact must be a nonempty regular file")
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    def identity(stat: os.stat_result) -> tuple[int, int, int, int, int]:
        """Return the immutable file identity relevant while recording an artifact."""
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    if identity(before) != identity(after) or identity(after) != identity(path.stat()):
        raise ProvenanceError("artifact changed during recording")
    return digest.hexdigest()


def build_inputs() -> dict[str, object]:
    tools: dict[str, str | None] = {}
    for name in TOOLS:
        try:
            tools[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            tools[name] = None
    result: dict[str, object] = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "tools": tools,
    }
    _validate_build_inputs(result)
    return result


def _validate_build_inputs(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "python_implementation",
        "python_version",
        "tools",
    }:
        raise ProvenanceError("invalid build inputs")
    if value["python_implementation"] not in {
        "CPython",
        "PyPy",
        "Jython",
        "IronPython",
    }:
        raise ProvenanceError("invalid interpreter identity")
    version = value["python_version"]
    tools = value["tools"]
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ProvenanceError("invalid interpreter version")
    if not isinstance(tools, dict) or set(tools) != set(TOOLS):
        raise ProvenanceError("invalid build tool inventory")
    if any(
        v is not None and (not isinstance(v, str) or not VERSION.fullmatch(v))
        for v in tools.values()
    ):
        raise ProvenanceError("invalid build tool version")


def record(
    source_repo: Path, source_commit: str, sdist: Path, wheel: Path
) -> dict[str, object]:
    repo = Path(source_repo).resolve()
    sdist, wheel = Path(sdist).resolve(), Path(wheel).resolve()
    for path in (sdist, wheel):
        _outside(path, repo)
    if sdist == wheel or (sdist.exists() and wheel.exists() and sdist.samefile(wheel)):
        raise ProvenanceError("sdist and wheel must be distinct artifacts")
    tree, epoch = _source(repo, source_commit)
    inputs = build_inputs()
    result = {
        "schema": 1,
        "source_commit": source_commit,
        "source_tree": tree,
        "build_inputs": inputs,
        "source_date_epoch": epoch,
        "sdist_sha256": _hash(sdist),
        "wheel_sha256": _hash(wheel),
    }
    if _source(repo, source_commit) != (tree, epoch):
        raise ProvenanceError("source changed during recording")
    return result


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ProvenanceError("non-finite JSON value")


def load(path: Path) -> dict[str, object]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=_constant,
    )
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["schema"]) is not int
        or value["schema"] != 1
    ):
        raise ProvenanceError("invalid provenance schema")
    for key in ("source_commit", "source_tree", "sdist_sha256", "wheel_sha256"):
        pattern = HEX if key.startswith("source_") else DIGEST
        if not isinstance(value[key], str) or not pattern.fullmatch(value[key]):
            raise ProvenanceError("invalid identity")
    if type(value["source_date_epoch"]) is not int or value["source_date_epoch"] < 0:
        raise ProvenanceError("invalid epoch")
    _validate_build_inputs(value["build_inputs"])
    return value


def main(argv: list[str] | None = None) -> int:
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    create = commands.add_parser("record")
    for name in ("source-repo", "source-commit", "sdist", "wheel", "output"):
        create.add_argument("--" + name, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("first")
    compare.add_argument("second")
    try:
        args = parser.parse_args(argv)
        if args.command == "compare":
            first, second = load(Path(args.first)), load(Path(args.second))
            mismatches = sorted(
                key for key in FIELDS - {"schema"} if first[key] != second[key]
            )
            print(
                json.dumps(
                    {
                        "schema": 1,
                        "reproducible": not mismatches,
                        "mismatches": mismatches,
                    },
                    sort_keys=True,
                )
            )
            return 1 if mismatches else 0
        repo = Path(args.source_repo).resolve()
        output = Path(args.output).resolve()
        _outside(output, repo)
        artifacts = (Path(args.sdist).resolve(), Path(args.wheel).resolve())
        if any(
            output == p or (output.exists() and p.exists() and output.samefile(p))
            for p in artifacts
        ):
            raise ProvenanceError("output must not overwrite an artifact")
        result = record(repo, args.source_commit, *artifacts)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=output.parent, delete=False
            ) as stream:
                temporary = stream.name
                stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
            os.replace(temporary, output)
        finally:
            if temporary is not None and Path(temporary).exists():
                Path(temporary).unlink()
        return 0
    except (OSError, ValueError, TypeError, UnicodeError):
        print("invalid or unverified provenance input", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
