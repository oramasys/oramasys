#!/usr/bin/env python3
"""Fail CI if Oramasys production code establishes raw outbound networking.

Oramasys owns application/workflow/provider semantics. Telos owns endpoint
security and secure outbound transport. Production modules under ``src/orama``
therefore must not import independent HTTP/socket stacks or shell out to network
clients. Test code is outside the scanned root and may use HTTP clients.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path

_BANNED_IMPORT_ROOTS = frozenset(
    {
        "httpx",
        "requests",
        "aiohttp",
        "urllib.request",
        "http.client",
        "socket",
        "ftplib",
        "smtplib",
        "paramiko",
        "asyncssh",
    }
)
_BANNED_FROM_IMPORTS = frozenset(
    {
        ("urllib", "request"),
        ("http", "client"),
    }
)
_BANNED_NETWORK_COMMANDS = frozenset(
    {"curl", "wget", "nc", "ncat", "ssh", "scp", "sftp"}
)
_SUBPROCESS_METHODS = frozenset(
    {"run", "call", "check_call", "check_output", "Popen"}
)


@dataclass(frozen=True, slots=True)
class Violation:
    path: Path
    line: int
    rule: str
    detail: str


def _matches_banned_import(name: str) -> bool:
    return any(
        name == banned or name.startswith(f"{banned}.")
        for banned in _BANNED_IMPORT_ROOTS
    )


def _call_name(node: ast.Call) -> tuple[str, str] | None:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    if not isinstance(func.value, ast.Name):
        return None
    return func.value.id, func.attr


def _literal_command(node: ast.AST) -> str | None:
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        first = node.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return Path(first.value).name
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        first = node.value.strip().split(maxsplit=1)
        if first:
            return Path(first[0]).name
    return None


def scan_file(path: Path) -> list[Violation]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[Violation] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _matches_banned_import(alias.name):
                    violations.append(
                        Violation(path, node.lineno, "raw-network-import", alias.name)
                    )

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _matches_banned_import(module):
                violations.append(
                    Violation(path, node.lineno, "raw-network-import", module)
                )
                continue
            for alias in node.names:
                if (module, alias.name) in _BANNED_FROM_IMPORTS:
                    violations.append(
                        Violation(
                            path,
                            node.lineno,
                            "raw-network-import",
                            f"{module}.{alias.name}",
                        )
                    )

        elif isinstance(node, ast.Call):
            called = _call_name(node)
            if called is None or called[0] != "subprocess":
                continue
            if called[1] not in _SUBPROCESS_METHODS or not node.args:
                continue
            executable = _literal_command(node.args[0])
            if executable in _BANNED_NETWORK_COMMANDS:
                violations.append(
                    Violation(
                        path,
                        node.lineno,
                        "raw-network-command",
                        executable,
                    )
                )

    return violations


def scan_tree(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(root.rglob("*.py")):
        violations.extend(scan_file(path))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="src/orama")
    args = parser.parse_args()

    violations = scan_tree(Path(args.root))
    for violation in violations:
        print(
            f"{violation.path}:{violation.line}: "
            f"{violation.rule}: {violation.detail}"
        )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
