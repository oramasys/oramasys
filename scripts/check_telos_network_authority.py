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
_BANNED_NETWORK_COMMANDS = frozenset(
    {"curl", "wget", "nc", "ncat", "ssh", "scp", "sftp"}
)
_SUBPROCESS_METHODS = frozenset(
    {"run", "call", "check_call", "check_output", "Popen"}
)
_PROCESS_LAUNCH_TARGETS = frozenset(
    {
        "os.system",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
    }
    | {f"subprocess.{method}" for method in _SUBPROCESS_METHODS}
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


def _build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Map locally-bound names to canonical dotted paths for call analysis."""
    alias_map: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                alias_map[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                alias_map[local] = f"{node.module}.{alias.name}"
    return alias_map


def _resolve_call(node: ast.Call, alias_map: dict[str, str]) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = alias_map.get(func.value.id, func.value.id)
        return f"{base}.{func.attr}"
    if isinstance(func, ast.Name):
        return alias_map.get(func.id)
    return None


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
    alias_map = _build_alias_map(tree)

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
                if alias.name == "*":
                    continue
                qualified = f"{module}.{alias.name}" if module else alias.name
                if _matches_banned_import(qualified):
                    violations.append(
                        Violation(
                            path,
                            node.lineno,
                            "raw-network-import",
                            qualified,
                        )
                    )

        elif isinstance(node, ast.Call):
            resolved = _resolve_call(node, alias_map)
            if resolved is None or resolved not in _PROCESS_LAUNCH_TARGETS:
                continue
            if not node.args:
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
