from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_telos_network_authority import scan_tree


def _write(tmp_path: Path, relative: str, content: str) -> Path:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_guard_rejects_httpx_in_production(tmp_path: Path) -> None:
    source = _write(tmp_path, "src/orama/provider.py", "import httpx\n")
    violations = scan_tree(tmp_path / "src/orama")
    assert any(
        v.rule == "raw-network-import" and v.path == source and v.detail == "httpx"
        for v in violations
    )


def test_guard_rejects_from_urllib_request_import(tmp_path: Path) -> None:
    _write(tmp_path, "src/orama/provider.py", "from urllib import request\n")
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.detail == "urllib.request" for v in violations)


def test_guard_rejects_aliased_qualified_from_import(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/orama/provider.py",
        "from urllib import request as urlrequest\n",
    )
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.detail == "urllib.request" for v in violations)


def test_guard_rejects_http_client_from_import(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/orama/provider.py",
        "from http import client as http_client\n",
    )
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.detail == "http.client" for v in violations)


def test_guard_rejects_subprocess_curl(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/orama/provider.py",
        "import subprocess\nsubprocess.run(['curl', 'https://example.com'], check=True)\n",
    )
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.rule == "raw-network-command" and v.detail == "curl" for v in violations)


def test_guard_rejects_aliased_subprocess_module(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/orama/provider.py",
        "import subprocess as sp\nsp.run(['curl', 'https://example.com'], check=True)\n",
    )
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.rule == "raw-network-command" and v.detail == "curl" for v in violations)


def test_guard_rejects_aliased_subprocess_function_import(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/orama/provider.py",
        "from subprocess import run as r\nr(['wget', 'https://example.com'], check=True)\n",
    )
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.rule == "raw-network-command" and v.detail == "wget" for v in violations)


def test_guard_rejects_shell_string_network_command(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/orama/provider.py",
        "import subprocess\nsubprocess.run('wget https://example.com', shell=True, check=True)\n",
    )
    violations = scan_tree(tmp_path / "src/orama")
    assert any(v.rule == "raw-network-command" and v.detail == "wget" for v in violations)


def test_guard_allows_telos_transport_import(tmp_path: Path) -> None:
    _write(tmp_path, "src/orama/provider.py", "from telos import SecureDialer\n")
    assert scan_tree(tmp_path / "src/orama") == []


def test_guard_does_not_scan_test_tree(tmp_path: Path) -> None:
    prod = tmp_path / "src/orama"
    prod.mkdir(parents=True)
    (prod / "__init__.py").write_text("", encoding="utf-8")
    _write(tmp_path, "src/tests/test_api.py", "import httpx\n")
    assert scan_tree(prod) == []


def test_current_oramasys_production_tree_has_no_raw_network_authority() -> None:
    assert scan_tree(ROOT / "src/orama") == []
