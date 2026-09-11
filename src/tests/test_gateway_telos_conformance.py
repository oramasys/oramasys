from __future__ import annotations

import ast
from pathlib import Path

DIALER_PATH = Path("src/orama/gateway/dialer.py")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            for alias in node.names:
                names.add(f"{node.module}.{alias.name}")
    return names


def test_gateway_dialer_has_no_second_transport_security_stack() -> None:
    imports = _imports(DIALER_PATH)
    forbidden = {
        "ipaddress",
        "socket",
        "ssl",
        "httpx",
        "requests",
        "urllib.request",
        "http.client",
    }

    assert imports.isdisjoint(forbidden)


def test_gateway_dialer_points_to_telos_secure_dialer() -> None:
    text = DIALER_PATH.read_text(encoding="utf-8")

    assert "SecureDialer" in text
    assert "DialConnector = SecureDialConnector" in text
    assert "_validate_application_capability" in text


def test_gateway_dialer_documents_endpoint_security_as_telos_owned() -> None:
    text = DIALER_PATH.read_text(encoding="utf-8")

    assert "Endpoint-security mechanics are owned by :mod:`telos`" in text
    assert "Do not add DNS, IP classification, SSRF, pinning" in text


def test_imports_records_qualified_from_import_path(tmp_path: Path) -> None:
    """Confirmed directly against the pre-fix _imports(): 'from urllib import
    request' only added the bare 'urllib' to the set, never the qualified
    'urllib.request' the forbidden set actually checks for -- meaning this
    exact forbidden import was invisible to
    test_gateway_dialer_has_no_second_transport_security_stack above."""
    path = tmp_path / "example.py"
    path.write_text("from urllib import request\n", encoding="utf-8")

    imports = _imports(path)

    assert "urllib.request" in imports
    assert "urllib" in imports
