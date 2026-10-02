"""Data-free Knowledge Portal HTML shell (D2) and its response headers."""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

_PAGE = Path(__file__).resolve().with_name("static") / "index.html"
_STYLE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _src(name: str, blocks: list[str]) -> str:
    if not blocks:
        return f"{name} 'none'"
    return f"{name} " + " ".join(_csp_hash(block) for block in blocks)


def shell_headers(html: str) -> dict[str, str]:
    csp = "; ".join(
        (
            "default-src 'none'",
            _src("script-src", _SCRIPT.findall(html)),
            _src("style-src", _STYLE.findall(html)),
            "connect-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        )
    )
    return {
        "Content-Security-Policy": csp,
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def render_shell() -> tuple[str, dict[str, str]]:
    html = _PAGE.read_text(encoding="utf-8")
    return html, shell_headers(html)
