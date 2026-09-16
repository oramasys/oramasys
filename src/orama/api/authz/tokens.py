"""Control-plane token resolution and comparison (S-AuthZ)."""
from __future__ import annotations

import os
import secrets
from typing import Iterable

# Weak placeholders rejected especially before LAN bind.
_WEAK_TOKENS = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "change-me-before-network-use",
        "test",
        "secret",
        "password",
        "token",
        "default",
    }
)


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_control_plane_token() -> str | None:
    """Return configured control-plane token, or None if unset/blank."""
    raw = os.environ.get("ORAMA_CONTROL_PLANE_TOKEN")
    if raw is None:
        return None
    token = raw.strip()
    return token or None


def is_weak_token(token: str | None) -> bool:
    if token is None:
        return True
    normalized = token.strip().lower()
    if not normalized or normalized in _WEAK_TOKENS:
        return True
    # Extremely short tokens are not suitable for LAN exposure.
    return len(token.strip()) < 16


def is_insecure_dev() -> bool:
    """Escape hatch: only meaningful when not LAN-bound (caller enforces)."""
    return _truthy(os.environ.get("ORAMA_INSECURE_DEV"))


def is_lan_bound() -> bool:
    return _truthy(os.environ.get("ORAMA_BIND_LAN"))


def is_loopback_host(host: str | None) -> bool:
    """True for loopback names only (no RFC1918 classification)."""
    if not host:
        return False
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h in {"localhost", "::1", "0:0:0:0:0:0:0:1"}:
        return True
    return h.startswith("127.")


def effective_listen_host() -> str:
    """Host the process intends to bind, from launcher/env (loopback default)."""
    for key in ("ORAMA_LISTEN_HOST", "ORAMA_BIND_HOST"):
        raw = os.environ.get(key, "").strip()
        if raw:
            return raw
    return "127.0.0.1"


def auth_enforced() -> bool:
    """Auth is enforced by default; insecure-dev only on loopback, never LAN.

    Keys off ``ORAMA_BIND_LAN`` and the actual listen host (``ORAMA_LISTEN_HOST``
    set by ``bin/serve``, else ``ORAMA_BIND_HOST``). Non-loopback listen never
    skips Bearer even when ``ORAMA_INSECURE_DEV`` is set.
    """
    if is_lan_bound():
        return True
    if not is_loopback_host(effective_listen_host()):
        return True
    if is_insecure_dev():
        return False
    return True


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, value = parts
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    return value or None


def token_matches(presented: str | None, candidates: Iterable[str | None] | None = None) -> bool:
    """Constant-time compare against configured token (and optional candidates)."""
    if presented is None:
        return False
    if candidates is None:
        candidates = (get_control_plane_token(),)
    for candidate in candidates:
        if candidate is None:
            continue
        if len(presented) == len(candidate) and secrets.compare_digest(presented, candidate):
            return True
    return False
