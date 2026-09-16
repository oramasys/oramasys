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


def auth_enforced() -> bool:
    """Auth is enforced by default; insecure-dev only when not LAN-bound."""
    if is_insecure_dev() and not is_lan_bound():
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
