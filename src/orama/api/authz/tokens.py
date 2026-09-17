"""Control-plane token resolution and comparison (S-AuthZ)."""
from __future__ import annotations

import ipaddress
import os
import secrets
from typing import Iterable, Mapping

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
    """True for missing, placeholder, or extremely short control-plane tokens."""
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
    """True when ``ORAMA_BIND_LAN`` requests a non-loopback listen address."""
    return _truthy(os.environ.get("ORAMA_BIND_LAN"))


def is_loopback_host(host: str | None) -> bool:
    """True for loopback names/IPs only (no RFC1918, no ``127.`` hostname prefix)."""
    if not host:
        return False
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if "%" in h:
        h = h.split("%", 1)[0]
    if h in {"localhost", "localhost."}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def effective_listen_host() -> str:
    """Host the process *declares* it will bind, from launcher/env (loopback default).

    This is declared intent, not proof: a process started without going
    through ``bin/serve`` (direct ``uvicorn --host 0.0.0.0``, a container
    CMD, a systemd unit) sets none of these variables, and this function
    then silently reports the loopback default even though the real bind
    may be non-loopback. A security decision MUST NOT rely on this alone
    -- see ``observed_listen_host`` for the per-request ground truth that
    ``auth_enforced`` also checks.
    """
    for key in ("ORAMA_LISTEN_HOST", "UVICORN_HOST", "ORAMA_BIND_HOST"):
        raw = os.environ.get(key, "").strip()
        if raw:
            return raw
    return "127.0.0.1"


def observed_listen_host(scope: Mapping[str, object] | None) -> str | None:
    """Ground-truth bind host for one request, read from the ASGI ``scope``.

    Per the ASGI spec, ``scope["server"]`` is the interface the connection
    actually arrived on -- populated by the real server (uvicorn et al.)
    regardless of how the process was launched, unlike
    ``effective_listen_host()`` which only reflects declared launcher
    intent and silently defaults to loopback when nothing declares
    otherwise. Returns ``None`` when no usable server tuple is present, so
    callers can fail closed instead of assuming loopback.
    """
    if not scope:
        return None
    server = scope.get("server")
    if not server or not isinstance(server, (tuple, list)) or not server[0]:
        return None
    return str(server[0])


def auth_enforced(scope: Mapping[str, object] | None = None) -> bool:
    """Auth is enforced by default; insecure-dev only on loopback, never LAN.

    Two independent host signals gate the ``ORAMA_INSECURE_DEV`` escape
    hatch, and either one reporting non-loopback is enough to keep auth on:

    1. ``effective_listen_host()`` -- declared launcher intent
       (``ORAMA_LISTEN_HOST`` from ``bin/serve``, else ``UVICORN_HOST``,
       else ``ORAMA_BIND_HOST``).
    2. ``observed_listen_host(scope)`` -- ground truth from the live ASGI
       request, when a scope is supplied. This closes the gap where a
       process is started without any of those three variables set:
       declared intent alone would silently default to loopback and let
       ``ORAMA_INSECURE_DEV`` disable auth on a listener that is actually
       LAN/internet exposed.

    Callers handling a real request (the auth middleware) MUST pass the
    request's ``scope``. Callers with no request in flight (tests, CLI
    banners) may omit it, in which case only declared intent is checked --
    identical to this function's behavior before ``observed_listen_host``
    existed.
    """
    if is_lan_bound():
        return True
    if not is_loopback_host(effective_listen_host()):
        return True
    observed = observed_listen_host(scope)
    if observed is not None and not is_loopback_host(observed):
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
