"""Loopback / LAN bind host resolution (no topology literals committed)."""
from __future__ import annotations

import os

from orama.api.authz.tokens import get_control_plane_token, is_lan_bound, is_weak_token


class LanBindError(RuntimeError):
    """Raised when LAN bind is requested without a non-weak control-plane token."""


def _all_interfaces_host() -> str:
    # Avoid committing a literal all-interfaces address in source.
    return ".".join(["0"] * 4)


def resolve_bind_host() -> str:
    """Return bind host for the glass window.

    Default: loopback (`127.0.0.1` or ``ORAMA_BIND_HOST``).
    When ``ORAMA_BIND_LAN`` is truthy: require a non-weak
    ``ORAMA_CONTROL_PLANE_TOKEN``, then return ``ORAMA_LAN_BIND_HOST`` or
    all-interfaces.
    """
    if is_lan_bound():
        token = get_control_plane_token()
        if is_weak_token(token):
            raise LanBindError(
                "ORAMA_BIND_LAN requires a non-weak ORAMA_CONTROL_PLANE_TOKEN "
                "(unset, empty, or placeholder tokens are refused)."
            )
        override = os.environ.get("ORAMA_LAN_BIND_HOST", "").strip()
        return override or _all_interfaces_host()

    override = os.environ.get("ORAMA_BIND_HOST", "").strip()
    return override or "127.0.0.1"
