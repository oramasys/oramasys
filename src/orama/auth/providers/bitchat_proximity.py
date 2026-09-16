"""BitChat proximity AuthProvider — Noise XX over BLE-shaped runtime.

Optional enabling only. Absence of BLE/radio never disables Bearer.
Identity subject = SHA-256 fingerprint of the remote Noise static key.
Does not vendor the BitChat Swift/Android mesh; does not authorize /run alone.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

from orama.auth.bitchat.ble import ProximityAttest
from orama.auth.protocol import AuthResult

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_SESSIONS: dict[str, ProximityAttest] = {}


def _enabled() -> bool:
    return os.environ.get("ORAMA_AUTH_BITCHAT_PROXIMITY", "").strip().lower() in _TRUTHY


def remember_proximity_session(attest: ProximityAttest) -> None:
    """Record a completed BLE Noise handshake for optional HTTP attest headers."""
    _SESSIONS[attest.remote_fingerprint] = attest


def clear_proximity_sessions() -> None:
    _SESSIONS.clear()


class BitChatProximityProvider:
    """Prove possession of a BitChat-compatible Noise static key in proximity."""

    name = "bitchat_shaped"

    def is_configured(self) -> bool:
        return _enabled()

    def get_auth_header(self) -> Mapping[str, str]:
        return {}

    def verify_peer_auth(self, headers: Mapping[str, str]) -> bool:
        return self.authenticate_request(headers) is not None

    def refresh_if_needed(self) -> None:
        return None

    def identity_subject(self) -> Optional[str]:
        return None

    def authenticate_request(
        self,
        headers: Mapping[str, str],
        *,
        method: str = "GET",
        url: str = "",
        body: bytes = b"",
    ) -> Optional[AuthResult]:
        if not self.is_configured():
            return None
        fp = (
            headers.get("X-BitChat-Fingerprint")
            or headers.get("x-bitchat-fingerprint")
            or ""
        ).strip().lower()
        if not fp:
            # No proximity attest presented — fall through (never disable Bearer).
            return None
        attest = _SESSIONS.get(fp)
        if attest is None:
            return None
        return AuthResult(
            subject=attest.remote_fingerprint,
            issuer="bitchat-noise",
            provider=self.name,
            raw={"peer_id": attest.remote_peer_id, "nonce": attest.nonce.hex()},
        )
