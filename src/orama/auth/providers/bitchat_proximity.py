"""BitChat proximity AuthProvider — Noise XX over BLE-shaped runtime.

Optional enabling only. Absence of BLE/radio never disables Bearer.
Identity subject = SHA-256 fingerprint of the remote Noise static key.
HTTP attest requires a high-entropy expiring session credential minted at
handshake — the fingerprint header is an identifier, not a secret.
Does not vendor the BitChat Swift/Android mesh; does not authorize /run alone.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Mapping, Optional

from orama.auth.bitchat.ble import ProximityAttest
from orama.auth.protocol import AuthResult

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_DEFAULT_TTL_SEC = 300.0
_SESSIONS: dict[str, "ProximitySession"] = {}
_SESSIONS_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class ProximitySession:
    attest: ProximityAttest
    credential: str
    expires_at: float


def _enabled() -> bool:
    return os.environ.get("ORAMA_AUTH_BITCHAT_PROXIMITY", "").strip().lower() in _TRUTHY


def remember_proximity_session(
    attest: ProximityAttest,
    *,
    ttl_sec: float = _DEFAULT_TTL_SEC,
    now: float | None = None,
) -> str:
    """Mint a high-entropy session credential after a successful Noise handshake."""
    ts = time.time() if now is None else now
    credential = secrets.token_urlsafe(32)
    session = ProximitySession(
        attest=attest,
        credential=credential,
        expires_at=ts + max(1.0, ttl_sec),
    )
    with _SESSIONS_LOCK:
        _SESSIONS[credential] = session
    return credential


def clear_proximity_sessions() -> None:
    with _SESSIONS_LOCK:
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
        credential = (
            headers.get("X-BitChat-Session")
            or headers.get("x-bitchat-session")
            or ""
        ).strip()
        if not credential:
            # Fingerprint-only is not proof — fall through (never disable Bearer).
            return None
        presented_fp = (
            headers.get("X-BitChat-Fingerprint")
            or headers.get("x-bitchat-fingerprint")
            or ""
        ).strip()
        now = time.time()
        with _SESSIONS_LOCK:
            session = _SESSIONS.get(credential)
            if session is not None and now >= session.expires_at:
                _SESSIONS.pop(credential, None)
                session = None
        if session is None:
            return None
        if not secrets.compare_digest(session.credential, credential):
            return None
        attest = session.attest
        expected_fp = attest.remote_fingerprint
        if presented_fp and (
            len(presented_fp) != len(expected_fp)
            or not secrets.compare_digest(presented_fp, expected_fp)
        ):
            return None
        return AuthResult(
            subject=attest.remote_fingerprint,
            issuer="bitchat-noise",
            provider=self.name,
            raw={"peer_id": attest.remote_peer_id, "nonce": attest.nonce.hex()},
        )
