"""BitChat proximity AuthProvider — STUB only.

Real Noise / BLE / proximity is plan-only (see pr-e-bitchat-noise-plan).
This stub is never configured and never authorizes.
"""
from __future__ import annotations

from typing import Mapping, Optional

from orama.auth.protocol import AuthResult


class BitChatProximityProvider:
    """Placeholder for future Noise-static-key fingerprint attest.

    Returns not-configured / None. Do not implement BLE or Noise here.
    """

    name = "bitchat_shaped"

    def is_configured(self) -> bool:
        return False

    def get_auth_header(self) -> Mapping[str, str]:
        return {}

    def verify_peer_auth(self, headers: Mapping[str, str]) -> bool:
        return False

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
        # Stub: never matches. Future: issuer=bitchat-noise, subject=fingerprint.
        return None
