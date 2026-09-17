"""Firebase-shaped AuthProvider — STUB MVP (never root of trust).

Empty adapter + verify seam comments. No firebase-admin SDK.
Prefer Google OIDC for cloud optional login; Firebase is shaped-only.
"""
from __future__ import annotations

from typing import Mapping, Optional

from orama.auth.protocol import AuthResult


class FirebaseShapedProvider:
    """Shaped placeholder for a future Firebase ID-token verify adapter.

    NEVER use as fleet root of trust. Local Bearer + gossip remain sufficient.
    Future verify seam (comments only — not implemented):

    - Accept a presented Firebase ID token (header TBD).
    - Verify via google-auth ``verify_firebase_token`` (prefer over Admin SDK).
    - Bind Firebase UID → FleetBindingStore fingerprints (issuer=firebase).
    - Absence / outage must fall through; must not disable Bearer.
    """

    name = "firebase_shaped"

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
        # Stub MVP: empty. Do not call firebase-admin; do not authorize /run.
        return None
