"""Grandfathered BearerTokenProvider — always registered last by AuthManager."""
from __future__ import annotations

from typing import Mapping, Optional

from orama.api.authz.tokens import extract_bearer, get_control_plane_token, token_matches
from orama.auth.protocol import AuthResult


class BearerTokenProvider:
    name = "bearer"

    def is_configured(self) -> bool:
        # Bearer lane is always present; success still needs a configured token.
        return True

    def get_auth_header(self) -> Mapping[str, str]:
        token = get_control_plane_token()
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

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
        auth = headers.get("Authorization") or headers.get("authorization")
        presented = extract_bearer(auth)
        configured = get_control_plane_token()
        if presented is None or configured is None:
            return None
        if not token_matches(presented, (configured,)):
            return None
        return AuthResult(
            subject="local-operator",
            issuer="orama-control-plane",
            provider=self.name,
        )
