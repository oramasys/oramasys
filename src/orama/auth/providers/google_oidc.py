"""Google OIDC AuthProvider via Authlib (+ joserfc) — optional, feature-flagged.

Outbound IdP dials are a Telos concern; this adapter does not import httpx/requests.
When enabled, it can verify a presented Google ID token if JWKS material is
supplied locally (``ORAMA_GOOGLE_JWKS_JSON``) — never replaces Bearer root.
"""
from __future__ import annotations

import json
import os
from typing import Any, Mapping, Optional

from orama.auth.protocol import AuthResult

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _enabled() -> bool:
    return os.environ.get("ORAMA_AUTH_GOOGLE_OIDC", "").strip().lower() in _TRUTHY


class GoogleOidcProvider:
    name = "google"

    # Authlib metadata URL (documentation / ceremony wiring). Live fetch = Telos.
    SERVER_METADATA_URL = (
        "https://accounts.google.com/.well-known/openid-configuration"
    )

    def is_configured(self) -> bool:
        if not _enabled():
            return False
        client_id = os.environ.get("ORAMA_GOOGLE_CLIENT_ID", "").strip()
        return bool(client_id)

    def get_auth_header(self) -> Mapping[str, str]:
        # Outbound Google tokens are not fleet Bearer substitutes.
        return {}

    def verify_peer_auth(self, headers: Mapping[str, str]) -> bool:
        return self.authenticate_request(headers) is not None

    def refresh_if_needed(self) -> None:
        return None

    def identity_subject(self) -> Optional[str]:
        return None

    def oauth_client_config(self) -> dict[str, Any]:
        """Authlib-compatible client kwargs for ceremony (Telos must dial)."""
        return {
            "name": "google",
            "client_id": os.environ.get("ORAMA_GOOGLE_CLIENT_ID", "").strip(),
            "client_secret": os.environ.get("ORAMA_GOOGLE_CLIENT_SECRET", "").strip(),
            "server_metadata_url": self.SERVER_METADATA_URL,
            "client_kwargs": {"scope": "openid email profile"},
        }

    def build_authlib_oauth(self):
        """Return an Authlib ``OAuth`` registry with Google OIDC registered.

        Does not perform network I/O; metadata fetch/token exchange belong to
        Telos-backed transport when wired into a ceremony/portal.
        """
        from authlib.integrations.starlette_client import OAuth

        oauth = OAuth()
        cfg = self.oauth_client_config()
        oauth.register(
            name=cfg["name"],
            client_id=cfg["client_id"],
            client_secret=cfg.get("client_secret") or None,
            server_metadata_url=cfg["server_metadata_url"],
            client_kwargs=cfg["client_kwargs"],
        )
        return oauth

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
        # Optional lane: look for explicit Google ID token header.
        id_token = headers.get("X-Google-ID-Token") or headers.get("x-google-id-token")
        if not id_token:
            # Fall through — absence never disables Bearer.
            return None
        claims = self._verify_id_token(id_token)
        if claims is None:
            return None
        subject = str(claims.get("sub", ""))
        if not subject:
            return None
        return AuthResult(
            subject=subject,
            issuer=str(claims.get("iss", "https://accounts.google.com")),
            provider=self.name,
            raw={"claims": dict(claims)},
        )

    def _verify_id_token(self, token: str) -> Optional[Mapping[str, Any]]:
        """Verify ID token with joserfc when JWKS JSON is injected locally."""
        jwks_raw = os.environ.get("ORAMA_GOOGLE_JWKS_JSON", "").strip()
        client_id = os.environ.get("ORAMA_GOOGLE_CLIENT_ID", "").strip()
        if not jwks_raw or not client_id:
            # Without local JWKS, do not phone home (Telos owns egress).
            return None
        try:
            from joserfc import jwt
            from joserfc.jwk import KeySet
            from joserfc.jwt import JWTClaimsRegistry
        except ImportError:
            return None
        try:
            key_set = KeySet.import_key_set(json.loads(jwks_raw))
            token_obj = jwt.decode(token, key_set)
            payload = dict(token_obj.claims)
            JWTClaimsRegistry(exp={"essential": True}).validate(payload)
        except Exception:
            return None
        aud = payload.get("aud")
        if isinstance(aud, list):
            if client_id not in aud:
                return None
        elif aud != client_id:
            return None
        iss = str(payload.get("iss", ""))
        if iss not in {
            "https://accounts.google.com",
            "accounts.google.com",
        }:
            return None
        return payload
