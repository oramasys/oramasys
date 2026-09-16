"""X / Twitter OAuth AuthProvider via Authlib — optional, feature-flagged.

PKCE-ready adapter. Does not import httpx/requests (Telos owns IdP egress).
Never replaces local Bearer root; absence falls through.
"""
from __future__ import annotations

import os
from typing import Any, Mapping, Optional

from orama.auth.protocol import AuthResult

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _enabled() -> bool:
    return os.environ.get("ORAMA_AUTH_TWITTER_X", "").strip().lower() in _TRUTHY


class TwitterXOauthProvider:
    name = "twitter_x"

    AUTHORIZE_URL = "https://twitter.com/i/oauth2/authorize"
    TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
    USERINFO_URL = "https://api.twitter.com/2/users/me"

    def is_configured(self) -> bool:
        if not _enabled():
            return False
        client_id = os.environ.get("ORAMA_TWITTER_CLIENT_ID", "").strip()
        return bool(client_id)

    def get_auth_header(self) -> Mapping[str, str]:
        return {}

    def verify_peer_auth(self, headers: Mapping[str, str]) -> bool:
        return self.authenticate_request(headers) is not None

    def refresh_if_needed(self) -> None:
        return None

    def identity_subject(self) -> Optional[str]:
        return None

    def oauth_client_config(self) -> dict[str, Any]:
        """Authlib-compatible OAuth2 client kwargs (PKCE). Dial via Telos."""
        return {
            "name": "twitter_x",
            "client_id": os.environ.get("ORAMA_TWITTER_CLIENT_ID", "").strip(),
            "client_secret": os.environ.get("ORAMA_TWITTER_CLIENT_SECRET", "").strip(),
            "authorize_url": self.AUTHORIZE_URL,
            "access_token_url": self.TOKEN_URL,
            "api_base_url": "https://api.twitter.com/2/",
            "client_kwargs": {
                "scope": "users.read tweet.read offline.access",
                "code_challenge_method": "S256",
            },
        }

    def build_authlib_oauth(self):
        """Return an Authlib ``OAuth`` registry with this client registered.

        Intended for ceremony / portal wiring. Does not perform network I/O.
        """
        from authlib.integrations.starlette_client import OAuth

        oauth = OAuth()
        cfg = self.oauth_client_config()
        oauth.register(
            name=cfg["name"],
            client_id=cfg["client_id"],
            client_secret=cfg.get("client_secret") or None,
            authorize_url=cfg["authorize_url"],
            access_token_url=cfg["access_token_url"],
            api_base_url=cfg["api_base_url"],
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
        # Optional attest header after ceremony; live userinfo = Telos later.
        subject = headers.get("X-Twitter-User-Id") or headers.get("x-twitter-user-id")
        if not subject:
            return None
        subject = subject.strip()
        if not subject:
            return None
        return AuthResult(
            subject=subject,
            issuer="twitter-x",
            provider=self.name,
        )
