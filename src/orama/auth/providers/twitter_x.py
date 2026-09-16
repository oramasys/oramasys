"""X / Twitter OAuth AuthProvider via Authlib — optional, feature-flagged.

PKCE-ready adapter. Does not import httpx/requests (Telos owns IdP egress).
Never replaces local Bearer root; absence falls through.
HTTP attest requires a signed, short-lived server-issued artifact — never
``X-Twitter-User-Id`` alone.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Mapping, Optional

from orama.auth.protocol import AuthResult

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_ISSUER = "orama-twitter-oauth-artifact"


def _enabled() -> bool:
    return os.environ.get("ORAMA_AUTH_TWITTER_X", "").strip().lower() in _TRUTHY


def _artifact_secret() -> str | None:
    raw = os.environ.get("ORAMA_TWITTER_ARTIFACT_SECRET", "").strip()
    return raw or None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_twitter_oauth_artifact(
    subject: str,
    *,
    ttl_sec: int = 300,
    now: int | None = None,
) -> str | None:
    """Mint a HMAC-signed, expiring artifact after a completed OAuth ceremony."""
    secret = _artifact_secret()
    subject = subject.strip()
    if not secret or not subject:
        return None
    ts = int(time.time()) if now is None else now
    payload = {
        "sub": subject,
        "iss": _ISSUER,
        "iat": ts,
        "exp": ts + max(1, ttl_sec),
    }
    body = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64url(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_twitter_oauth_artifact(token: str, *, now: int | None = None) -> str | None:
    secret = _artifact_secret()
    if not secret or not token or "." not in token:
        return None
    body, _, sig = token.partition(".")
    expected = _b64url(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    if len(sig) != len(expected) or not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    ts = int(time.time()) if now is None else now
    try:
        exp = int(payload["exp"])
        iat = int(payload["iat"])
    except (KeyError, TypeError, ValueError):
        return None
    if payload.get("iss") != _ISSUER:
        return None
    if iat > ts + 60 or exp <= ts:
        return None
    subject = str(payload.get("sub", "")).strip()
    return subject or None


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
        # Spoofable user-id headers are ignored. Require a server-issued artifact.
        artifact = (
            headers.get("X-Twitter-OAuth-Artifact")
            or headers.get("x-twitter-oauth-artifact")
            or ""
        ).strip()
        if not artifact:
            return None
        subject = verify_twitter_oauth_artifact(artifact)
        if not subject:
            return None
        return AuthResult(
            subject=subject,
            issuer="twitter-x",
            provider=self.name,
        )
