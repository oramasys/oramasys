"""AuthManager: optional providers first, Bearer always last / grandfathered."""
from __future__ import annotations

from typing import Iterable, Mapping, Optional, Sequence

from orama.auth.protocol import AuthProvider, AuthResult
from orama.auth.providers.bearer import BearerTokenProvider


class AuthManager:
    """Try configured optional providers, then Bearer (always registered last).

    Optional IdP / Nostr / stubs never disable local auth when absent or offline:
    unconfigured providers are skipped; failed *attempted* schemes may deny that
    lane only. Bearer remains the grandfathered fallback and S-AuthZ root.
    """

    def __init__(self, providers: Sequence[AuthProvider] | None = None) -> None:
        if providers is None:
            self._providers: list[AuthProvider] = [BearerTokenProvider()]
        else:
            self._providers = list(providers)
            if not any(getattr(p, "name", "") == "bearer" for p in self._providers):
                self._providers.append(BearerTokenProvider())

    @property
    def providers(self) -> tuple[AuthProvider, ...]:
        return tuple(self._providers)

    def authenticate_outbound(self) -> Mapping[str, str]:
        """First configured provider that can mint outbound headers; else empty."""
        for provider in self._providers:
            if not provider.is_configured():
                continue
            try:
                provider.refresh_if_needed()
                headers = provider.get_auth_header()
            except Exception:
                continue
            if headers:
                return dict(headers)
        return {}

    def verify_inbound(
        self,
        headers: Mapping[str, str],
        *,
        method: str = "GET",
        url: str = "",
        body: bytes = b"",
    ) -> bool:
        """True when any configured provider (Bearer last) authenticates the request."""
        result = self.authenticate_request(
            headers, method=method, url=url, body=body
        )
        return result is not None

    def authenticate_request(
        self,
        headers: Mapping[str, str],
        *,
        method: str = "GET",
        url: str = "",
        body: bytes = b"",
    ) -> Optional[AuthResult]:
        """Return first successful AuthResult; Bearer last among configured."""
        for provider in self._providers:
            if not provider.is_configured():
                continue
            result = provider.authenticate_request(
                headers, method=method, url=url, body=body
            )
            if result is not None:
                return result
        return None


def build_default_auth_manager() -> AuthManager:
    """Construct manager with feature-flagged optional providers + Bearer last."""
    from orama.auth.providers.bitchat_proximity import BitChatProximityProvider
    from orama.auth.providers.buzz_nip98 import BuzzNostrProvider
    from orama.auth.providers.firebase_shaped import FirebaseShapedProvider
    from orama.auth.providers.google_oidc import GoogleOidcProvider
    from orama.auth.providers.twitter_x import TwitterXOauthProvider

    # Doc 49 order: BUZZ → Twitter/X → Google → BitChat proximity → Firebase stub → Bearer last.
    ordered: list[AuthProvider] = [
        BuzzNostrProvider(),
        TwitterXOauthProvider(),
        GoogleOidcProvider(),
        BitChatProximityProvider(),
        FirebaseShapedProvider(),
        BearerTokenProvider(),
    ]
    return AuthManager(ordered)


def configured_provider_names(manager: AuthManager | None = None) -> list[str]:
    mgr = manager or build_default_auth_manager()
    return [p.name for p in mgr.providers if p.is_configured()]
