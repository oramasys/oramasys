"""Buzz / Nostr NIP-98 AuthProvider — optional, feature-flagged."""
from __future__ import annotations

import os
from typing import Mapping, Optional

from orama.auth.nip98.replay import ReplayCache
from orama.auth.nip98.verify import Nip98Error, verify_nip98
from orama.auth.protocol import AuthResult

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _enabled() -> bool:
    return os.environ.get("ORAMA_AUTH_BUZZ_NIP98", "").strip().lower() in _TRUTHY


def _skew_sec() -> int:
    raw = os.environ.get("ORAMA_NIP98_SKEW_SEC", "60").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 60


def _require_payload() -> bool:
    return os.environ.get("ORAMA_NIP98_REQUIRE_PAYLOAD", "").strip().lower() in _TRUTHY


def _replay_max() -> int:
    raw = os.environ.get("ORAMA_NIP98_REPLAY_MAX", "4096").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 4096


class BuzzNostrProvider:
    """Verify ``Authorization: Nostr <base64(kind:27235)>`` per NIP-98.

    Optional enabling only — absence never disables Bearer. Successful verify
    yields subject = hex pubkey for FleetBindingStore; does not authorize
    ``POST /run`` alone (S-AuthZ Bearer remains root).
    """

    name = "buzz-nip98"

    def __init__(self, replay: ReplayCache | None = None) -> None:
        self._replay = replay or ReplayCache(
            max_size=_replay_max(), ttl_sec=float(_skew_sec())
        )

    def is_configured(self) -> bool:
        return _enabled()

    def get_auth_header(self) -> Mapping[str, str]:
        # Clients sign; server does not hold nsec.
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
            # Disabled: ignore Nostr scheme (fall through to Bearer).
            return None
        auth = headers.get("Authorization") or headers.get("authorization")
        if not auth:
            return None
        scheme = auth.split(None, 1)[0].lower()
        if scheme != "nostr":
            return None
        try:
            result = verify_nip98(
                authorization=auth,
                method=method,
                url=url or "http://localhost/",
                body=body,
                skew_sec=_skew_sec(),
                require_payload=_require_payload(),
                replay=self._replay,
            )
        except Nip98Error as exc:
            if str(exc) == "not_applicable":
                return None
            # Attempted Nostr auth failed — do not fall through as success.
            return None
        return AuthResult(
            subject=result.pubkey,
            issuer="nostr",
            provider=self.name,
            raw={"event_id": result.event_id},
        )
