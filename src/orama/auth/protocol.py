"""AuthProvider protocol and shared result types (doc 49 + binding brief)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Successful optional-provider verification (attest / unlock only)."""

    subject: str
    issuer: str
    provider: str
    raw: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class AuthProvider(Protocol):
    """Optional identity upgrade adapter.

    Providers never replace local Bearer / gossip roots. Missing or offline
    providers must fall through (return None / False) without disabling local auth.
    """

    name: str

    def is_configured(self) -> bool:
        """True when this optional lane is enabled and ready."""
        ...

    def get_auth_header(self) -> Mapping[str, str]:
        """Outbound peer/request headers for this provider (may be empty)."""
        ...

    def verify_peer_auth(self, headers: Mapping[str, str]) -> bool:
        """Inbound peer verification for this provider lane."""
        ...

    def refresh_if_needed(self) -> None:
        """Refresh short-lived credentials if applicable (no-op OK)."""
        ...

    def identity_subject(self) -> Optional[str]:
        """Stable subject for binding ceremony; None if anonymous/local-only."""
        ...

    def authenticate_request(
        self,
        headers: Mapping[str, str],
        *,
        method: str = "GET",
        url: str = "",
        body: bytes = b"",
    ) -> Optional[AuthResult]:
        """Verify an inbound request for this lane.

        Return AuthResult on success, None if not applicable (fall through).
        """
        ...
