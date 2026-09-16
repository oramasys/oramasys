"""Optional AuthManager / AuthProviders + fleet binding (local secrets remain root)."""
from orama.auth.binding import FleetBinding, FleetBindingStore, ceremony_bind, fingerprint_secret
from orama.auth.manager import AuthManager, build_default_auth_manager
from orama.auth.protocol import AuthProvider, AuthResult

__all__ = [
    "AuthManager",
    "AuthProvider",
    "AuthResult",
    "FleetBinding",
    "FleetBindingStore",
    "build_default_auth_manager",
    "ceremony_bind",
    "fingerprint_secret",
]
