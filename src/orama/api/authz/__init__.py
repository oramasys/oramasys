"""S-AuthZ: HTTP control-plane capability manifest + bearer middleware."""
from orama.api.authz.bind import LanBindError, assert_host_allowed, resolve_bind_host
from orama.api.authz.manifest import (
    ROUTE_MANIFEST,
    RouteCapability,
    RouteSpec,
    capability_for,
    manifest_keys,
    requires_auth,
)
from orama.api.authz.middleware import AuthzMiddleware, install_authz
from orama.api.authz.tokens import (
    auth_enforced,
    effective_listen_host,
    extract_bearer,
    get_control_plane_token,
    is_insecure_dev,
    is_lan_bound,
    is_loopback_host,
    is_weak_token,
    token_matches,
)

__all__ = [
    "AuthzMiddleware",
    "LanBindError",
    "ROUTE_MANIFEST",
    "RouteCapability",
    "RouteSpec",
    "assert_host_allowed",
    "auth_enforced",
    "capability_for",
    "effective_listen_host",
    "extract_bearer",
    "get_control_plane_token",
    "install_authz",
    "is_insecure_dev",
    "is_lan_bound",
    "is_loopback_host",
    "is_weak_token",
    "manifest_keys",
    "requires_auth",
    "resolve_bind_host",
    "token_matches",
]
