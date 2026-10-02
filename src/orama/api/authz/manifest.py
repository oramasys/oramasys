"""Declarative HTTP route capability manifest for S-AuthZ."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class RouteCapability(str, Enum):
    """The authorization class a glass-window route demands of its caller."""

    PUBLIC = "public"
    READ = "read"
    MUTATE = "mutate"
    LIFECYCLE = "lifecycle"
    DANGEROUS_WORKER = "dangerous-worker"


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """One declared route: HTTP method, exact path and the capability it needs."""

    method: str
    path: str
    capability: RouteCapability

    @property
    def key(self) -> tuple[str, str]:
        """Return the upper-cased method and path used to match this route."""
        return (self.method.upper(), self.path)


# Every non-framework glass-window route must appear here before merge.
ROUTE_MANIFEST: tuple[RouteSpec, ...] = (
    RouteSpec("GET", "/api/workspace/capabilities", RouteCapability.READ),
    RouteSpec("POST", "/api/workspace/run", RouteCapability.MUTATE),
    RouteSpec("GET", "/health", RouteCapability.PUBLIC),
    RouteSpec("POST", "/run", RouteCapability.MUTATE),
    RouteSpec("POST", "/adjustments", RouteCapability.LIFECYCLE),
    RouteSpec("GET", "/api/knowledge/search", RouteCapability.READ),
    RouteSpec("POST", "/api/mcp", RouteCapability.READ),
    RouteSpec("POST", "/api/a2a", RouteCapability.READ),
    RouteSpec("GET", "/.well-known/agent-card.json", RouteCapability.PUBLIC),
    # D2: data-free HTML shell. Isolated; drop this spec to require Bearer for GET /knowledge.
    RouteSpec("GET", "/knowledge", RouteCapability.PUBLIC),
)

# FastAPI / OpenAPI surfaces: public for alpha (operator docs on loopback).
_FRAMEWORK_PUBLIC: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/redoc"),
        ("GET", "/openapi.json"),
        ("HEAD", "/docs"),
        ("HEAD", "/redoc"),
        ("HEAD", "/openapi.json"),
    }
)


def capability_for(method: str, path: str) -> RouteCapability | None:
    """Return capability for an exact route, or None if undeclared."""
    key = (method.upper(), path)
    for spec in ROUTE_MANIFEST:
        if spec.key == key:
            return spec.capability
    if key in _FRAMEWORK_PUBLIC:
        return RouteCapability.PUBLIC
    return None


def requires_auth(capability: RouteCapability | None) -> bool:
    """Return whether ``capability`` needs authentication; undeclared routes do."""
    if capability is None:
        # Undeclared routes fail closed.
        return True
    return capability is not RouteCapability.PUBLIC


def manifest_keys() -> set[tuple[str, str]]:
    """Return the (method, path) key of every declared route."""
    return {spec.key for spec in ROUTE_MANIFEST}


def iter_manifest() -> Iterable[RouteSpec]:
    """Iterate over every declared route in declaration order."""
    return ROUTE_MANIFEST
