"""Declarative HTTP route capability manifest for S-AuthZ."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class RouteCapability(str, Enum):
    PUBLIC = "public"
    READ = "read"
    MUTATE = "mutate"
    LIFECYCLE = "lifecycle"
    DANGEROUS_WORKER = "dangerous-worker"


@dataclass(frozen=True, slots=True)
class RouteSpec:
    method: str
    path: str
    capability: RouteCapability

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)


# Every non-framework glass-window route must appear here before merge.
ROUTE_MANIFEST: tuple[RouteSpec, ...] = (
    RouteSpec("GET", "/health", RouteCapability.PUBLIC),
    RouteSpec("POST", "/run", RouteCapability.MUTATE),
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
    if capability is None:
        # Undeclared routes fail closed.
        return True
    return capability is not RouteCapability.PUBLIC


def manifest_keys() -> set[tuple[str, str]]:
    return {spec.key for spec in ROUTE_MANIFEST}


def iter_manifest() -> Iterable[RouteSpec]:
    return ROUTE_MANIFEST
