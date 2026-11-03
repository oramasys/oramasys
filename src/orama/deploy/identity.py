"""Opt-in, loader-bound public topology snapshot; not deployment qualification.

This captures only the profile loader's result. It does not observe other loaders,
startup checks, installed artifacts, policy, filesystem identity, or approval.
The calling process must actually use ``effective`` for the observation to apply.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping

from . import profile


@dataclass(frozen=True)
class PublicProjection:
    """Closed, non-secret projection of one profile load (schema version 1)."""

    schema: int
    outcome: str
    source: str
    role: str | None
    serving_applicability: str | None
    public_state: str | None
    role_override: str
    refusal: str | None


@dataclass(frozen=True)
class LoadedIdentity:
    """Projection plus the loader result; the latter may contain private values."""

    projection: PublicProjection
    effective: profile.EffectiveNode | None = field(repr=False)


def load_with_identity(env: Mapping[str, str] | None = None) -> LoadedIdentity:
    """Load once using a private environment snapshot and capture safe fields.

    A profile refusal returns a fixed classification without exception text. The
    existing ``load_effective`` API and its exception behavior are unchanged.
    Neither this snapshot nor a successful load authorizes serving or proves R5.
    """
    source_env = os.environ if env is None else env
    captured_env = {
        key: source_env[key]
        for key in (profile.ENV_PROFILE, profile.ENV_NODE_ID, profile.ENV_NODE_ROLE)
        if key in source_env
    }
    try:
        effective = profile.load_effective(captured_env)
    except profile.ProfileError:
        # Parsing may fail before the override is examined; don't claim an effect.
        override_result = "unknown" if (captured_env.get(profile.ENV_NODE_ROLE) or "").strip() else "absent"
        return LoadedIdentity(
            PublicProjection(1, "refused", "refused", None, None, None, override_result, "profile-invalid"),
            None,
        )

    override = (captured_env.get(profile.ENV_NODE_ROLE) or "").strip()
    original_role = effective.profile_role or "client"
    if not override:
        override_result = "absent"
    elif override == original_role:
        override_result = "same"
    elif effective.role != original_role:
        override_result = "downgraded"
    else:
        override_result = "ignored"
    return LoadedIdentity(
        PublicProjection(
            1, "loaded" if effective.source == "profile" else "fallback",
            effective.source, effective.role, effective.serving,
            effective.public_state, override_result, None,
        ),
        effective,
    )
