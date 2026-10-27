"""Four independent readiness facts for the serving surface (DRAFT).

``verifier_ready``, ``issuer_ready``, ``serving_enabled`` and ``autonomous_policy_ready`` each come
from their own source and none is derived from another. A probe that raises or answers anything but
``True`` is ``False``. Only ``verifier_ready`` and ``serving_enabled`` gate ``/readyz``; the other two
are reported so an operator can see them and are never used to infer permission.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from orama.api.capabilities import CapabilityView

Probe = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class ReadinessProbes:
    """Optional injected probes; a missing probe is a False fact, never a True one."""

    verifier: Probe | None = None
    issuer: Probe | None = None
    autonomous_policy: Probe | None = None


@dataclass(frozen=True, slots=True)
class ReadinessFacts:
    """The four facts, each established independently."""

    verifier_ready: bool
    issuer_ready: bool
    serving_enabled: bool
    autonomous_policy_ready: bool

    def as_public(self) -> dict[str, bool]:
        """Return the facts as plain booleans for the data-free readiness payload."""
        return {
            "verifier_ready": self.verifier_ready,
            "issuer_ready": self.issuer_ready,
            "serving_enabled": self.serving_enabled,
            "autonomous_policy_ready": self.autonomous_policy_ready,
        }

    def serving_facts_hold(self) -> bool:
        """Return True only when verification can be served: a ready verifier AND serving enabled."""
        return self.verifier_ready and self.serving_enabled


def _probe(probe: Probe | None) -> bool:
    """Run a probe; absence, an exception or any non-True answer is False."""
    if probe is None:
        return False
    try:
        return probe() is True
    except Exception:  # noqa: BLE001 - a failing probe is not-ready, never ready
        return False


def collect_facts(
    capabilities: CapabilityView, *, verify_authority_present: bool, probes: ReadinessProbes
) -> ReadinessFacts:
    """Establish each fact from its own source without inferring one from another.

    ``verifier_ready`` needs the injected verify-only authority and, when given, its probe.
    ``issuer_ready`` and ``autonomous_policy_ready`` come only from their probes.
    ``serving_enabled`` is the effective ``serving`` capability bit and nothing else.
    """
    verifier = verify_authority_present and (probes.verifier is None or _probe(probes.verifier))
    return ReadinessFacts(
        verifier_ready=verifier,
        issuer_ready=_probe(probes.issuer),
        serving_enabled=capabilities.is_effective("serving"),
        autonomous_policy_ready=_probe(probes.autonomous_policy),
    )
