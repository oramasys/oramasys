"""Oramasys discovery composition: Telos-backed probes + registry I/O.

Pure backend types and selection logic remain in ``perpetua_core.discovery``.
"""
from .probe import ProbeResult, health_probe
from .registry import DiscoveryBackendRegistry

__all__ = [
    "DiscoveryBackendRegistry",
    "ProbeResult",
    "health_probe",
]
