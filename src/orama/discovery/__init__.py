"""Composition-owned discovery. Perpetua Core stores observations; Telos probes them."""

from .observe import record_probed
from .probe import ProbeResult, health_probe

__all__ = ["ProbeResult", "health_probe", "record_probed"]
