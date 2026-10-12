"""Immutable value types for T2 multi-unit accounting.

These values describe consumption only. In particular, ``effect_attempts``
records attempts and does not authorize an external effect.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ChargeUnits:
    """Four nonnegative accounting quantities under one explicit cost basis."""

    steps: int = 0
    elapsed_ms: int = 0
    cost_microunits: int = 0
    effect_attempts: int = 0
    cost_basis: str = field(kw_only=True)

    _QUANTITY_FIELDS = ("steps", "elapsed_ms", "cost_microunits", "effect_attempts")

    def __post_init__(self) -> None:
        """Reject ambiguous numeric inputs and missing cost context."""
        for name in self._QUANTITY_FIELDS:
            value = getattr(self, name)
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must be nonnegative")
        if not isinstance(self.cost_basis, str):
            raise TypeError("cost_basis must be a string")
        if not self.cost_basis.strip():
            raise ValueError("cost_basis must be nonblank")

    def to_dict(self) -> dict[str, int | str]:
        """Return the canonical mapping used by accounting records and digests."""
        return {
            "steps": self.steps,
            "elapsed_ms": self.elapsed_ms,
            "cost_microunits": self.cost_microunits,
            "effect_attempts": self.effect_attempts,
            "cost_basis": self.cost_basis,
        }

    def __add__(self, other: object) -> ChargeUnits:
        """Add each quantity, requiring an identical cost basis."""
        if not isinstance(other, ChargeUnits):
            return NotImplemented
        self._require_same_basis(other)
        return ChargeUnits(
            **{
                name: getattr(self, name) + getattr(other, name)
                for name in self._QUANTITY_FIELDS
            },
            cost_basis=self.cost_basis,
        )

    def __sub__(self, other: object) -> ChargeUnits:
        """Subtract each quantity without permitting any component to underflow."""
        if not isinstance(other, ChargeUnits):
            return NotImplemented
        self._require_same_basis(other)
        values = {
            name: getattr(self, name) - getattr(other, name)
            for name in self._QUANTITY_FIELDS
        }
        if any(value < 0 for value in values.values()):
            raise ValueError("charge subtraction underflow")
        return ChargeUnits(**values, cost_basis=self.cost_basis)

    def fits_within(self, limit: ChargeUnits) -> bool:
        """Return whether every quantity is at or below the matching-basis limit."""
        if not isinstance(limit, ChargeUnits):
            raise TypeError("limit must be ChargeUnits")
        self._require_same_basis(limit)
        return all(
            getattr(self, name) <= getattr(limit, name)
            for name in self._QUANTITY_FIELDS
        )

    def _require_same_basis(self, other: ChargeUnits) -> None:
        """Refuse arithmetic or comparison across different cost bases."""
        if self.cost_basis != other.cost_basis:
            raise ValueError("cost_basis must match")
