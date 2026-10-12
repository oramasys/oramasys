"""Strict value semantics for multi-unit accounting charges."""
from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from orama.graph.accounting_types import ChargeUnits


def test_charge_units_requires_an_explicit_cost_basis() -> None:
    with pytest.raises(TypeError):
        ChargeUnits()  # type: ignore[call-arg]

    assert ChargeUnits(cost_basis="usd_microunits") == ChargeUnits(
        steps=0,
        elapsed_ms=0,
        cost_microunits=0,
        effect_attempts=0,
        cost_basis="usd_microunits",
    )


@pytest.mark.parametrize("cost_basis", ["", " ", "\t\n", 1, None])
def test_charge_units_rejects_invalid_cost_basis(cost_basis: object) -> None:
    with pytest.raises((TypeError, ValueError), match="cost_basis"):
        ChargeUnits(cost_basis=cost_basis)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["steps", "elapsed_ms", "cost_microunits", "effect_attempts"])
@pytest.mark.parametrize("value", [True, False, 1.0, -1])
def test_charge_units_rejects_non_strict_nonnegative_integers(field: str, value: object) -> None:
    values = {
        "steps": 0,
        "elapsed_ms": 0,
        "cost_microunits": 0,
        "effect_attempts": 0,
        field: value,
    }

    with pytest.raises((TypeError, ValueError), match=field):
        ChargeUnits(**values, cost_basis="usd_microunits")  # type: ignore[arg-type]


def test_charge_units_is_immutable_and_slotted() -> None:
    charge = ChargeUnits(steps=1, cost_basis="usd_microunits")

    with pytest.raises(FrozenInstanceError):
        charge.steps = 2  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        charge.extra = 1  # type: ignore[attr-defined]


def test_charge_units_has_a_canonical_dict() -> None:
    charge = ChargeUnits(
        steps=1,
        elapsed_ms=2,
        cost_microunits=3,
        effect_attempts=4,
        cost_basis="usd_microunits",
    )

    assert charge.to_dict() == {
        "steps": 1,
        "elapsed_ms": 2,
        "cost_microunits": 3,
        "effect_attempts": 4,
        "cost_basis": "usd_microunits",
    }


def test_charge_units_adds_and_subtracts_componentwise() -> None:
    left = ChargeUnits(1, 20, 300, 4, cost_basis="usd_microunits")
    right = ChargeUnits(5, 60, 700, 8, cost_basis="usd_microunits")

    total = left + right

    assert total == ChargeUnits(6, 80, 1000, 12, cost_basis="usd_microunits")
    assert total - left == right


@pytest.mark.parametrize("operator", ["add", "subtract"])
def test_charge_units_rejects_arithmetic_across_cost_bases(operator: str) -> None:
    usd = ChargeUnits(cost_basis="usd_microunits")
    tokens = ChargeUnits(cost_basis="token_microunits")

    with pytest.raises(ValueError, match="cost_basis"):
        _ = usd + tokens if operator == "add" else usd - tokens


def test_charge_units_subtraction_rejects_component_underflow() -> None:
    smaller = ChargeUnits(steps=1, elapsed_ms=10, cost_basis="usd_microunits")
    larger = ChargeUnits(steps=2, elapsed_ms=10, cost_basis="usd_microunits")

    with pytest.raises(ValueError, match="underflow"):
        _ = smaller - larger


def test_charge_units_checks_componentwise_limits() -> None:
    limit = ChargeUnits(steps=2, elapsed_ms=20, cost_microunits=30, effect_attempts=4, cost_basis="usd")

    assert ChargeUnits(2, 19, 30, 0, cost_basis="usd").fits_within(limit) is True
    assert ChargeUnits(2, 21, 30, 0, cost_basis="usd").fits_within(limit) is False
    with pytest.raises(ValueError, match="cost_basis"):
        ChargeUnits(cost_basis="tokens").fits_within(limit)
