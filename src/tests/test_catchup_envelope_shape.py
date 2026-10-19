"""Maker-added cases for the catch-up envelope validator (complements the reviewer-drafted file)."""
from __future__ import annotations

import pytest

from orama.graph.catchup_envelope import CatchupRefused, validate_catchup


def refused(envelope: object, **kwargs: int) -> str:
    with pytest.raises(CatchupRefused) as excinfo:
        validate_catchup(envelope, **kwargs)
    return excinfo.value.reason


def test_a_contiguous_envelope_that_stops_short_of_through_version_is_a_gap() -> None:
    envelope = {"from_version": 11, "through_version": 13, "events": [{"version": 11}, {"version": 12}]}
    assert refused(envelope, requested_acked_through=10, r_f=13) == "catchup_gap"


@pytest.mark.parametrize("event", [None, "event", 7, ["version"], {}, {"version": "11"}, {"version": True}])
def test_an_event_without_an_integer_version_is_malformed(event: object) -> None:
    envelope = {"from_version": 11, "through_version": 11, "events": [event]}
    assert refused(envelope, requested_acked_through=10, r_f=11) == "catchup_malformed"


def test_a_non_mapping_envelope_is_malformed() -> None:
    for envelope in (None, [], "envelope", 3):
        assert refused(envelope, requested_acked_through=0, r_f=0) == "catchup_malformed"


def test_the_bound_is_a_parameter_and_boundary_exact() -> None:
    events = [{"version": 1}, {"version": 2}]
    envelope = {"from_version": 1, "through_version": 2, "events": events}
    assert validate_catchup(envelope, requested_acked_through=0, r_f=2, max_events=2) is events
    assert refused(envelope, requested_acked_through=0, r_f=2, max_events=1) == "catchup_too_large"


def test_validation_returns_the_same_list_object_and_changes_nothing() -> None:
    events = [{"version": 5}]
    envelope = {"from_version": 5, "through_version": 5, "events": events}
    assert validate_catchup(envelope, requested_acked_through=4, r_f=5) is events
    assert envelope == {"from_version": 5, "through_version": 5, "events": [{"version": 5}]}
