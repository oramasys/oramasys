"""Unit tests for catch-up envelope validator (orama.graph.catchup_envelope).

Contract:
- MAX_CATCHUP_EVENTS = 64
- validate_catchup(envelope, *, requested_acked_through: int, r_f: int, max_events: int = 64) -> list[dict]
- Raises CatchupRefused(reason) in order:
  1. catchup_malformed: missing keys, extra keys, non-int (bool excluded) versions, non-list events
  2. catchup_too_large: len(events) > max_events
  3. catchup_range: from_version != acked_through + 1 or through_version != r_f or from_version > through_version;
     empty events valid only when acked_through == r_f and from_version == r_f + 1 and through_version == r_f
  4. catchup_gap: event[i].version != from_version + i or last event version != through_version
- Returns events list unchanged.
"""

from __future__ import annotations

import pytest

from orama.graph.catchup_envelope import (
    MAX_CATCHUP_EVENTS,
    CatchupRefused,
    validate_catchup,
)


def test_max_catchup_events_constant() -> None:
    """MAX_CATCHUP_EVENTS constant is exactly 64."""
    assert MAX_CATCHUP_EVENTS == 64


def test_catchup_refused_exception_has_reason() -> None:
    """CatchupRefused exposes the reason passed at instantiation."""
    err = CatchupRefused("catchup_malformed")
    assert err.reason == "catchup_malformed"
    assert str(err) == "catchup_malformed"


def test_valid_non_empty_catchup_envelope() -> None:
    """Valid non-empty envelope returns events list unchanged."""
    events = [
        {"version": 11, "type": "revocation"},
        {"version": 12, "type": "revocation"},
        {"version": 13, "type": "finalization"},
    ]
    envelope = {
        "from_version": 11,
        "through_version": 13,
        "events": events,
    }
    result = validate_catchup(envelope, requested_acked_through=10, r_f=13)
    assert result is events
    assert result == [
        {"version": 11, "type": "revocation"},
        {"version": 12, "type": "revocation"},
        {"version": 13, "type": "finalization"},
    ]


def test_valid_empty_catchup_envelope_when_up_to_date() -> None:
    """Empty events list is valid only when consumer acked_through equals r_f."""
    envelope = {
        "from_version": 11,
        "through_version": 10,
        "events": [],
    }
    result = validate_catchup(envelope, requested_acked_through=10, r_f=10)
    assert result == []


@pytest.mark.parametrize(
    "malformed_envelope",
    [
        {"from_version": 1, "through_version": 1},  # missing events
        {"from_version": 1, "events": []},  # missing through_version
        {"through_version": 1, "events": []},  # missing from_version
        {"from_version": 1, "through_version": 1, "events": [], "extra": "field"},  # extra key
        {"from_version": "1", "through_version": 1, "events": []},  # str from_version
        {"from_version": 1, "through_version": "1", "events": []},  # str through_version
        {"from_version": True, "through_version": 1, "events": []},  # bool from_version (bool is int subclass)
        {"from_version": 1, "through_version": False, "events": []},  # bool through_version
        {"from_version": 1.0, "through_version": 1, "events": []},  # float from_version
        {"from_version": 1, "through_version": 1.0, "events": []},  # float through_version
        {"from_version": None, "through_version": 1, "events": []},  # None from_version
        {"from_version": 1, "through_version": None, "events": []},  # None through_version
        {"from_version": 1, "through_version": 1, "events": None},  # non-list events
        {"from_version": 1, "through_version": 1, "events": "events"},  # str events
        {"from_version": 1, "through_version": 1, "events": ({"version": 1},)},  # tuple events
    ],
)
def test_catchup_malformed_rejected(malformed_envelope: object) -> None:
    """Envelope with missing, extra, non-int or non-list keys raises catchup_malformed."""
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(malformed_envelope, requested_acked_through=0, r_f=1)  # type: ignore[arg-type]
    assert exc_info.value.reason == "catchup_malformed"


def test_catchup_size_boundary_64_vs_65() -> None:
    """Boundary test: exactly 64 events passes, 65 events raises catchup_too_large."""
    events_64 = [{"version": 10 + i} for i in range(1, 65)]
    env_64 = {
        "from_version": 11,
        "through_version": 74,
        "events": events_64,
    }
    assert validate_catchup(env_64, requested_acked_through=10, r_f=74) == events_64

    events_65 = [{"version": 10 + i} for i in range(1, 66)]
    env_65 = {
        "from_version": 11,
        "through_version": 75,
        "events": events_65,
    }
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(env_65, requested_acked_through=10, r_f=75)
    assert exc_info.value.reason == "catchup_too_large"


@pytest.mark.parametrize(
    ("from_v", "through_v", "acked", "r_f", "events"),
    [
        (10, 12, 10, 12, [{"version": 10}, {"version": 11}, {"version": 12}]),  # from != acked + 1
        (12, 13, 10, 13, [{"version": 12}, {"version": 13}]),  # from != acked + 1 (gap at start)
        (11, 14, 10, 13, [{"version": 11}, {"version": 12}, {"version": 13}, {"version": 14}]),  # through != r_f
        (11, 12, 10, 13, [{"version": 11}, {"version": 12}]),  # through != r_f (truncated)
        (15, 14, 10, 14, [{"version": 15}]),  # from_version > through_version
        # empty events invalid combinations:
        (11, 10, 9, 10, []),  # acked != r_f
        (10, 10, 10, 10, []),  # from_version != r_f + 1
        (11, 11, 10, 10, []),  # through_version != r_f
    ],
)
def test_catchup_range_mismatches_refused(
    from_v: int, through_v: int, acked: int, r_f: int, events: list[dict]
) -> None:
    """Envelope range mismatch against requested_acked_through and r_f raises catchup_range."""
    envelope = {
        "from_version": from_v,
        "through_version": through_v,
        "events": events,
    }
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(envelope, requested_acked_through=acked, r_f=r_f)
    assert exc_info.value.reason == "catchup_range"


@pytest.mark.parametrize(
    "events_with_gap",
    [
        [{"version": 11}, {"version": 13}],  # missing version 12
        [{"version": 11}, {"version": 11}, {"version": 12}],  # duplicate version 11
        [{"version": 12}, {"version": 13}],  # starts with wrong version
        [{"version": 11}, {"version": 12}, {"version": 12}],  # last version != through_version
    ],
)
def test_catchup_gap_refused(events_with_gap: list[dict]) -> None:
    """Events list with non-contiguous versions raises catchup_gap."""
    envelope = {
        "from_version": 11,
        "through_version": 13,
        "events": events_with_gap,
    }
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(envelope, requested_acked_through=10, r_f=13)
    assert exc_info.value.reason == "catchup_gap"


def test_precedence_malformed_beats_too_large() -> None:
    """Precedence 1 (catchup_malformed) takes priority over Precedence 2 (catchup_too_large)."""
    envelope = {
        "from_version": "invalid_type",
        "through_version": 100,
        "events": [{"version": i} for i in range(100)],
    }
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(envelope, requested_acked_through=0, r_f=100)
    assert exc_info.value.reason == "catchup_malformed"


def test_precedence_too_large_beats_range() -> None:
    """Precedence 2 (catchup_too_large) takes priority over Precedence 3 (catchup_range)."""
    envelope = {
        "from_version": 999,  # invalid range
        "through_version": 888,
        "events": [{"version": i} for i in range(70)],  # > 64 events
    }
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(envelope, requested_acked_through=10, r_f=50)
    assert exc_info.value.reason == "catchup_too_large"


def test_precedence_range_beats_gap() -> None:
    """Precedence 3 (catchup_range) takes priority over Precedence 4 (catchup_gap)."""
    envelope = {
        "from_version": 20,  # wrong range (acked=10 -> expected from=11)
        "through_version": 25,
        "events": [{"version": 20}, {"version": 25}],  # also has a gap
    }
    with pytest.raises(CatchupRefused) as exc_info:
        validate_catchup(envelope, requested_acked_through=10, r_f=25)
    assert exc_info.value.reason == "catchup_range"
