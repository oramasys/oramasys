"""M1 generation 1 stays reproducible after the generation-2 promotion.

The archived inputs under ``requirements/history/m1-gen1/`` are the exact bytes that the
operator approved (PR 45 comment 6217460696) and that run 38916773943 qualified. They are
checked against their own frozen identities: a literal pin table, the generation-1 registry
ref and consumer. Nothing here is derived from the active generation or from the file under
test, so a promotion can neither rewrite this evidence nor make these checks vacuous.
"""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from orama.compat.manifest import ManifestError, canonical_digest, validate_manifest
from tests.active_pins import HISTORY, M1_GEN1_CORE_PINS, frozen_lane_files
from tests.test_compatibility_manifest_schema2_equivalence import CASES

GEN1_REGISTRY_REF = "65ec365293c6a892cd4f978e656cfb61c0d04b9a"
GEN1_CONSUMER = "f8898b35d5249e483b2f4a68c097957e675a0ef4"
GEN1_MANIFEST_DIGEST = "4892b6ba9894eee0e85deae3dcbb020a82f3afb55fadc7424f2a3cfa2dd6bae2"
GEN1_COVERAGE_DIGEST = "6af7fa7a02fa6fca3b34ec0eff06a7e281c9b3f92d8de3bbdd4d325f8656b326"
ARCHIVE_BYTES = {
    "compatibility-manifest.v3.json":
        "b5cece0ef5982c4bb241284cccdbd323a60cdc3dbea37e9992ed1f195fc80a6b",
    "qualification-coverage-packet.v1.json":
        "db10291db6e2fcb19289099fc7913407e2d38c6a3cd93a4fcbb9056d10e15ffe",
    "final-producers-install-plan.v1.json":
        "e5ecd7b93a0478256d57ed6f9c21574ac7b74a37b2e6a4fa0c07dae5ff6dbaff",
}


def _load(name: str) -> dict:
    return json.loads((HISTORY / name).read_text(encoding="utf-8"))


def _check_gen1(manifest: dict, **kw) -> None:
    validate_manifest(manifest, core_pins=M1_GEN1_CORE_PINS, lane_files=frozen_lane_files(),
                      producer_ref=GEN1_REGISTRY_REF, **kw)


@pytest.mark.parametrize("name", sorted(ARCHIVE_BYTES))
def test_archived_file_keeps_its_exact_bytes(name: str) -> None:
    """Archives are evidence, not JSON eligible for reformatting."""
    assert hashlib.sha256((HISTORY / name).read_bytes()).hexdigest() == ARCHIVE_BYTES[name]


def test_archived_digests_are_the_approved_freeze_digests() -> None:
    assert canonical_digest(_load("compatibility-manifest.v3.json")) == GEN1_MANIFEST_DIGEST
    assert canonical_digest(_load("qualification-coverage-packet.v1.json")) == GEN1_COVERAGE_DIGEST


def test_archived_v3_validates_against_its_own_generation() -> None:
    _check_gen1(_load("compatibility-manifest.v3.json"), expected_schema=3,
                expected_digest=GEN1_MANIFEST_DIGEST, consumer_sha=GEN1_CONSUMER)


def test_archived_v3_is_refused_against_the_active_lanes() -> None:
    """Generation-1 data cannot pass as the active generation."""
    from tests.active_pins import ACTIVE_PINS, live_lane_files

    with pytest.raises(ManifestError):
        validate_manifest(_load("compatibility-manifest.v3.json"), core_pins=ACTIVE_PINS,
                          lane_files=live_lane_files(), producer_ref=GEN1_REGISTRY_REF)


def test_archived_install_plan_names_the_generation_one_consumer() -> None:
    assert _load("final-producers-install-plan.v1.json")["consumer"]["commit"] == GEN1_CONSUMER


def test_archived_schema2_validates_and_equals_the_v3_historical_cells() -> None:
    v2 = _load("compatibility-manifest.json")
    _check_gen1(v2)
    v3_cells = [c for c in _load("compatibility-manifest.v3.json")["cells"]
                if c["profile"] != "final-producers"]
    key = lambda c: (c["profile"], c["python"])  # noqa: E731 - local sort key
    assert sorted(v3_cells, key=key) == sorted(v2["cells"], key=key)


@pytest.mark.parametrize("name", sorted(CASES))
def test_schema2_equivalence_holds_on_the_generation_one_bundle(name: str) -> None:
    """The recorded original outcomes still hold on generation 1's own pins and lanes."""
    mutate, message = CASES[name]
    manifest = copy.deepcopy(_load("compatibility-manifest.json"))
    mutate(manifest)
    try:
        _check_gen1(manifest)
        outcome = None
    except Exception as error:  # noqa: BLE001 - the exact type is part of the comparison
        outcome = (type(error).__name__, str(error))
    assert outcome == (None if message is None else ("ManifestError", message))
