"""A proposed digest is useful evidence but cannot confer operator acceptance."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def helper():
    spec = importlib.util.spec_from_file_location("qualification_freeze", ROOT / "scripts/qualification_freeze.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_proposal_never_claims_approval() -> None:
    proposal = helper().proposal({"schema": 3}, {"packet_version": 1}, "a" * 40)
    assert proposal["status"] == "proposed"
    assert proposal["approval_ref"] is None
    with pytest.raises(ValueError, match="approved"):
        helper().verify(proposal, {"schema": 3}, {"packet_version": 1}, "a" * 40)


def test_approved_record_binds_both_inputs_and_consumer() -> None:
    manifest, coverage = {"schema": 3}, {"packet_version": 1}
    record = helper().proposal(manifest, coverage, "a" * 40)
    record.update(status="approved", approval_ref="operator-decision:synthetic-approval")
    helper().verify(record, manifest, coverage, "a" * 40)
    for m, p, c in [({"schema": 2}, coverage, "a" * 40),
                    (manifest, {"packet_version": 2}, "a" * 40),
                    (manifest, coverage, "b" * 40)]:
        with pytest.raises(ValueError):
            helper().verify(record, m, p, c)


@pytest.mark.parametrize("approval", [None, "", "   "])
def test_blank_approval_ref_is_rejected(approval: str | None) -> None:
    record = helper().proposal({}, {}, "a" * 40)
    record.update(status="approved", approval_ref=approval)
    with pytest.raises(ValueError):
        helper().verify(record, {}, {}, "a" * 40)
