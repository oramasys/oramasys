"""CI must reject a unilateral edit to either cross-repository probe copy."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("changed", [None, "c2_interop_probe.py", "c2_slice2_probe.py"])
def test_peer_probe_changes_fail_the_workflow_check(tmp_path: Path, changed: str | None) -> None:
    """Run the same shell gate as CI against equal and independently mutated peer bytes."""
    peers = [tmp_path / "runtime", tmp_path / "probe"]
    for peer, name in zip(peers, ["c2_interop_probe.py", "c2_slice2_probe.py"], strict=True):
        target = peer / "src/tests/interop" / name
        target.parent.mkdir(parents=True)
        target.write_bytes((ROOT / "src/tests/interop" / name).read_bytes())
        if changed == name:
            target.write_bytes(target.read_bytes() + b"\n# unilateral change\n")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/check-permit-probe-parity.sh"), *map(str, peers)],
        capture_output=True, check=False,
    )
    assert (result.returncode == 0) == (changed is None)


def test_workflow_uses_an_immutable_separate_probe_source() -> None:
    """The lane compares both probes without changing the existing runtime issuer pin."""
    pin = (ROOT / "requirements/compatibility-phylax-slice2-probe.txt").read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{40}", pin)
    workflow = (ROOT / ".github/workflows/permit-interop.yml").read_text()
    assert "requirements/compatibility-phylax-slice2-probe.txt" in workflow
    assert "ref: ${{ steps.pin.outputs.probe_commit }}" in workflow
    assert "bash scripts/check-permit-probe-parity.sh phylax-pinned phylax-probe-pinned" in workflow
