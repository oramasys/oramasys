"""Real process death on either side of the retry-token commit boundary."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from .support import admitted, declare, open_store, request


_CHILD = r'''
import os, sys
from pathlib import Path
from tests.orchestrator_controller.support import admitted, open_store, request
store = open_store(Path(sys.argv[1]))
if sys.argv[2] == 'before':
    def trace(sql):
        if sql == 'RELEASE transition':
            os._exit(71)
    store._db.set_trace_callback(trace)
store.apply_admitted(request(), admitted())
os._exit(72)
'''


@pytest.mark.parametrize('boundary', ['before', 'after'])
def test_retry_process_death_preserves_commit_boundary(tmp_path: Path, boundary: str) -> None:
    """SQLite rolls back an uncommitted retry and retains a committed consumption after process death."""
    store = open_store(tmp_path)
    declare(store)
    original = store.apply_admitted(request(), admitted())
    store.close()
    child = subprocess.run([sys.executable, '-c', _CHILD, str(tmp_path), boundary], check=False)
    assert child.returncode == (71 if boundary == 'before' else 72)
    store = open_store(tmp_path)
    retry = store.apply_admitted(request(), admitted())
    assert retry.lease_token == (original.lease_token if boundary == 'before' else None)
    assert store.apply_admitted(request(), admitted()).lease_token is None
    store.close()
