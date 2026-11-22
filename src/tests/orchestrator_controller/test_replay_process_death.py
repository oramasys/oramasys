"""Real process death on either side of the retry-token commit boundary."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import orama

from .support import admitted, declare, open_store, request


def _child_environment(env: dict[str, str]) -> dict[str, str]:
    """Prepend the parent package root while preserving the complete environment."""
    result = env.copy()
    root = str(Path(orama.__file__).resolve().parent.parent)
    inherited = env.get("PYTHONPATH")
    result["PYTHONPATH"] = os.pathsep.join((root, inherited)) if inherited else root
    return result


_CHILD = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from support import admitted, open_store, request
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
    child = subprocess.run(
        [sys.executable, '-c', _CHILD, str(tmp_path), boundary, str(Path(__file__).resolve().parent)],
        cwd=tmp_path, env=_child_environment(os.environ), capture_output=True, text=True, check=False,
    )
    assert child.returncode == (71 if boundary == 'before' else 72), child.stderr
    store = open_store(tmp_path)
    retry = store.apply_admitted(request(), admitted())
    assert retry.lease_token == (original.lease_token if boundary == 'before' else None)
    assert store.apply_admitted(request(), admitted()).lease_token is None
    store.close()


def test_child_imports_parent_package_with_contaminated_pythonpath(tmp_path: Path) -> None:
    """A child must import the exact parent package even when another copy is first in the environment."""
    import os
    import orama
    fake = tmp_path / 'fake' / 'orama'
    fake.mkdir(parents=True)
    (fake / '__init__.py').write_text('')
    env = {**os.environ, 'PYTHONPATH': str(fake.parent), 'SYSTEMROOT': 'preserved'}
    child = subprocess.run(
        [sys.executable, '-c', 'import orama, os; print(orama.__file__); print(os.environ["SYSTEMROOT"])'],
        cwd=tmp_path, env=_child_environment(env), capture_output=True, text=True, check=True,
    )
    assert Path(child.stdout.splitlines()[0]).resolve() == Path(orama.__file__).resolve()
    assert child.stdout.splitlines()[1] == 'preserved'
