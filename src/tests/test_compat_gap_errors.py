"""Feature detection and import-gap reporting have distinct Python contracts."""
from __future__ import annotations

import importlib
import importlib.abc
import sys
import types

import pytest

from orama.compat.errors import CompatGapAttributeError, CompatGapModuleError, explain, unsupported_symbol


def test_module_gap_is_skipped_but_explicitly_detectable(monkeypatch: pytest.MonkeyPatch) -> None:
    """importorskip skips a missing module; conformance must assert the gap directly."""
    class Blocker(importlib.abc.MetaPathFinder):
        """Claim a known unsupported namespace, rather than allowing real fallback."""
        def find_spec(self, fullname: str, path: object = None, target: object = None) -> object:
            """Raise the informative missing-module subclass only for this test row."""
            if fullname == "compat_missing_fixture":
                raise CompatGapModuleError(fullname, "G18")
            return None
    monkeypatch.setattr(sys, "meta_path", [Blocker(), *sys.meta_path])
    with pytest.raises(CompatGapModuleError) as error:
        importlib.import_module("compat_missing_fixture")
    assert error.value.name == "compat_missing_fixture"
    assert error.value.matrix_row == "G18"
    assert isinstance(error.value, ImportError)
    with pytest.raises(pytest.skip.Exception):
        pytest.importorskip("compat_missing_fixture")


def test_symbol_feature_detection_and_from_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """AttributeError preserves feature detection; explicit explain keeps the lost reason."""
    module = types.ModuleType("compat_symbol_fixture")
    module.__getattr__ = lambda name: unsupported_symbol(module.__name__, name, "G18")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    assert not hasattr(module, "Unsupported")
    assert getattr(module, "Unsupported", "default") == "default"
    with pytest.raises(CompatGapAttributeError) as error:
        module.Unsupported
    assert error.value.matrix_row == "G18"
    with pytest.raises(AttributeError) as dunder:
        module.__path__
    assert type(dunder.value) is AttributeError
    with pytest.raises(ImportError):
        exec("from compat_symbol_fixture import Unsupported")
    assert explain("G18")["id"] == "G18"
    assert explain("langgraph.pregel")["status"] == "unsupported"
    assert explain("fixture.Unsupported", matrix_row=error.value.matrix_row)["id"] == "G18"
    with pytest.raises(KeyError):
        explain("unknown.Target")


def test_finder_returning_none_can_fall_through(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Returning None does not claim absence; the later installed finder still wins."""
    attempts = []
    (tmp_path / "compat_installed_fixture.py").write_text("VALUE = 42\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    class Finder(importlib.abc.MetaPathFinder):
        """A diagnostic-only finder cannot implement an unsupported-module gate."""
        def find_spec(self, fullname: str, path: object = None, target: object = None) -> None:
            """Decline ownership to let Python consult the remaining finders."""
            attempts.append(fullname)
            return None
    monkeypatch.setattr(sys, "meta_path", [Finder(), *sys.meta_path])
    try:
        assert importlib.import_module("compat_installed_fixture").VALUE == 42
        assert "compat_installed_fixture" in attempts
    finally:
        sys.modules.pop("compat_installed_fixture", None)


def test_gap_errors_survive_pickling() -> None:
    """Gap diagnostics must cross process boundaries (workers, log shipping) intact."""
    import pickle
    from orama.compat.errors import CompatGapAttributeError, CompatGapModuleError

    for error in (CompatGapModuleError("langgraph.pregel", "G18"),
                  CompatGapAttributeError("langgraph.types.Send", "G18")):
        copy = pickle.loads(pickle.dumps(error))
        assert type(copy) is type(error)
        assert copy.matrix_row == "G18" and str(copy) == str(error)
    assert pickle.loads(pickle.dumps(CompatGapModuleError("langgraph.pregel", "G18"))).name == "langgraph.pregel"
