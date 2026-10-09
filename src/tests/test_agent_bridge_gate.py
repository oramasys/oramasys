"""The production path must refuse before importing or running a foreign agent."""
from __future__ import annotations

import builtins
from typing import Any

import pytest

from orama.compat.pydantic_ai_bridge import BridgeRefused, as_node


def test_default_refuses_before_agent_runs() -> None:
    """Phase 1 does not authorize real provider connections or tools."""
    with pytest.raises(BridgeRefused, match="production"):
        as_node(object(), prompt_from=lambda state: "prompt", deps_from=lambda state: None,
                output_key="output")


def test_broken_optional_import_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Installed-but-broken imports cannot fall back to guessed duck typing."""
    original = builtins.__import__
    def broken(name: str, *args: Any, **kwargs: Any) -> Any:
        """Inject a transitive failure rather than an absent framework root."""
        if name == "pydantic_ai":
            raise ModuleNotFoundError("broken transitive fixture", name="broken_transitive_fixture")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", broken)
    with pytest.raises(ModuleNotFoundError) as error:
        as_node(object(), prompt_from=lambda state: "prompt", deps_from=lambda state: None,
                output_key="output", offline_test=True)
    assert error.value.name == "broken_transitive_fixture"
