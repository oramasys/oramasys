"""Tiered Python-native absence errors, without deceptive supported stubs."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

_ROWS = MappingProxyType({"G18": MappingProxyType({
    "id": "G18", "status": "unsupported", "reason": "Compatibility surface not implemented",
    "reference": "docs/v2/references/loop-graph-compatibility-2026-10-09/EXECUTION-REVISION-4.md",
})})


_TARGET_ROWS = MappingProxyType({"langgraph.pregel": "G18"})


def explain(target: str, *, matrix_row: str | None = None) -> Mapping[str, str]:
    """Explain a known replacement target, row, or explicit gap diagnostic.

    Unknown targets raise KeyError. This describes our replacement coverage,
    not the installed upstream package; no import interception is activated.
    """
    row = matrix_row if matrix_row is not None else _TARGET_ROWS.get(target, target)
    return _ROWS[row]


class CompatGapModuleError(ModuleNotFoundError):
    """Claim an explicitly unsupported module; compatible with importorskip."""
    def __init__(self, fullname: str, matrix_row: str) -> None:
        """Bind Python's missing-module name and the durable matrix row."""
        explain(matrix_row)
        self.matrix_row = matrix_row
        super().__init__(f"Unsupported module {fullname!r}; compatibility row {matrix_row}", name=fullname)


class CompatGapAttributeError(AttributeError):
    """Report a symbol gap while preserving hasattr/getattr(default) semantics."""
    def __init__(self, fullname: str, matrix_row: str) -> None:
        """Carry the diagnostic for direct access; from-import may replace it."""
        explain(matrix_row)
        self.matrix_row = matrix_row
        super().__init__(f"Unsupported symbol {fullname!r}; compatibility row {matrix_row}")


def unsupported_symbol(module: str, symbol: str, matrix_row: str) -> None:
    """A facade's __getattr__ hook must not claim dunders or export false support."""
    if symbol.startswith("__") and symbol.endswith("__"):
        raise AttributeError(symbol)
    raise CompatGapAttributeError(f"{module}.{symbol}", matrix_row)
