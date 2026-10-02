"""Bounded, read-only Markdown search over a local docs tree.

No outbound I/O. Concurrency slots are threading-based so a timed-out scan
cannot release the slot while the worker is still running.
"""
from __future__ import annotations

import asyncio
import os
import re
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any

_MAX_DOC_BYTES = 512_000
_EXCERPT_CHARS = 280
_WORD = re.compile(r"[0-9a-z][0-9a-z_.-]*", re.IGNORECASE)
_TIMEOUT_DETAIL = "documentation search timed out; retry with a narrower query"
_BUSY_DETAIL = "documentation search busy; retry shortly"


class SearchUnavailable(Exception):
    """Timed out or saturated: HTTP → 503, JSON-RPC → -32000."""


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return max(0.5, float(raw))
    except ValueError:
        return default


def _max_files_scan() -> int:
    return _env_int("ORAMA_KNOWLEDGE_MAX_FILES_SCAN", 2000)


def _max_concurrent_searches() -> int:
    return _env_int("ORAMA_KNOWLEDGE_MAX_CONCURRENT_SEARCHES", 4)


def _search_timeout_s() -> float:
    return _env_float("ORAMA_KNOWLEDGE_SEARCH_TIMEOUT_S", 8.0)


_slots = threading.BoundedSemaphore(_max_concurrent_searches())


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _fold_align(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    origins: list[int] = []
    for index, char in enumerate(text):
        folded = "".join(
            piece
            for piece in unicodedata.normalize("NFKD", char)
            if not unicodedata.combining(piece)
        )
        for piece in folded:
            chars.append(piece)
            origins.append(index)
    return "".join(chars), origins


def _excerpt(text: str, terms: tuple[str, ...]) -> str:
    folded, origins = _fold_align(text)
    folded = folded.lower()
    starts = [folded.find(term) for term in terms]
    starts = [start for start in starts if start >= 0]
    if not starts or len(folded) != len(origins):
        return " ".join(text.split())[:_EXCERPT_CHARS]
    folded_at = min(starts)
    orig_at = origins[folded_at]
    half = _EXCERPT_CHARS // 2
    start = max(0, orig_at - half)
    end = min(len(text), start + _EXCERPT_CHARS)
    if end - start < _EXCERPT_CHARS:
        start = max(0, end - _EXCERPT_CHARS)
    snippet = " ".join(text[start:end].split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def docs_root() -> Path:
    configured = os.getenv("ORAMA_DOCS_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    # Repo checkout: src/orama/knowledge/search.py → parents[3] is the root.
    # Installed wheels do not ship docs/; set ORAMA_DOCS_ROOT there.
    return Path(__file__).resolve().parents[3] / "docs"


def search_docs(
    query: str, limit: int = 8, deadline: float | None = None
) -> list[dict[str, Any]]:
    terms = tuple(dict.fromkeys(word.lower() for word in _WORD.findall(_fold(query))))
    if not terms:
        return []
    root = docs_root()
    if not root.is_dir():
        return []
    hits: list[tuple[int, dict[str, Any]]] = []
    scanned = 0
    for path in root.rglob("*.md"):
        if deadline is not None and time.monotonic() >= deadline:
            break
        scanned += 1
        if scanned > _max_files_scan():
            break
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
            if not resolved.is_file() or resolved.stat().st_size > _MAX_DOC_BYTES:
                continue
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        folded = _fold(text).lower()
        title = next(
            (line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")),
            path.stem,
        )
        title_lower = _fold(title).lower()
        score = sum(folded.count(term) + (5 if term in title_lower else 0) for term in terms)
        if not score:
            continue
        hits.append(
            (
                score,
                {
                    "title": title,
                    "path": resolved.relative_to(root).as_posix(),
                    "excerpt": _excerpt(text, terms),
                    "score": score,
                },
            )
        )
    hits.sort(key=lambda item: (-item[0], item[1]["path"]))
    return [hit for _, hit in hits[:limit]]


def _release_when_done(fut: asyncio.Future, slot: threading.BoundedSemaphore) -> None:
    slot.release()
    if not fut.cancelled():
        fut.exception()


async def bounded_search(query: str, limit: int = 8) -> list[dict[str, Any]]:
    slot = _slots
    if not slot.acquire(blocking=False):
        raise SearchUnavailable(_BUSY_DETAIL)
    timeout = _search_timeout_s()
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(
        None, search_docs, query, limit, time.monotonic() + timeout
    )
    fut.add_done_callback(lambda f: _release_when_done(f, slot))
    try:
        return await asyncio.wait_for(asyncio.shield(fut), timeout)
    except TimeoutError:
        raise SearchUnavailable(_TIMEOUT_DETAIL) from None
