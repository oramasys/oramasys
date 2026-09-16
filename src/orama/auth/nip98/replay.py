"""In-process NIP-98 event-id replay cache."""
from __future__ import annotations

import time
from collections import OrderedDict


class ReplayCache:
    """Remember event ids for the skew window; reject duplicates."""

    def __init__(self, max_size: int = 4096, ttl_sec: float = 60.0) -> None:
        self._max_size = max(1, max_size)
        self._ttl_sec = max(1.0, ttl_sec)
        self._entries: OrderedDict[str, float] = OrderedDict()

    def seen(self, event_id: str, *, now: float | None = None) -> bool:
        """Return True if event_id was already recorded (replay)."""
        ts = time.time() if now is None else now
        self._purge(ts)
        return event_id in self._entries

    def remember(self, event_id: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        self._purge(ts)
        if event_id in self._entries:
            self._entries.move_to_end(event_id)
            self._entries[event_id] = ts
            return
        self._entries[event_id] = ts
        while len(self._entries) > self._max_size:
            self._entries.popitem(last=False)

    def _purge(self, now: float) -> None:
        cutoff = now - self._ttl_sec
        while self._entries:
            _eid, seen_at = next(iter(self._entries.items()))
            if seen_at >= cutoff:
                break
            self._entries.popitem(last=False)
