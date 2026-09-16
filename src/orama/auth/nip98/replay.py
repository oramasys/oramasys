"""In-process NIP-98 event-id replay cache."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict


class ReplayCache:
    """Remember event ids until their skew window ends; reject duplicates."""

    def __init__(self, max_size: int = 4096, ttl_sec: float = 120.0) -> None:
        self._max_size = max(1, max_size)
        self._ttl_sec = max(1.0, ttl_sec)
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def seen(self, event_id: str, *, now: float | None = None) -> bool:
        """Return True if event_id was already recorded (replay)."""
        ts = time.time() if now is None else now
        with self._lock:
            self._purge(ts)
            return event_id in self._entries

    def remember(self, event_id: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        with self._lock:
            self._admit_locked(event_id, now=ts, expires_at=ts + self._ttl_sec)

    def admit(
        self,
        event_id: str,
        *,
        now: float | None = None,
        expires_at: float | None = None,
    ) -> bool:
        """Purge, reject replay, or record in one lock. True if newly stored."""
        ts = time.time() if now is None else now
        expiry = (ts + self._ttl_sec) if expires_at is None else expires_at
        with self._lock:
            return self._admit_locked(event_id, now=ts, expires_at=expiry)

    def _admit_locked(self, event_id: str, *, now: float, expires_at: float) -> bool:
        self._purge(now)
        if event_id in self._entries:
            return False
        self._entries[event_id] = expires_at
        while len(self._entries) > self._max_size:
            self._entries.popitem(last=False)
        return True

    def _purge(self, now: float) -> None:
        while self._entries:
            _eid, expires_at = next(iter(self._entries.items()))
            if expires_at >= now:
                break
            self._entries.popitem(last=False)
