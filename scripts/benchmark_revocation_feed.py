"""Measure signed-feed lookup latency and contention without enabling serving.

Run with the consumer and the chosen Phylax source on PYTHONPATH. All stores
and synthetic signing material live in a temporary directory. Results are
observations on this host, never a deployment qualification or an SLO.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from nacl.bindings import crypto_sign_seed_keypair
from orama.graph.dispatch_attempts import SqliteAttemptStore
from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import SqliteDispatchPermitStore
from phylax.dispatch_retention import RetainedEventFeed, RetentionLedger
from phylax.revocation_publication import build_state, sign_state_body
from revocation_feed_adapter import RevocationFeedAdapter, RevocationUnavailable


class SyntheticSigner:
    """Generate disposable, explicitly synthetic benchmark signatures."""

    def __init__(self) -> None:
        """Use a public test seed that carries no deployment authority."""
        self.seed = b"B" * 32

    def active_key_id(self) -> str:
        """Name this benchmark's disposable key."""
        return "benchmark-key"

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign the synthetic event domain."""
        return wire.sign_event(self.seed, digest)

    def sign_state(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign the synthetic state domain."""
        return sign_state_body(self.seed, body)


def measure(events: int, workers: int, lookups: int) -> dict[str, Any]:
    """Build a real signed feed, then time concurrent reads of its dedicated cache."""
    with tempfile.TemporaryDirectory(prefix="orama-revocation-benchmark-") as directory:
        root = Path(directory)
        signer = SyntheticSigner()
        public = crypto_sign_seed_keypair(signer.seed)[0]
        producer = SqliteDispatchPermitStore(root / "producer.db")
        feed = RetainedEventFeed(producer, RetentionLedger(root / "retention.db"))
        for index in range(events):
            producer.append_revocation("grant", f"synthetic-{index}", signer=signer)
        now = datetime.now(UTC)
        state = build_state(feed, issuer_id="benchmark", head_version=events, signer=signer, now=now)
        chain = feed.events(1, events) if events else []
        store = SqliteAttemptStore(root / "attempts.db")
        try:
            adapter = RevocationFeedAdapter(
                root / "cache.db", store=store, issuer_id="benchmark",
                public_key_for=lambda issuer, key: public if (issuer, key) == ("benchmark", "benchmark-key") else None,
                clock=lambda: datetime.now(UTC), approval_ref_for=lambda *_: "",
            )
            started = time.perf_counter()
            adapter.refresh(state, chain)
            refresh_seconds = time.perf_counter() - started

            def lookup(index: int) -> tuple[float, str]:
                """Measure one unrevoked query, counting every fail-closed denial."""
                started = time.perf_counter()
                try:
                    outcome = "allowed" if adapter.revoked("unlisted", "benchmark") is False else "revoked"
                except RevocationUnavailable:
                    outcome = "unavailable"
                return time.perf_counter() - started, outcome

            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(lookup, range(lookups)))
            elapsed = time.perf_counter() - started
            durations = sorted(duration for duration, _ in results)
            return {
                "events": events, "workers": workers, "lookups": lookups,
                "refresh_seconds": refresh_seconds, "elapsed_seconds": elapsed,
                "median_seconds": statistics.median(durations),
                "p95_seconds": durations[min(len(durations) - 1, int(len(durations) * .95))],
                "outcomes": {name: sum(outcome == name for _, outcome in results)
                             for name in ("allowed", "revoked", "unavailable")},
            }
        finally:
            store.close()


def main() -> None:
    """Print machine-readable observations for the requested bounded workload."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, nargs="+", default=[0, 256, 4096])
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--lookups", type=int, default=16)
    args = parser.parse_args()
    if any(not 0 <= value <= 4096 for value in args.events) or any(not 1 <= value <= 64 for value in args.workers) or not 1 <= args.lookups <= 10000:
        parser.error("events must be 0..4096, workers 1..64, and lookups 1..10000")
    print(json.dumps({"python": platform.python_version(), "platform": platform.system(),
                      "results": [measure(events, workers, args.lookups)
                                  for events in args.events for workers in args.workers]}, indent=2))


if __name__ == "__main__":
    main()
