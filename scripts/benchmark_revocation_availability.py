"""Measure complete inert sends competing with revocation refreshes; never enables serving.

Each send is a full ``SealedInertDriver.send``: envelope check, final boundary (including the
real ``RevocationFeedAdapter`` lookup over a real signed synthetic feed), transactional send
start, in-process inert simulation and receipt settlement. A background refresher re-signs a
fixed-size synthetic feed, so cached state bytes change and serving lookups must reverify.
New revocations during the measured window are not modelled. Every send attempt is counted; a retryable
``approval_verifier_unavailable`` refusal is retried up to ``--retries`` times because it does
not burn the attempt.

Run from the repository root with the chosen Phylax source and PyNaCl importable::

    PYTHONPATH="src:scripts:$PHYLAX_SOURCE/src" python scripts/benchmark_revocation_availability.py

The authorized attempts reuse the test suite's synthetic inert fixtures (fake issuer-port
signatures, a fixed historical send clock). Each send owns its attempt-store file, so
attempt-store contention between senders is NOT modelled; the shared resources measured are
the revocation cache, its lock and refresh. Senders are threads in one process. Results are
observations of the filesystem the temporary directory lives on, never a deployment
qualification, an SLO or approval.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import tempfile
import threading
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nacl.bindings import crypto_sign_seed_keypair
from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.final_boundary import FinalBoundaryRefused
from orama.graph.sealed_inert_driver import SealedInertDriver
from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import SqliteDispatchPermitStore
from phylax.dispatch_retention import RetainedEventFeed, RetentionLedger
from phylax.revocation_publication import build_state, sign_state_body
from revocation_feed_adapter import RevocationFeedAdapter
from tests.test_dispatch_attempts import ISSUER, NOW
from tests.test_final_boundary import Approvals
from tests.test_inert_effect_integration import inert_harness
from tests.test_sealed_inert_driver import SCOPE, approve, envelope

KEY_ID = "benchmark-key"
SEED = b"B" * 32


class SyntheticSigner:
    """Generate disposable, explicitly synthetic benchmark signatures."""

    def active_key_id(self) -> str:
        """Name this benchmark's disposable key."""
        return KEY_ID

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign the synthetic event domain."""
        return wire.sign_event(SEED, digest)

    def sign_state(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign the synthetic state domain."""
        return sign_state_body(SEED, body)


def percentile(sorted_values: list[float], fraction: float) -> float | None:
    """Return a nearest-rank percentile of already sorted values, or None when empty."""
    if not sorted_values:
        return None
    return sorted_values[min(len(sorted_values) - 1, int(len(sorted_values) * fraction))]


def summarize(values: list[float]) -> dict[str, float | None]:
    """Summarize latencies in milliseconds."""
    ordered = sorted(values)
    return {
        "p50_ms": None if not ordered else round(statistics.median(ordered) * 1000, 2),
        "p95_ms": None if not ordered else round(percentile(ordered, .95) * 1000, 2),
        "p99_ms": None if not ordered else round(percentile(ordered, .99) * 1000, 2),
        "max_ms": None if not ordered else round(ordered[-1] * 1000, 2),
    }


class Feed:
    """Own the synthetic producer and build complete signed snapshots at wall time."""

    def __init__(self, root: Path, events: int) -> None:
        """Pre-populate ``events`` synthetic revocations."""
        self.signer = SyntheticSigner()
        self.producer = SqliteDispatchPermitStore(root / "producer.db")
        self.feed = RetainedEventFeed(self.producer, RetentionLedger(root / "retention.db"))
        for index in range(events):
            self.producer.append_revocation("grant", f"synthetic-{index}", signer=self.signer)
        self.lock = threading.Lock()

    def snapshot(self) -> tuple[bytes, list[dict[str, Any]]]:
        """Sign the fixed-size complete feed at the current time."""
        with self.lock:
            head = self.producer.current_counter()
            state = build_state(self.feed, issuer_id=ISSUER, head_version=head,
                                signer=self.signer, now=datetime.now(UTC))
            return state, (self.feed.events(1, head) if head else [])


def refresh_once(feed: Feed, writer: RevocationFeedAdapter, latencies: list[float],
                 failures: dict[str, int]) -> None:
    """Record either a completed refresh or a snapshot/refresh failure."""
    try:
        snapshot = feed.snapshot()
        begin = time.perf_counter()
        writer.refresh(*snapshot)
        latencies.append(time.perf_counter() - begin)
    except Exception as error:  # noqa: BLE001 - every failure is an observation
        name = type(error).__name__
        failures[name] = failures.get(name, 0) + 1


def measure(
    *, events: int, senders: int, sends: int, send_interval: float, refresh_interval: float,
    refresher: str, retries: int,
) -> dict[str, Any]:
    """Run one workload cell and return its observations."""
    public = crypto_sign_seed_keypair(SEED)[0]
    with tempfile.TemporaryDirectory(prefix="orama-revocation-availability-") as directory:
        root = Path(directory)
        feed = Feed(root, events)
        adapter_store = SqliteAttemptStore(root / "adapter-attempts.db")
        stores: list[SqliteAttemptStore] = [adapter_store]

        def make_adapter() -> RevocationFeedAdapter:
            """Open one adapter instance over the shared dedicated cache."""
            return RevocationFeedAdapter(
                root / "cache.db", store=adapter_store, issuer_id=ISSUER,
                public_key_for=lambda issuer, key: public if (issuer, key) == (ISSUER, KEY_ID) else None,
                clock=lambda: datetime.now(UTC), approval_ref_for=lambda *_: "",
            )

        serving = make_adapter()
        drivers: list[SealedInertDriver] = []
        for index in range(senders * sends):
            attempt_root = root / f"attempt-{index}"
            attempt_root.mkdir(mode=0o700)
            harness = inert_harness(attempt_root)
            approve(harness)
            stores.append(harness.store)
            drivers.append(SealedInertDriver(
                harness.store, effects_allowed=lambda: True, approval_verifier=Approvals(),
                revocations=serving, issuer_id=ISSUER, clock=lambda: NOW,
            ))
        genuine = envelope()
        # Refresh only after slow fixture setup so the measured window starts fresh.
        started = time.perf_counter()
        serving.refresh(*feed.snapshot())
        initial_refresh = time.perf_counter() - started
        writer = serving if refresher == "same" else make_adapter()

        stop = threading.Event()
        refresh_latencies: list[float] = []
        refresh_failures: dict[str, int] = {}

        def refresh_loop() -> None:
            """Refresh at a fixed cadence until senders finish, recording every outcome."""
            while not stop.wait(refresh_interval):
                refresh_once(feed, writer, refresh_latencies, refresh_failures)

        def send(driver: SealedInertDriver) -> tuple[float, int, str]:
            """Complete one send, retrying only retryable unavailability."""
            begin = time.perf_counter()
            tries = 0
            while True:
                tries += 1
                try:
                    driver.send(genuine.raw, genuine.digest, principal=SCOPE.principal)
                    return time.perf_counter() - begin, tries, "sent"
                except FinalBoundaryRefused as refusal:
                    if refusal.terminal:
                        return time.perf_counter() - begin, tries, f"terminal:{refusal.reason}"
                    if tries > retries:
                        return time.perf_counter() - begin, tries, f"unavailable:{refusal.reason}"
                    time.sleep(0.05)
                except Exception as error:  # noqa: BLE001 - every failure is an observation
                    return time.perf_counter() - begin, tries, f"error:{type(error).__name__}"

        def sender(index: int) -> list[tuple[float, int, str]]:
            """Send this sender's attempts sequentially at the requested pace."""
            out = []
            for driver in drivers[index * sends:(index + 1) * sends]:
                out.append(send(driver))
                if send_interval:
                    time.sleep(send_interval)
            return out

        thread = threading.Thread(target=refresh_loop, daemon=True) if refresh_interval > 0 else None
        if thread:
            thread.start()
        try:
            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=senders) as pool:
                results = [item for batch in pool.map(sender, range(senders)) for item in batch]
            elapsed = time.perf_counter() - started
        finally:
            stop.set()
            if thread:
                thread.join(120)
            for store in stores:
                store.close()
        outcomes: dict[str, int] = {}
        for _, _, outcome in results:
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        total = len(results)
        first_try_ok = sum(1 for _, tries, outcome in results if outcome == "sent" and tries == 1)
        return {
            "events": events, "senders": senders, "sends": total, "send_interval_s": send_interval,
            "refresh_interval_s": refresh_interval, "refresher": refresher, "retries": retries,
            "initial_refresh_ms": round(initial_refresh * 1000, 2),
            "elapsed_s": round(elapsed, 3), "throughput_sends_per_s": round(total / elapsed, 1),
            "send_latency": summarize([duration for duration, _, outcome in results if outcome == "sent"]),
            "outcomes": outcomes,
            "first_try_unavailable_rate": round(1 - first_try_ok / total, 4),
            "final_error_rate": round(1 - outcomes.get("sent", 0) / total, 4),
            "refreshes": {"ok": len(refresh_latencies), "failed": refresh_failures,
                          **summarize(refresh_latencies)},
        }


def main() -> None:
    """Print machine-readable observations for every requested workload cell."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--events", type=int, nargs="+", default=[256])
    parser.add_argument("--senders", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--sends", type=int, default=50, help="sends per sender")
    parser.add_argument("--refresh-interval", type=float, nargs="+", default=[1.0],
                        help="seconds between refreshes; 0 disables the refresher")
    parser.add_argument("--refresher", choices=["separate", "same"], nargs="+", default=["separate"],
                        help="refresh through a second adapter instance or the serving instance")
    parser.add_argument("--send-interval", type=float, default=0.02,
                        help="seconds each sender pauses between sends")
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--label", default="unlabelled filesystem",
                        help="where the temporary directory lives, recorded verbatim")
    args = parser.parse_args()
    if (any(not 0 <= value <= 4096 for value in args.events)
            or any(not 1 <= value <= 64 for value in args.senders)
            or not 1 <= args.sends <= 2000 or not 0 <= args.retries <= 10
            or not 0 <= args.send_interval <= 10
            or any(not 0 <= value <= 30 for value in args.refresh_interval)):
        parser.error("events 0..4096, senders 1..64, sends 1..2000, retries 0..10, "
                     "send interval 0..10, refresh interval 0..30")
    print(json.dumps({
        "label": args.label, "python": platform.python_version(), "platform": platform.system(),
        "tempdir": "system temporary directory",
        "results": [measure(events=events, senders=senders, sends=args.sends,
                            send_interval=args.send_interval, refresh_interval=interval, refresher=refresher, retries=args.retries)
                    for events in args.events for senders in args.senders
                    for interval in args.refresh_interval for refresher in args.refresher],
    }, indent=2))


if __name__ == "__main__":
    main()
