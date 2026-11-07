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

Each cell requires a soft descriptor limit of at least
``3 * (senders * sends + 3) + 3 * (senders + 2) + 128``. This reserves three
descriptors per attempt/supporting store and concurrent cache connection, plus
fixed headroom. The harness does not change limits; platforms without POSIX
``resource`` report the capacity as not checked, not qualified.

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
import math
import platform
import sqlite3
import statistics
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from c6_runtime import require_c6_runtime

try:
    import resource
except ImportError:
    resource = None  # type: ignore[assignment]

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
    return sorted_values[max(0, min(len(sorted_values) - 1, math.ceil(len(sorted_values) * fraction) - 1))]


def scheduled_at(epoch: float, sequence: int, interval: float) -> float:
    """Schedule arrivals independently of prior request duration."""
    return epoch + sequence * interval


def final_error_upper_bound(errors: int, trials: int, confidence: float = 0.95) -> float:
    """Invert the binomial CDF for a one-sided Clopper-Pearson upper bound."""
    if trials < 1 or not 0 <= errors <= trials or not 0 < confidence < 1:
        raise ValueError("invalid binomial counts or confidence")
    if errors == trials:
        return 1.0
    if errors == 0:
        return -math.expm1(math.log1p(-confidence) / trials)
    low, high = errors / trials, 1.0
    for _ in range(60):
        p = (low + high) / 2
        terms = [math.lgamma(trials + 1) - math.lgamma(k + 1) - math.lgamma(trials - k + 1)
                 + k * math.log(p) + (trials - k) * math.log1p(-p) for k in range(errors + 1)]
        largest = max(terms)
        cdf = math.exp(largest) * math.fsum(math.exp(value - largest) for value in terms)
        if cdf > 1 - confidence:
            low = p
        else:
            high = p
    return (low + high) / 2


def safe_error(error: BaseException) -> dict[str, str | int]:
    """Expose diagnostic classes/codes without arbitrary exception text or locals."""
    result: dict[str, str | int] = {"class": type(error).__name__}
    if isinstance(error, sqlite3.Error):
        for field in ("sqlite_errorcode", "sqlite_errorname"):
            value = getattr(error, field, None)
            if isinstance(value, (str, int)):
                result[field] = value
    return result


@dataclass(frozen=True)
class SendSample:
    """One scheduled send, including queue delay and failed outcomes."""

    sender: int
    sequence: int
    scheduled_s: float
    started_s: float
    finished_s: float
    attempts: int
    outcome: str
    first_attempt_outcome: str


class MeasuredAdapter(RevocationFeedAdapter):
    """Observe actual cache lock waits/holds without modifying production hooks."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Keep measurements local to this diagnostic adapter."""
        self.lock_spans: list[dict[str, str | float]] = []
        self.transaction_errors: list[dict[str, str | int]] = []
        super().__init__(*args, **kwargs)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Measure acquisition separately from the full commit/rollback hold."""
        waiting = time.perf_counter()
        acquired: float | None = None
        try:
            with super()._transaction() as db:
                acquired = time.perf_counter()
                yield db
        except sqlite3.Error as error:
            self.transaction_errors.append(safe_error(error))
            raise
        finally:
            if acquired is not None:
                self.lock_spans.append({"thread": threading.current_thread().name,
                                        "wait_s": acquired - waiting,
                                        "hold_s": time.perf_counter() - acquired})


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
                 failures: dict[str, int], stages: list[dict[str, Any]] | None = None,
                 *, scheduled: float | None = None, sequence: int = 0) -> None:
    """Record either a completed refresh or a snapshot/refresh failure."""
    begin = time.perf_counter()
    constructed: float | None = None
    outcome = "failed"
    diagnostic: dict[str, str | int] | None = None
    offset = len(getattr(writer, "lock_spans", []))
    try:
        snapshot = feed.snapshot()
        constructed = time.perf_counter()
        writer.refresh(*snapshot)
        end = time.perf_counter()
        latencies.append(end - begin)
        outcome = "ok"
    except Exception as error:  # noqa: BLE001 - every failure is an observation
        name = type(error).__name__
        failures[name] = failures.get(name, 0) + 1
        diagnostic = safe_error(error)
    finally:
        end = time.perf_counter()
        if stages is not None:
            spans = getattr(writer, "lock_spans", [])[offset:]
            stages.append({"sequence": sequence, "scheduled_monotonic_s": scheduled,
                           "queue_s": 0.0 if scheduled is None else max(0, begin - scheduled),
                           "snapshot_s": (end if constructed is None else constructed) - begin,
                           "adapter_s": None if constructed is None else end - constructed,
                           "started_monotonic_s": begin, "finished_monotonic_s": end,
                           "outcome": outcome, "error": diagnostic,
                           "cache_write_hold_s": sum(float(span["hold_s"]) for span in spans)})


def join_refresher(thread: threading.Thread) -> None:
    """Require the refresher to stop before returning a workload result."""
    thread.join(120)
    if thread.is_alive():
        raise RuntimeError("refresher did not stop within 120 seconds")


def fd_preflight(senders: int, sends: int) -> dict[str, Any]:
    """Check the soft descriptor limit without modifying it, or report unsupported."""
    required = 3 * (senders * sends + 3) + 3 * (senders + 2) + 128
    if resource is None:
        return {"status": "not_checked", "required": required, "available": None}
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < required:
        raise RuntimeError(
            f"file descriptor capacity insufficient: required {required}, available soft limit {soft}; "
            "ask the operator to raise the process soft limit before running"
        )
    return {"status": "checked", "required": required,
            "available": "unlimited" if soft == resource.RLIM_INFINITY else soft}


def measure(
    *, events: int, senders: int, sends: int, send_interval: float, refresh_interval: float,
    refresher: str, retries: int, sample_path: Path | None = None,
) -> dict[str, Any]:
    """Run one workload cell and return its observations."""
    runtime = require_c6_runtime()
    descriptors = fd_preflight(senders, sends)
    public = crypto_sign_seed_keypair(SEED)[0]
    with tempfile.TemporaryDirectory(prefix="orama-revocation-availability-") as directory:
        root = Path(directory)
        feed = Feed(root, events)
        adapter_store = SqliteAttemptStore(root / "adapter-attempts.db")
        stores: list[SqliteAttemptStore] = [adapter_store]

        def make_adapter() -> MeasuredAdapter:
            """Open one adapter instance over the shared dedicated cache."""
            return MeasuredAdapter(
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
        cold_lock_spans = list(serving.lock_spans)
        serving.lock_spans.clear()
        writer = serving if refresher == "same" else make_adapter()

        stop = threading.Event()
        refresh_latencies: list[float] = []
        refresh_failures: dict[str, int] = {}
        refresh_stages: list[dict[str, Any]] = []

        def refresh_loop() -> None:
            """Refresh at a fixed cadence until senders finish, recording every outcome."""
            sequence = 1
            while not stop.wait(max(0, scheduled_at(epoch, sequence, refresh_interval) - time.perf_counter())):
                refresh_once(feed, writer, refresh_latencies, refresh_failures, refresh_stages,
                             scheduled=scheduled_at(epoch, sequence, refresh_interval), sequence=sequence)
                sequence += 1

        def send(driver: SealedInertDriver, index: int, sequence: int, scheduled: float) -> SendSample:
            """Complete one send, retrying only retryable unavailability."""
            begin = time.perf_counter()
            tries = 0
            first_outcome = "sent"

            def sample(outcome: str) -> SendSample:
                """Keep every completion in the measured population, including failures."""
                return SendSample(index, sequence, scheduled - epoch, begin - epoch,
                                  time.perf_counter() - epoch, tries, outcome, first_outcome)

            while True:
                tries += 1
                try:
                    driver.send(genuine.raw, genuine.digest, principal=SCOPE.principal)
                    return sample("sent")
                except FinalBoundaryRefused as refusal:
                    if tries == 1:
                        first_outcome = f"terminal:{refusal.reason}" if refusal.terminal else f"unavailable:{refusal.reason}"
                    if refusal.terminal:
                        return sample(f"terminal:{refusal.reason}")
                    if refusal.reason != "approval_verifier_unavailable" or tries > retries:
                        return sample(f"unavailable:{refusal.reason}")
                    time.sleep(0.05)
                except Exception as error:  # noqa: BLE001 - every failure is an observation
                    outcome = "error:" + json.dumps(safe_error(error), sort_keys=True)
                    if tries == 1:
                        first_outcome = outcome
                    return sample(outcome)

        def sender(index: int) -> list[SendSample]:
            """Send this sender's attempts sequentially at the requested pace."""
            out = []
            for sequence, driver in enumerate(drivers[index * sends:(index + 1) * sends]):
                scheduled = scheduled_at(epoch, sequence, send_interval)
                delay = scheduled - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
                out.append(send(driver, index, sequence, scheduled))
            return out

        epoch = time.perf_counter()
        thread = threading.Thread(target=refresh_loop, name="c6-refresh", daemon=True) if refresh_interval > 0 else None
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
                join_refresher(thread)
            for store in stores:
                store.close()
        outcomes: dict[str, int] = {}
        for result in results:
            outcomes[result.outcome] = outcomes.get(result.outcome, 0) + 1
        total = len(results)
        if total != senders * sends or len({(r.sender, r.sequence) for r in results}) != total:
            raise RuntimeError("scheduled send accounting mismatch")
        first_unavailable = sum(r.first_attempt_outcome == "unavailable:approval_verifier_unavailable" for r in results)
        errors = total - outcomes.get("sent", 0)
        if sample_path is not None:
            with sample_path.open("x", encoding="utf-8", newline="\n") as output:
                for result in sorted(results, key=lambda r: (r.sender, r.sequence)):
                    output.write(json.dumps(asdict(result), sort_keys=True) + "\n")
        spans = list(serving.lock_spans) + ([] if writer is serving else list(writer.lock_spans))
        refresh_spans = [span for span in spans if span["thread"] == "c6-refresh"]
        return {
            "runtime": runtime,
            "file_descriptors": descriptors,
            "events": events, "senders": senders, "sends": total, "send_interval_s": send_interval,
            "refresh_interval_s": refresh_interval, "refresher": refresher, "retries": retries,
            "initial_refresh_ms": round(initial_refresh * 1000, 2),
            "elapsed_s": round(elapsed, 3), "throughput_sends_per_s": round(total / elapsed, 1),
            "send_latency": summarize([r.finished_s - r.started_s for r in results if r.outcome == "sent"]),
            "scheduled_latency": summarize([r.finished_s - r.scheduled_s for r in results]),
            "queue_latency": summarize([r.started_s - r.scheduled_s for r in results]),
            "all_outcome_service_latency": summarize([r.finished_s - r.started_s for r in results]),
            "scheduled_sends": senders * sends,
            "offered_sends_per_s": None if send_interval == 0 else senders / send_interval,
            "outcomes": outcomes,
            "first_try_unavailable_count": first_unavailable,
            "first_try_unavailable_rate": first_unavailable / total,
            "final_error_count": errors,
            "final_error_rate": errors / total,
            "final_error_upper_95": final_error_upper_bound(errors, total),
            "confidence_limitation": "binomial bound assumes independent trials; refresh failures can correlate",
            "cold_cache_lock_spans": cold_lock_spans,
            "refresh_cache_lock_spans": refresh_spans,
            "refresh_cache_lock_hold": summarize([float(s["hold_s"]) for s in refresh_spans]),
            "refresh_cache_lock_wait": summarize([float(s["wait_s"]) for s in refresh_spans]),
            "refresh_stages": refresh_stages,
            "refresh_queue_latency": summarize([stage["queue_s"] for stage in refresh_stages]),
            "per_refresh_cache_lock_hold": summarize([stage["cache_write_hold_s"] for stage in refresh_stages]),
            "cache_transaction_errors": list(serving.transaction_errors) + (
                [] if writer is serving else list(writer.transaction_errors)),
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
    parser.add_argument("--samples-jsonl", type=Path, help="exclusive-create per-send evidence for one cell")
    args = parser.parse_args()
    if (any(not 0 <= value <= 4096 for value in args.events)
            or any(not 1 <= value <= 64 for value in args.senders)
            or not 1 <= args.sends <= 2000 or not 0 <= args.retries <= 10
            or not 0 <= args.send_interval <= 10
            or any(not 0 <= value <= 30 for value in args.refresh_interval)):
        parser.error("events 0..4096, senders 1..64, sends 1..2000, retries 0..10, "
                     "send interval 0..10, refresh interval 0..30")
    if args.samples_jsonl and len(args.events) * len(args.senders) * len(args.refresh_interval) * len(args.refresher) != 1:
        parser.error("--samples-jsonl requires exactly one workload cell")
    if args.samples_jsonl and args.samples_jsonl.exists():
        parser.error("sample evidence already exists; choose a unique filename")
    require_c6_runtime()
    print(json.dumps({
        "label": args.label, "python": platform.python_version(), "platform": platform.system(),
        "tempdir": "system temporary directory",
        "results": [measure(events=events, senders=senders, sends=args.sends,
                            send_interval=args.send_interval, refresh_interval=interval, refresher=refresher,
                            retries=args.retries, sample_path=args.samples_jsonl)
                    for events in args.events for senders in args.senders
                    for interval in args.refresh_interval for refresher in args.refresher],
    }, indent=2))


if __name__ == "__main__":
    main()
