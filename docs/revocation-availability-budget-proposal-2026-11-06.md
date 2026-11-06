# Revocation availability: proposed workload and budget (C6)

**Status: PROPOSED — awaiting operator confirmation; target-filesystem measurement is owner-held.**
Nothing here is an approved SLO, a qualification, or an availability claim. The measurements
below come from one container run ("container filesystem, not target host") and are
implementation evidence only. Serving stays dark; no deployment keys were used.

Register row: master closure plan C6, "Revocation availability — Oramasys": trust-and-byte-aware
snapshot validation; retirement/tamper/restart regressions; complete-send plus refresh benchmark
on target filesystem. Inputs: [capacity handoff](revocation-capacity-handoff-2026-11-03.md)
next gates 1 and 2, and remaining-work item 2 of the
[post-merge qualification record](release12-postmerge-qualification-2026-11-04.md).

## What changed in `scripts/revocation_feed_adapter.py`

The gap the handoff named was real at base `fe4049e`: every lookup re-ran the complete signature
and chain replay inside the cache's `BEGIN IMMEDIATE` write lock (about 0.6 s per lookup at 4096
events here), so concurrent lookups timed out at the 0.1 s lock wait. The base was already safe
(it re-verified everything every time); it was slow. The handoff's warning was that a naive
bytes-only cache would revive trust in a retired key.

- **Trust-and-byte-aware reuse.** A lookup skips the replay only when the cached signed state and
  feed match a per-instance record by SHA-256 *and* length, and every key identifier that signed
  them still resolves to the same trusted public key. Trust is sampled before and after the full
  verification; if it changed, nothing is recorded. Any byte, length, digest, or head change, and
  any trust change (retirement, replacement, or resolver error), forces a full replay, which then
  fails closed.
- **No persistence.** The record lives in memory only. A restart or a failed refresh discards it,
  and a restarted instance still needs an explicit successful refresh before any lookup.
- **Per-lookup checks kept.** The clock high-water mark and the 60 s freshness window are still
  checked on every lookup. Empty, unknown, or unverifiable state raises `RevocationUnavailable`;
  it never means "not revoked".
- **Replays outside the write lock.** A lookup that finds a changed snapshot replays it in a plain
  read before taking the write lock. Concurrent lookups on one instance share that single replay.
  The locked path rechecks bytes, trust, clock, and freshness and makes the decision.
- **Refresh.** Refresh verifies its input once, before the write lock. Under the lock it resamples
  trust (and re-verifies on any change) and checks freshness at the locked time. For its
  antirollback comparison it reuses its own record of the previous snapshot.

Regressions in `src/tests/r3_interop/test_revocation_feed_adapter.py` (Phylax R3 lane):

- key retirement, replacement, and resolver failure after a snapshot write
- no revival of a retired-key snapshot after restart
- after a warm lookup: state and feed truncation, extension, byte flip, other-head state or feed,
  and a re-signed head-digest mismatch
- a cross-instance writer replacing the reused snapshot
- clock rollback and expiry with reuse
- restart and failed-refresh discard
- replays outside the lock
- trust retired between the outside-lock verification and the locked commit
- single-flight concurrent replay

## Benchmark harness

`scripts/benchmark_revocation_availability.py` (not part of the pytest suite). Each send is a
complete `SealedInertDriver.send`:

1. envelope check
2. final boundary, with the real adapter over a real signed synthetic feed
3. transactional send start
4. inert simulation
5. receipt settlement

A background refresher re-signs the state at wall time on a fixed cadence and appends one
revocation while the feed is below 4096 events. Retryable `approval_verifier_unavailable` is
retried up to `--retries` times with a 50 ms pause, because it does not burn the attempt. The
harness reports p50, p95, p99, and maximum latency for successful sends, the first-try
unavailable rate, the final error rate, and refresh latency and failures.

```sh
PYTHONPATH="src:$PHYLAX_SOURCE/src" python scripts/benchmark_revocation_availability.py \
  --events 256 4096 --senders 8 --sends 300 --send-interval 0.2 \
  --refresh-interval 15 --refresher separate --label "<filesystem description>"
```

Modelling limits:

- Each send owns its attempt-store file, so attempt-store contention between senders, and between
  senders and refresh ingestion, is not modelled.
- Senders are threads in one process.
- The fixtures reuse the suite's synthetic inert harness (fake issuer-port signatures, fixed send
  clock).
- The run measures whatever filesystem holds the system temporary directory.

## Proposed workload (for operator confirmation)

| Dimension | Proposed expected | Stress, no budget proposed |
| --- | --- | --- |
| Feed size, complete from genesis | ≤ 256 events | 4096 (adapter default ceiling) |
| Refresh | every 15 s from a separate adapter instance or process | every 1 s; same-instance refresh |
| Concurrent senders | 8 | 1 and 8 |
| Send rate | 5 sends/s per sender, 40 sends/s aggregate | 50 sends/s per sender |
| Retry on retryable unavailability | ≤ 2 retries, 50 ms apart | same |

At a 15 s cadence against the producer's 60 s state-age ceiling, three consecutive refresh
failures are tolerated before sends become unavailable.

Refreshing through the serving instance is **not** proposed. A refresh marks that instance
unavailable until it completes, by design.

## Proposed latency and error budget (expected workload)

| Measure | Proposed budget |
| --- | --- |
| Complete-send latency, including retries | p95 ≤ 50 ms, p99 ≤ 250 ms |
| First-try retryable unavailability | ≤ 1 % of sends |
| Final error rate after retries | ≤ 0.1 % of sends, per hour of steady load |
| Terminal refusal caused by revocation unavailability | 0 |
| Fail-open: any send allowed on stale, unknown, tampered, or untrusted state | 0; any occurrence is a defect, not budget |
| Refresh latency | p95 ≤ 1 s; 0 failures at steady state |

One container run of 2400 sends with 0 errors bounds the true error rate at about 0.125 % (95 %
upper bound). Showing ≤ 0.1 % therefore needs a longer target-host run, for example one hour at
the proposed rate (about 144,000 sends).

## Measured: container filesystem, not target host

Environment: Linux container, 4 vCPU, ext4 virtual disk, Python 3.13.18, Phylax `main` 1d2f2bb
(includes producer a7211df). Adapter at `954e089`; "base" is the adapter at `fe4049e` run by the
same harness. Each cell is one run. These values describe this container only.

**Proposed workload:** 8 senders × 300 sends, 0.2 s pacing, separate refresher every 15 s.

| Events | Adapter | Send p50 / p95 / p99 / max (ms) | First-try unavailable | Final error | Refresh p50 / max (ms), failed |
| --- | --- | --- | --- | --- | --- |
| 256 | new | 5.98 / 13.19 / 37.32 / 107.46 | 0.00 % | 0.00 % (0/2400) | 81.6 / 90.6, 0 |
| 256 | base | 71.12 / 341.31 / 395.59 / 480.71 | 24.29 % | 3.63 % | 100.6 / 101.9, 4 lock timeouts |
| 4096 | new | 10.76 / 23.59 / 1028.05 / 1173.45 | 1.67 % | 0.46 % | 998.5 / 1539.4, 0 |
| 4096 | base | 877.06 / 980.63 / 1019.86 / 1028.37 | 98.42 % | 91.54 % | 1591.4 / 1591.4, 11 lock timeouts |

At 256 events the new adapter meets every proposed number in this one container run. At 4096
events it misses the p99 and final-error proposals. No budget is proposed for 4096.

**Stress:** 1 s refresh, 100 sends per sender, 0.02 s pacing, new adapter.

| Events | Senders | Refresher | Send p95 / p99 (ms) | First-try unavailable | Final error |
| --- | --- | --- | --- | --- | --- |
| 256 | 1 | separate | 5.46 / 123.87 | 0.00 % | 0.00 % |
| 256 | 1 | same | 4.80 / 105.55 | 2.00 % | 0.00 % |
| 256 | 8 | separate | 30.87 / 111.07 | 0.75 % | 0.00 % |
| 256 | 8 | same | 24.77 / 110.25 | 2.12 % | 0.88 % |
| 4096 | 1 | separate | 18.21 / 939.18 | 3.00 % | 1.00 % |
| 4096 | 1 | same | 10.55 / 110.84 | 14.00 % | 13.00 % |
| 4096 | 8 | separate | 184.61 / 811.11 | 7.63 % | 3.37 % |
| 4096 | 8 | same | 113.61 / 187.99 | 26.25 % | 21.75 % |

The base adapter under the same stress had a final error of 0–48 % at 256 events and 18–99 % at
4096 events.

**Lookup-only** (`scripts/benchmark_revocation_feed.py`, 64 lookups, new adapter):

| Events | Workers | Median / p95 (ms) | Unavailable |
| --- | --- | --- | --- |
| 256 | 1 | 1.96 / 2.63 | 0 |
| 256 | 8 | 31.05 / 46.10 | 0 |
| 4096 | 1 | 6.91 / 9.13 | 0 |
| 4096 | 8 | 20.41 / 115.39 | 6 |

The same benchmark on the base adapter in this container gave:

- 4096 events, 1 worker: 569.98 ms median.
- 4096 events, 8 workers: 62 of 64 unavailable.
- 256 events, 8 workers: 45 of 64 unavailable.

All lookup unavailability, and every send failure in the new-adapter runs, was a retryable
fail-closed `RevocationUnavailable`. The underlying causes were cache lock timeouts
(`OperationalError`). No run recorded a terminal refusal. The benchmark cannot detect
fail-open; the regression tests cover that.

## Remaining limits and owner-held items

- **Target filesystem (owner-held).** The deployment owner must select the host, OS, and
  filesystem, then run the harness there with the confirmed workload. They should run it for
  long enough to resolve the error budget and record the label. This run is not that evidence.
- **Operator confirmation (owner-held).** The workload and budget above are proposals. The
  operator may change any number. Until it is confirmed, C6 availability is not claimed.
- **Large-feed refresh.** Refresh still holds the cache write lock during
  `SqliteAttemptStore.ingest_events`, which re-verifies every event (about 0.6 s of a ≈1–1.5 s
  refresh at 4096 events). The first lookup after a change still costs one full replay per
  instance. Incremental verification of an extended prefix was not attempted.
- **Per-lookup writes.** Each lookup commits two fully synchronous write transactions, the clock
  observation and the decision. Under contention these hit the 0.1 s lock wait. They are the
  remaining source of retryable unavailability at 256 events.
- **Key retirement.** A key that signed any retained event or the cached state cannot be retired
  without the complete-from-genesis feed becoming unverifiable. Refresh then refuses, which is
  fail-closed but unavailable, until a producer or operator procedure re-establishes a verifiable
  feed and cache. This follows from the design; only no-revival is tested.
- **Not modelled.** The benchmark does not model a shared attempt store or multiple processes.
