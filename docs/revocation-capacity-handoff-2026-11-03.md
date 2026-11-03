# Revocation capacity and merged-producer follow-up

## Sources and implementation

Consumer baseline: [98b7568](https://github.com/oramasys/oramasys/commit/98b7568fa4bedbf59be788b62d2c7333f10535f4), merging #91.
Producer: [a7211df](https://github.com/oramasys/phylax/commit/a7211df7d58695f35f5afee9b6b50af6a3f96139), merging #30.
The R3 candidate workflow now tests this immutable merged producer. Production pins and accepted generations are separate.

The benchmark uses real signed synthetic events, temporary SQLite stores, current wall time,
and the actual adapter. It measures cache lookups, not complete sends. No deployment keys or
serving activation are involved. Each row contains 16 lookups; concurrent rows include failures
in latency statistics and therefore must be read with the unavailable count.

It exposed an additional race: sampling time before waiting for a write lock could compare an
old sample against another writer's newer observation. Time is now sampled under the observation
lock, and sampled again after acquiring the lookup transaction. Actual backwards time is still
refused. A deterministic interleaving regression failed before the fix and passes afterwards.

## Observations

One Linux / Python 3.12.14 run, milliseconds rounded; these are host observations, not an SLO.

| Events | Workers | Median before / after (ms) | Unavailable before / after |
| --- | --- | --- | --- |
| 0 | 1 | 0.55 / 0.59 | 0 / 0 |
| 0 | 8 | 2.40 / 4.77 | 10 / 0 |
| 256 | 1 | 40.04 / 47.74 | 0 / 0 |
| 256 | 8 | 44.94 / 102.70 | 13 / 12 |
| 4096 | 1 | 711.96 / 700.10 | 0 / 0 |
| 4096 | 8 | 101.94 / 101.64 | 15 / 15 |

After the fix the observed concurrent failures were cache lock timeouts (`OperationalError`).
The expensive signature/chain replay still holds the write lock. This remains an availability
limit and is not suitable evidence for high-concurrency deployment readiness.

Reproduce with the chosen producer source and this consumer on the import path:

```sh
PYTHONPATH="src:$PHYLAX_SOURCE/src" python scripts/benchmark_revocation_feed.py
```

Validation: the required R3/effect interop, retained-authority, transactional recheck, dispatch,
serving refusal and process-crash selection passed **215 tests** against merged Phylax main.
The benchmark, adapter and changed test file have **64/64** documented items.

## Next implementation and independent gates

1. Reduce full-chain replay inside the write lock. A verified snapshot cache must invalidate on
   both cached bytes **and current issuer-key trust changes**; a bytes-only cache would resurrect
   trust in a retired key. Test trust removal without changing bytes, tampering, concurrent refresh,
   stale snapshots, clock rollback, restart and cross-process writers before accepting it.
2. Benchmark refresh competing with lookups and complete sends on the target filesystem; the
   current benchmark covers concurrent lookup workers only. Establish a workload and latency/error
   budget before claiming availability qualification.
3. Continue the [release synthesis handoff](release12-r3-synthesis-handoff-2026-11-02.md)
   and [completion matrix](release12-r3-completion-matrix-2026-11-02.md): loaded configuration
   evidence, real R4/R5 identity/ACL evidence, Windows call-site review, independent R6,
   operator-owned R7 generation and separate R8 activation remain open.

Author and actor: Codex implementation lane. Local tests are implementation evidence, not
independent review endorsement or deployment qualification. No release gate is promoted here.
