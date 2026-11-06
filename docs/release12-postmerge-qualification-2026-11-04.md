# Approved next-slice qualification and handoff

> **2026-11-06 readback:** [Oramasys #92](https://github.com/oramasys/oramasys/pull/92)
> and [Phylax #31](https://github.com/oramasys/phylax/pull/31) have merged. The
> draft references below describe the publication-time snapshot. Their merges
> do not close actual-host R4/R5, independent R6, operator R7 or separate R8.
> R1–R3 have candidate software and source-test evidence in this record; do not
> infer production qualification merely from their omission in the open-gate list.
> The [operator runbook](serving-activation-runbook.md) routes the remaining gates.
> The per-gate R1–R8 status table, with evidence links, is in the dated note of the
> [remaining requirements](release12-remaining-requirements-2026-10-29.md).

Plan date: 2026-11-04 Asia/Manila. Execution: 2026-11-03 UTC.
Status: implemented software candidate and reviewed design subset; R4–R8 remain open.

## Exact sources and publication

| Source | Immutable revision / review |
| --- | --- |
| Consumer merged baseline | `98b7568fa4bedbf59be788b62d2c7333f10535f4` (#91 merged) |
| Consumer original draft | `9ca04b3fd7176a83403dffe8ec158c84ae794949` |
| Reviewed consumer runtime/test code | `12c81880a5ecdf267a0130746e44eff74553d976` |
| Consumer matrix and design alignment | `c3706d5` (same runtime code) |
| Consumer publication target | Existing draft [#92](https://github.com/oramasys/oramasys/pull/92) |
| Merged producer | `a7211df7d58695f35f5afee9b6b50af6a3f96139` |
| Repaired producer | `b2edfe9584f4e013105cab3d87fda174e13079f6`, draft [#31](https://github.com/oramasys/phylax/pull/31) |

The [CI baseline audit](release12-postmerge-ci-baseline-2026-11-04.md) records prior
main/#92 checks separately. The new producer's [Actions run](https://github.com/oramasys/phylax/actions/runs/41729538709)
passed Ubuntu full tests, Windows platform-only cells (3.11/3.12), and permit interop.
CodeRabbit skipped that run. Required branch-protection settings could not be read (403).
The updated consumer checks must run after this single publication; older green checks
cannot qualify the updated head. Remote readback and final head are reported in the PR.

## Implemented and reviewed

- The source-test workflow preserves the merged-producer matrix and adds the immutable
  repaired producer, each on Python 3.11/3.12 with both interop-required flags.
- Refresh resamples time under its second cache write lock, closing the reproduced false
  rollback race. Regression tests distinguish forward interleaving from true rollback.
- The approval retry test now recovers from an outage, sends once, and replays the receipt.
- Phylax rechecks registry freshness, key validity/revocation and assertion expiry under
  the nonce write lock before consumption. Four regressions failed before the repair;
  nonce consumption remains absent on refusal. This does not detect an unobserved registry.
- The reviewed [loaded-identity ADR](adr/loaded-deployment-identity.md) has a bounded opt-in
  implementation: `load_with_identity` snapshots relevant environment inputs, loads once,
  and freezes an allowlisted public topology projection. It observes return-time values;
  the existing mutable effective result is not bound to later service consumption.
  Serialize only `projection`; the enclosing result contains private effective values.
  Generic loader refusals use `load-refused` without forwarding exception messages.

No Phylax import was added under `src/orama`. Production `pyproject.toml`, all
compatibility production pins, and accepted generation bytes are unchanged.

## Current local verification

Clean, separate Linux environments installed `.[dev]` and `PyNaCl==1.6.2`; `pip check`
passed in each. Python versions were 3.11.17 and 3.12.14. Dependency snapshots are retained
with the logs; both snapshot files have SHA-256
`b65b3ec96c09bf1f142e6ff657883dd2aedd4d8511ab26c16abfeb6718ac2e8b`.
These are source-test environments, not installed deployment qualification.

| Selection | Python 3.11 | Python 3.12 |
| --- | --- | --- |
| Final consumer selection + merged producer | 225 passed | 225 passed |
| Final consumer selection + repaired producer | 225 passed | 225 passed |
| Full reviewed consumer + repaired producer | 2,928 passed, 3 skipped | 2,928 passed, 3 skipped |
| Full repaired producer | 992 passed, 1 skipped | 992 passed, 1 skipped |

Consumer skips: optional `langchain_core.runnables` unavailable, `ORAMA_DOCS_V2_REGISTRY`
unset, and `ORAMA_REQUIRE_CLEAN_INSTALL` unset. These are unexecuted local cells, not passes;
the remote production CI separately configures the canonical registry and clean install.
Producer skip: Windows-only same-handle lock test on Linux. Producer coverage: 92.62%.
Existing pytest-asyncio warns that the fixture loop scope is unset; no test failed.

The workflow selection is `src/tests/r3_interop`, `src/tests/effect_interop`, retained
dispatch authority, approval transaction recheck, dispatch attempts, serving refusals,
inert process crashes, and loaded deployment identity. Full suites used `python -m pytest
-q -rs` with the candidate source paths and required interop flags. Changed consumer Python
files have 89/89 documented module/class/function items; producer files have 68/68.

### Retained log checksums (SHA-256)

| Log | Digest |
| --- | --- |
| `qualification-final-py311-merged-selected.log` | `de323cde6f5bf7319a118d28983d991c463de978351c58e8ceb656d1bb72347a` |
| `qualification-final-py311-repair-selected.log` | `09209a3a552e93e2f619af458a60ea6a782eb89f3f4193ea60b7f9f0ee81fd24` |
| `qualification-final-py312-merged-selected.log` | `40aca4b524afa41838317e8f7a29b381d8435df565ac3a83654e2eaee0ef2f53` |
| `qualification-final-py312-repair-selected.log` | `3a618983698bdb8da4d15cbf7c05132c9fbb473dacf49e1f473a71f8c3462bfc` |
| `qualification-final-reviewed-py311-consumer.log` | `23a88d7a9844593e7b283f3171314dd535f643f8073d9167f8825fed803febb4` |
| `qualification-final-reviewed-py312-consumer.log` | `e801f003f277cd5d302c283264c4bc6948dd0485ae5666780de62a1a930cf80b` |
| `phylax-commit-time-py311-20261103.log` | `8708eddb0c673bbe7e222b54a43d2df0912d4084843623a2f259acc54e24e2d3` |
| `phylax-repair-py312-full.log` | `8ced24dad8866f6a6ec14c3210ff10958f2db22db07558b08737951e3099fe3d` |

## Review provenance

Author lanes: GPT-6.1 Terra baseline audit, consumer regression, producer/platform audit,
and loaded-identity design/implementation. Actor/integrator: Codex; local commits were
inspected, integrated and reverified. Fresh Terra review found the refresh race and two
identity scope/classification issues; all were fixed and re-reviewed without further
concrete findings. This same-session endorsement is bounded code review, not independent
R6. No human signing, ceremony or qualification evidence was fabricated.

## Remaining work, owner and evidence

1. Maintainers: review #31 and #92 and their new exact-head CI. Merge producer before
   promotion decisions. A passing candidate lane does not promote any production pin.
2. Runtime owner: optimize snapshot verification only with invalidation for both cached
   bytes and current issuer-key trust. Large-feed write-lock contention remains measured
   in the [capacity handoff](revocation-capacity-handoff-2026-11-03.md). Benchmark complete
   sends and simultaneous refresh on the target filesystem before availability claims.
3. Deployment owner: select actual host/OS/filesystem, service identity, real entrypoint and
   complete configuration/policy loader chain. Define private evidence storage, integrity,
   retention, publication and process-to-installed-set binding. The projection is not a
   private evidence assembler, canonical wire validator, filesystem proof or R5 receipt.
4. Operator: collect R4 secret-read and issuer/public-write denials with
   `scripts/qualify_serving_identity.py` under the actual service identity. Collect R5 using
   `scripts/verify_installed_identity.py`, `scripts/verify_phylax_pin.py` and a reviewed
   deployment-bound config/policy collector outside checkout. Real Windows ACL evidence
   requires Windows deployment execution; Windows platform CI cannot substitute.
5. Independent reviewer: R6 at exact producer/consumer/configuration SHAs after host evidence.
   Operator: R7 new immutable generation with paired production/test pins only after gates;
   R8 remains a separate activation decision with expiry, canary and rollback.
6. Subsequent scoped work: checkpoint equivalence/pruning, saved-frontier continuation,
   Telos-backed provider transport, versioned framework differential compatibility and
   multi-host partition/split-brain qualification. Audit existing code before extending.

Keep `ORAMA_GRANT_SERVING` unset and live senders disabled. Source-level callback locality
is a trusted injected-port requirement: arbitrary injected functions are not mechanically
prevented from doing network work or re-entering stores. Supplied adapters are tested
within that contract; do not describe this as process isolation.

Rollback: revert this slice's consumer and producer commits in reverse dependency order.
No production database migration, pin rollback or accepted-generation rewrite is needed.
Publication of this evidence does not authorize deployment, merge or activation.
