# C1 disposition ledger — Oramasys documentation findings (2026-11-06)

Register row: C1 of the Orama master closure plan
(`docs/v2/MASTER-CLOSURE-AND-IMPLEMENTATION-PLAN-2026-11-06.md` in orama-system).
Input: the read-only architecture and migration docs review dated 2026-11-06
(reviewed Oramasys at PR #93 head `07f4f81`). That review is a claim list, not an
authority; every finding below was re-checked against Oramasys `main` `fe4049e`
(PRs #93 and #94 merged) and current source before a disposition was recorded.

Dispositions: **fixed** (this branch), **already-fixed** (commit cited),
**superseded**, **historical**, **rejected** (reason given), **blocked** (owner
and missing evidence named). This ledger closes documentation findings only. It
does not review, qualify, approve or activate anything; R4–R8 stay open.

## Section 3 — v2 map corrections (as they apply to Oramasys)

| Finding | Disposition | Source evidence |
| --- | --- | --- |
| M-2 satellite dependency modes; `adapters.py` unwired | already-fixed `6646b9e` | `ARCHITECTURE.md` ownership rows for Telos, Phylax, Agate and the paragraph after the table. Verified: Phylax is the `grant-serving` extra in `pyproject.toml`; no `phylax` import under `src/orama`. |
| M-3 leases have "no runtime code" | already-fixed `6646b9e` | Row scoped to job-claim leases and links `src/orama/graph/execution_guard.py`. |
| M-7 Knowledge Portal missing | already-fixed `6646b9e` | "Local documentation search" row links `src/orama/knowledge/`. |
| M-8 "admission" under Telos and Phylax | already-fixed `6646b9e` | Telos: "address admission"; Phylax: "principal/capability admission". |
| M-9 "no separate repository" too firm | fixed | Controller row now says a standalone repository is possible only through doc 68 §9, linked to the orama-system copy on `main`. |
| M-11 compatibility review shown as current | already-fixed `6646b9e` (label); fixed (active-generation link) | `ARCHITECTURE.md` labels it historical and now links `requirements/ACTIVE-GENERATION.json` (`m1-gen2`). The review file is not edited because `scripts/check_harness_consumer_drift.py` allow-lists it at fixed bytes (commit `7753dd3`). Its own 2026-10-10 note already marks it historical. |
| M-4 mastery doc listed as normative (v2 half) | already-fixed `6646b9e` | Listed under secondary references as "(review draft)". |
| M-5 stale PT closure record (v2 half) | already-fixed `6646b9e` | Links the PT retrospective as the merged outcome. |
| M-6 normative-decision owner row (v2 half) | already-fixed `b952dc6` | "Design decisions, ownership registry and capability schema" row. |
| M-10 PT wiki scope (v2 half) | already-fixed `6646b9e` | Labeled the historical July 2026 STM/mesh-security graph. |
| M-1, M-12 (v1 map only) | rejected for this repository | They concern the orama-system v1 map; routed to the orama-system C1 owner. |
| Oramasys docs the maps do not link | fixed | `ARCHITECTURE.md` "Current and Planned Boundaries" now links the runbook, post-merge handoff, loaded-identity ADR, execution witnesses, foreign transport, revocation state view, LangChain facade and reporting doc. The orama-system and PT link lists are routed to their owners. |

## Section 4.2 — Oramasys status rows

| Finding | Disposition | Source evidence |
| --- | --- | --- |
| Gateway-to-Telos migration pins and "verified" wording | already-fixed `6646b9e` (banner); fixed (historical PR evidence note) | A dated note before the list marks it as historical PR evidence and restates the current pins from `pyproject.toml` (Telos `931b6347…`, Core `6d75cfe…`, Agate `172bfc3e…`). This branch did not re-run that PR's verification. |
| Outbound ledger "no concrete `ProviderInvoker`" | already-fixed `6646b9e` (partial); fixed | Extended dated note: `GuardedForeignInvoker` (`src/orama/providers/foreign_transport.py`) is dark, takes an injected `DialPort` that must be Telos-backed, and keeps SQLite holds keyed by `run_id`. The optional injected `OutboundLedger` and `JsonlOutboundLedger` (`src/orama/providers/outbound_ledger.py`, append-only, single-process locking) also contradict the absence claim. Added an inventory row backed by `src/tests/test_foreign_transport.py`. Neither is wired into a default serving path. |
| Loaded-identity ADR header "no implementation" | already-fixed `6646b9e` | The header names a bounded loader-only implementation. Verified against `src/orama/deploy/identity.py` (`load_with_identity`, `LoadedIdentity`, `PublicProjection`). |
| 4.9 two R-gate series (Oramasys side) | already-fixed `6646b9e` | The runbook distinguishes graph-compatibility R3/R4 from Release 1–2 gates. The orama-system glossary and reference link are routed to orama-system. |

## Section 6 — release readiness

| Finding | Disposition | Source evidence |
| --- | --- | --- |
| H-1 runbook omits open gates | already-fixed `6646b9e` | The "Required qualification gates" section comes before "3. Receipt". It covers R4/R5 including R5(b), R6, R7, and R8 canary, expiry, monitoring and rollback. It also covers D6 and the `governed=True` entrypoint check, and links the 2026-11-04 handoff. |
| H-1 D6 record required by `profile.py` but absent | fixed (documentation); blocked (record) | `serving_permitted` requires an injected matcher returning `True`, and does not itself verify D6. Activation requires a trusted matcher wired to verify the applicable record; the default matcher never matches. No record exists in this repository or in orama-system `docs/v2/`; creation is held by the operator under C11. |
| H-1 `governed` defaults to `False` | fixed (documentation); blocked (code) | `SqliteAttemptStore(..., governed=False)` in `src/orama/graph/dispatch_attempts.py` is unchanged. This lane is docs-only. The runbook requires entrypoint verification, and `e1-t3-effect-seam-1.md` has a note that the limit is still live. Any default flip is held by the runtime owner. |
| H-1 "Phylax pin recorded" accepts the recovery verifier | fixed | A runbook precondition note says the verify-only pin (`0c3e860…`, `requirements/compatibility-phylax-verify-only.txt`) cannot authenticate effect authority. It links `release12-process-crash-evidence.md#remaining-release-gates`. |
| H-1 receipt template lacks R5(b)/R6/R7/D6 fields | already-fixed `6646b9e` | `docs/templates/serving-activation-receipt.md` lines for R4–R8, D6 and `governed=True`. |
| H-1 runtime safety intact | verified, no change | `_grant_flag` and `serving_permitted` in `src/orama/deploy/profile.py` fail closed by default. |
| Release-12 chain: remaining-requirements draft, no forward link | fixed | A dated note forward-links the 2026-11-04 handoff. The body is preserved. |
| Release-12 chain: R1–R8 status table | fixed | The table in that note marks R1–R3 as candidate and R4–R8 as open, with evidence links and C7–C11 register rows. The handoff readback links to it. |
| #92 described as draft | already-fixed `6646b9e` | The handoff readback records #92 as merged. Verified: `f89f82c` "Merge pull request #92". |
| Phylax #31 described as draft | already-fixed `6646b9e` | The readback records it as merged. Verified on Phylax `main`: `1d2f2bb` "Merge pull request #31", descending from repaired producer `b2edfe9`. |
| References stop at 2026-10-26 | rejected for this repository | These are orama-system reference documents; routed to that owner. |

## Table 7.4 — Oramasys `docs/`

| Document | Disposition | Note |
| --- | --- | --- |
| `serving-activation-runbook.md` | already-fixed `6646b9e`; fixed | See H-1 rows. |
| `templates/serving-activation-receipt.md` | already-fixed `6646b9e` | Fields present. |
| `architecture/outbound-consumer-authority-ledger.md` | fixed | See 4.2. |
| `architecture/gateway-telos-endpoint-security-migration.md` | historical (pins); fixed note | See 4.2. |
| `release12-remaining-requirements-2026-10-29.md` | superseded in part; fixed note | Forward link and status table. |
| `release12-postmerge-qualification-2026-11-04.md` | already-fixed `6646b9e`; fixed link | Readback covers #92 and #31. |
| `adr/loaded-deployment-identity.md` | already-fixed `6646b9e` | See 4.2. |
| `COMPATIBILITY_REVIEW_2026-10-09.md` | historical | See M-11. Not edited because the drift guard pins its bytes. |
| `e1-c2-consumer-slice2.md` | superseded in part; fixed note | Points to execution witnesses, the R3 synthesis handoff and the current handoff. |
| `e1-t3-effect-seam-1.md` | historical; fixed note | Its `governed` limit is still live. |
| `release12-process-crash-evidence.md` | historical; fixed note | Gate list now tracked as R1–R8. |
| `release12-review-fixes-2026-10-26.md` | historical; fixed note | It had no status header before this note. |
| `superpowers/plans/` (×2) | historical; fixed notes | Unchecked boxes are not task state. |
| `v2/71`, `v2/72` | superseded by orama-system `main`; fixed notes | Pointer notes to the canonical copies. The local bodies are kept rather than converted to link-only stubs, so preserved text is not deleted. Reconciling 70–72 remains in orama-system C1. |
| `plans/references/local-workspace-roadmap-2.md` | historical; fixed note | Core at `6d75cfe` has no receipt module. The workspace receipt and verifier live in `src/orama/workspace/`. |
| `README.md` pins (:50) | fixed | Core, Telos and Agate base pins, plus Phylax via the `grant-serving` extra. |
| `README.md` layout (:18-26) | fixed | Adds `compat/`, `deploy/`, `discovery/`, `workspace/`, `config/`, `docs/`, `requirements/` and `tests/oracles/`. |
| `README.md` Claude-Desktop-LLM owner | fixed | Named as the injected `ClaudeProviderPort` (`src/orama/gateway/contracts.py`), not a constellation authority. |
| `README.md` "future concrete provider invoker" (found during closure) | fixed | Now names the dark `GuardedForeignInvoker` and links its contract. |

## Open and owner-held items

- **D6 activation record:** operator, C11. No record exists.
- **R4/R5 host evidence on POSIX and native Windows:** operator with tooling owner, C7/C8.
- **Independent R6:** reviewer, C9.
- **R7 generation/pin decision:** operator, C10.
- **R8 activation:** operator, C11.
- **`governed` default:** runtime owner. Code is unchanged here.
- **Controller:** partially implemented and not wired or deployed. C3d remains open for operator review and acceptance of the exact final SHA, legacy-job disposition, rollback and runbook acceptance, and contract review; real adapters and serving composition remain outside this slice.
- **Future policy backlog:** make an independent reviewer configurable, defaulting to operator-only review. This does not change doc 68 or runtime policy in this closure.
