# R3 reference index: production approval verifier and revocation view

Every link below is pinned to a commit, so it shows what was read and will not drift. IDs such as
`S3` are used by [`02-OPTIONS-DRAFT.md`](02-OPTIONS-DRAFT.md).

| Repo | Pinned commit (`origin/main` on 2026-11-02) |
| --- | --- |
| `oramasys/oramasys` | `40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d` |
| `oramasys/phylax` | `cf3a300c6d39092ab64df54f0d1ab3fea3db3c38` |
| `diazMelgarejo/orama-system` | `95fe5f88ba14f9171f6197164e4b2e29291c2b18` |
| `diazMelgarejo/Perpetua-Tools` | `403d904f2001360129d50479a94487a0419346c3` |

All four repos are public. A build step checked that every file, line anchor and pull request
below exists. The review depth is stated per section. Quote a line only after you have re-found it
at the pinned commit.

**Depth key.** **Read**: the relevant part was read in full. **Skimmed**: keyword search plus the
matching lines. **Cited**: confirmed to exist, not read; its note comes from its title or from another document.

## Corrections to the earlier list

1. The E1 freeze and the C2 Part 1 and Part 2 files still say `DRAFT` or `PROPOSED` in their own
   headers. They are **ratified**: see S10, which amends their status. Read their headers with that
   in mind.
2. The earlier list said Phylax's only document was `BOUNDARIES.md`. That came from a local checkout
   149 commits behind. `origin/main` has three more relevant documents: section 2 below.
3. The earlier list said no document names a production approval authority. More exactly: the
   documents name **Phylax** as the owner and **P5** as the mechanism (S2, S4, F13). None of them
   specifies the consumer-side adapter. That is the gap the draft addresses.

## 1. Consumer code (`oramasys`)

| ID | Link | Why it matters | Depth | See also |
| --- | --- | --- | --- | --- |
| C1 | [`ApprovalVerifier` port](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/final_boundary.py#L72) | `verify(binding) -> bool`, the port to fill | Read | C3, O1 |
| C2 | [`RevocationLookup` port](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/final_boundary.py#L79) | `revoked(grant_id, issuer_id) -> bool` | Read | C5, C6 |
| C3 | [`FinalBoundaryBinding`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/final_boundary.py#L46) | The exact tuple approval binds to | Read | S1 |
| C4 | [`authorize_final_boundary`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/final_boundary.py#L168) | Check order; anything but a strict `True` or `False` refuses | Read | S4 |
| C5 | [`RevocationPort` contract](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_attempts.py#L154) | MUST also cover approval chain and issuer | Read | L1, S5 |
| C6 | [`refusal_reason`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_revocations.py#L69) | The local Rule 4 check on acknowledged events | Read | S5, P4 |
| C7 | [`ingest_events`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_attempts.py#L933) | Verifies and records issuer events; see draft finding 4 | Read | P4 |
| C8 | [`FinalBoundaryPorts`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/effect_grant_composition.py#L157) | The three values a composition root must supply | Read | C9 |
| C9 | [`serve_with_effect_grants.py`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/scripts/serve_with_effect_grants.py) | Composition root, and why no sender is wired | Read | S3, C10 |
| C10 | [`OperatorSignatureVerifier`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/api/capabilities.py#L68) | The third missing port | Read | F6, S3 |
| C11 | [`test_final_boundary.py`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/tests/test_final_boundary.py) | Current test doubles for both ports | Skimmed | O1 |

## 2. Phylax producer code and docs

| ID | Link | Why it matters | Depth | See also |
| --- | --- | --- | --- | --- |
| F1 | [`P5ApprovalAuthority`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/p5_approval.py#L523) | Requires `signing_key`; receipts use [HMAC](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/p5_approval.py#L637) | Read | S2, L3 |
| F2 | [`EffectGrantAuthority.issue`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/effect_grant.py#L308) | Runs P5, signs "one human-approved, single-use effect grant" | Read | F1, S1 |
| F3 | [`verify_finalization`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/dispatch_wire.py#L429) | Public-key check, pure, no I/O | Skimmed | F4, S5 |
| F4 | [Permit and finalization fields](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/dispatch_wire.py#L75) | What the issuer signs about an attempt | Read | S5, F9 |
| F5 | [`RevocationObservation`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/adjustment_grant.py#L120) | Per-grant only: no approval or issuer field | Read | C5 |
| F6 | [`revocation_freshness`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/verifier_surface.py#L271) | The time it reports is the read time; see draft finding 5 | Read | O3 |
| F7 | [`capability_record.py`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/capability_record.py#L165) | Refuses every enablement in R0-2 | Read | S3, C10 |
| F8 | [`open_effect_grant_verifier`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/grant_composition.py#L283) | Verify-only opener; "seeds and P5 stay unreachable" | Read | S2 |
| F9 | [`e1-c2-permit-contract-freeze.md`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/e1-c2-permit-contract-freeze.md) | Frozen wire behaviour | Skimmed | S5 |
| F10 | [`trusted-composition-boundary.md`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/trusted-composition-boundary.md) | Lists what is still unbuilt, including `GrantFacts` and operator-authority adapters | Read | Draft A |
| F11 | [`model-launch-approval.md`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/model-launch-approval.md) | How human evidence plugs into P5 for model launches | Read (opening) | F12, L5 |
| F12 | [`GitHubCliModelApprovalVerifier`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/github_device_approval.py#L387) | The only built human-evidence verifier | Skimmed | L5 |
| F13 | [`BOUNDARIES.md`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/BOUNDARIES.md) | What Phylax owns | Read (opening) | S2 |
| F14 | [`dispatch-permit-v1.json`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/vectors/dispatch-permit-v1.json) and [`dispatch-events-v1.json`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/vectors/dispatch-events-v1.json) | Byte-exact conformance vectors | Cited | F9 |

## 3. Oramasys requirements and decisions

| ID | Link | Why it matters | Depth | See also |
| --- | --- | --- | --- | --- |
| O1 | [`release12-remaining-requirements`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/release12-remaining-requirements-2026-10-29.md) | The R3 requirement and the R6 review scope | Read (table) | C1, S3 |
| O2 | [`release12-review-fixes`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/release12-review-fixes-2026-10-26.md) | States that no operator signature verifier is wired | Skimmed | C10 |
| O3 | [ADR 71 (Level 1 gate)](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/v2/71-operator-provisioning-and-autonomous-tier-adr.md#L67) | 60-second freshness; "signed public state publication" | Read (section) | F6 |
| O4 | [Plan 72](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/v2/72-task6-operator-provisioning-and-autonomous-tier-plan.md) | Human issuer path; same-user limits | Read (sections) | S2 |
| O5 | [`e1-c2-consumer-slice2.md`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/e1-c2-consumer-slice2.md) | What shipped for revocation and cascade events | Skimmed | P4 |
| O6 | [`release12-process-crash-evidence.md`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/release12-process-crash-evidence.md) | Ordering for revocation and finalization | Skimmed | S4 |

## 4. orama-system contracts and plans

Paths marked R4 are in `docs/v2/references/r4-safety-compatibility-platform-2026-10-10/`.

| ID | Link | Why it matters | Depth | See also |
| --- | --- | --- | --- | --- |
| S1 | [Durable HITL effects contract](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/CONTRACT-DURABLE-HITL-EFFECTS.md) (R4) | The six-step protocol. "No UI Boolean" is a grant | Read | S5, C3 |
| S2 | [E1 authority, state, effect freeze](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-AUTHORITY-STATE-EFFECT-FREEZE-DRAFT-2026-10-15.md) (R4) | Role table; serving is verifier-only | Read (sections 2.x) | F8, S10 |
| S3 | [R0-R2 contract freeze](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r0-r2-contract-freeze-2026-10-26.md) | "No signing path exists" in Releases 0 to 2; approval binding | Read (sections) | F7 |
| S4 | [Activation and T3-T5 plan](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/ACTIVATION-SERVING-T3-T5-REMOTE-AUTONOMY-PLAN-2026-10-25.md#L151) | Owner map; HITL per attempt; T3 gate | Read (section) | D1 in draft |
| S5 | [C2 Part 2: permit wire and roles](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-C2-PERMIT-WIRE-AND-ROLE-RECONCILIATION-2026-10-18.md) (R4) | Rule 4; finalization orders revocation | Skimmed | C6 |
| S6 | [Release 1-2 implementation round](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/RELEASE12-IMPLEMENTATION-ROUND-2026-10-26.md) | Lists authenticated approval as open | Skimmed | O1 |
| S7 | [C2 Part 1: purpose, version, refusals](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-C2-PURPOSE-VERSION-AND-REFUSAL-CONTRACT-2026-10-18.md) (R4) | 19-field grant, refusal vocabulary | Cited | S10 |
| S8 | [Part 3 schema amendment](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-C2-INTEGRATED-SCHEMA-PART3-AMENDMENT-2026-10-19.md) (R4) | Integrated schema | Cited | S9 |
| S9 | [Part 3 ratification packet](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-C2-PART3-RATIFICATION-ACCEPTANCE-PACKET-2026-10-22.md) and [acceptance matrix](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-C2-PART3-S12-ACCEPTANCE-MATRIX-2026-10-24.md) (R4) | Acceptance criteria | Cited | P1 |
| S10 | [E1 ratification addendum](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/2026-10-19-e1-specification-ratification-addendum.md) (R4) | Makes S2, S5 and S7 ratified | Read (opening) | S2 |
| S11 | [ADR D-LG-7](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/ADR-D-LG-7-R4-SAFETY-COMPATIBILITY-PLATFORM.md) and [R4 execution plan](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/PLAN-R4-EXECUTION.md) (R4) | Governing decision and T3 slice | Cited | S1 |
| S12 | [C1 source recovery and test map](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/r4-safety-compatibility-platform-2026-10-10/E1-C1-SOURCE-RECOVERY-AND-TEST-MAP-2026-10-18.md) (R4) | Spec-to-test map | Cited | S2 |
| S13 | [Compatibility refusal and HITL contract](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/2026-10-09-compatibility-refusal-hitl-contract.md) | The base contract S1 builds on | Cited | S1 |
| S14 | [Human-grant security gap research](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/bin/orama-system/references/pr-body-human-grant-security-gap-research.md) | Passkey and other options; verify at the final boundary | Skimmed | S15 |
| S15 | [Security sentinel passkey orbit](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/51-security-sentinel-orbit-passkey-mcp.md) and [grant remediation plan](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/plans/2026-08-02-pr-body-grant-security-remediation.md) | Passkey deferred to v2.1 | Cited | D2 in draft |
| S16 | [M1 qualification evidence receipt](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/m1-qualification-evidence-receipt-2026-10-17.md) | Earlier "approval verifier" check | Skimmed | L5 |
| S17 | [Activation readiness baseline](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/activation-readiness-baseline-2026-10-26.md) | Context only; no approval or revocation text | Skimmed | S4 |
| S18 | Older P5 plans: [decisions](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/plans/P5-DECISIONS-LOCKED.md), [status](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/plans/P5-STATUS.md), [security PR3](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/plans/2026-06-28-security-pr3-p5-swarm-approval-execution-plan.md), [P5/P6 plan](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/plans/2026-07-26-p5-p6-lan-discovery-swarm-approval-plan.md) | v1 swarm approval, the origin of P5 | Cited | F1 |
| S19 | [Human-in-the-loop accountability](https://github.com/diazMelgarejo/orama-system/blob/95fe5f88ba14f9171f6197164e4b2e29291c2b18/docs/v2/references/HUMAN-IN-LOOP-ACCOUNTABILITY.md) | Accountability statement | Cited | S1 |

## 5. Perpetua-Tools memory and plans

PT memory is the running record of how these decisions were reached. Lessons are one line each; a
link opens the exact line at the pinned commit. `recall.py` is keyword-based, so the lessons were
also collected by direct search.

### Lessons

| ID | Lesson | Point | Status |
| --- | --- | --- | --- |
| L1 | [`lesson_3a8f4e9f0578`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L154) | Check each injected port can express every path a rule names, including approval-chain and issuer revocation | Accepted |
| L2 | [`lesson_a8b6683ca75a`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L214) | A bearer credential identifies a proxy, not a human; human gates need out-of-band P5 evidence | Accepted |
| L3 | [`lesson_34a8f3b70323`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L213) | No ad-hoc token ledgers; map to P5 intents consumed atomically | Accepted |
| L4 | [`lesson_bcd29ba0e6d7`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L212) | Keep the approval-receipt lifetime separate from the execution-authority lifetime | Accepted |
| L5 | [`lesson_bf09dab5d7ee`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L98) | The GitHub device ceremony is procedural evidence, not an attested MFA event; agents never do the human login | Accepted |
| L6 | [`lesson_45ef3722b361`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L216) | Phylax stays the fail-closed authority for human evidence and receipt single use | Accepted |
| L7 | [`lesson_f2ab09025493`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L231) | A policy helper never grants an exception; the trusted dispatcher spends one receipt | Provisional |
| L8 | [`lesson_088401dddd92`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L241) | A green groundwork suite is not release qualification | Provisional |
| L9 | [`lesson_566fea39bb3e`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L30) | Approval to build something is not a durable authorization grant | Accepted |
| L10 | [`lesson_446162929cb3`](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/LESSONS.md#L448) | Same-user secrets raise effort but do not prove a human | Accepted |

### Handoffs, chronicles and plans

| ID | Link | Why it matters | Depth |
| --- | --- | --- | --- |
| P1 | [Release 1-2 qualification handoff](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/working/RELEASE12_SERVING_EFFECTS_QUALIFICATION_HANDOFF_2026-10-26.md) | The four open gates, and the next slice | Read |
| P2 | [E1C2 closeout, handoff lanes, takeover](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/SESSION_CHRONICLE_2026-10-25_E1C2_CLOSEOUT_HANDOFF_LANES_AND_TAKEOVER.md) | Closeout and takeover record | Cited |
| P3 | [E1C2 schema review chronicle](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/E1_C2_SCHEMA_REVIEW_AND_MULTIAGENT_COORDINATION_CHRONICLE_2026-10-20.md) and [five-day chronicle](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/E1_C2_CLAUDE_FIVE_DAY_CHRONICLE_2026-10-20.md) | Schema review history | Cited |
| P4 | [Part 3 consumer floor and event bodies](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/SESSION_CHRONICLE_2026-10-22_TO_2026-10-24_PART3_CONSUMER_FLOOR_EVENT_BODIES_AND_REVIEW_REMEDIATION.md) | Event body shapes, and the `approval_ref` finding | Skimmed |
| P5 | [Review follow-ups and stacked merges](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/SESSION_CHRONICLE_2026-10-24_REVIEW_FOLLOWUPS_STACKED_MERGES_AND_CONFLICT_RESOLUTION.md) | Review and merge history | Cited |
| P6 | [Fast-exception gate and next steps](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/semantic/SESSION_CHRONICLE_2026-10-25_FAST_EXCEPTION_GATE_PARITY_AND_NEXT_STEPS.md) | Fast-exception gate history | Cited |
| P7 | [E1C2 48-hour chronicle and signature legend](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/working/E1_C2_48H_CHRONICLE_AND_SIGNATURE_LEGEND_2026-10-22.md) | Signature legend | Cited |
| P8 | [Antigravity ratification reconciliation](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/working/ANTIGRAVITY_RATIFICATION_RECONCILIATION_CHRONICLE_2026-10-23.md) and [five uploads reconciliation](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/working/LOCKSTEP_FIVE_UPLOADS_AND_GOVERNANCE_RECONCILIATION_2026-10-22.md) | Ratification history | Cited |
| P9 | [Clean rollback and preflight chronicle](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/.agent/memory/working/2026-10-19-clean-rollback-and-preflight-chronicle.md) | Earlier rollback context | Cited |
| P10 | [MiniGraph compatibility evidence plan](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/docs/plans/2026-10-09-minigraph-compatibility-evidence-plan.md#L140) | Resolved HITL policy | Skimmed |
| P11 | [Phase 0 and orama closure plan](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/docs/references/phase0-and-orama-open-work-closure-plan-2026-07-18.md#L45) | Why a client approval boolean was retired | Skimmed |
| P12 | [ADR-003 security foundation](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/docs/adr/ADR-003-maestro-owasp-v2-security-foundation.md) | Operator approval for tool-definition changes | Skimmed |
| P13 | [Agent handoff template](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/docs/coordination/agent-handoff-template.md) and [handoff packet example](https://github.com/diazMelgarejo/Perpetua-Tools/blob/403d904f2001360129d50479a94487a0419346c3/docs/coordination/examples/handoff-packet-v1.json) | The board's dispatch format | Cited |

Checked and left out: PT's `MULTIAGENT-SWARM-SECURITY-ANALYSIS.md` and the state-transition-manager
plans matched only on keywords. They have no approval or revocation design content for this work.

## 6. Pull requests

Cited by the documents above. State is what GitHub reported at build time. These were not reviewed
for this index.

[phylax #6](https://github.com/oramasys/phylax/pull/6) (merged), [phylax #7](https://github.com/oramasys/phylax/pull/7) (merged), [phylax #10](https://github.com/oramasys/phylax/pull/10) (merged), [phylax #11](https://github.com/oramasys/phylax/pull/11) (merged),
[phylax #19](https://github.com/oramasys/phylax/pull/19) (merged), [oramasys #32](https://github.com/oramasys/oramasys/pull/32) (merged), [oramasys #33](https://github.com/oramasys/oramasys/pull/33) (merged),
[oramasys #74](https://github.com/oramasys/oramasys/pull/74) (merged), [oramasys #75](https://github.com/oramasys/oramasys/pull/75) (merged), [orama-system #423](https://github.com/diazMelgarejo/orama-system/pull/423) (merged),
[orama-system #436](https://github.com/diazMelgarejo/orama-system/pull/436) (merged)

## 7. What could not be found

- `PHYLAX-ADJUSTMENT-GRANT-DESIGN-v2.md`: [Plan 72](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/v2/72-task6-operator-provisioning-and-autonomous-tier-plan.md)
  says this source design is not published in any oramasys repository.
- Any document that specifies the consumer-side `ApprovalVerifier` implementation.
- Any document that says how issuer events reach a deployed consumer.
