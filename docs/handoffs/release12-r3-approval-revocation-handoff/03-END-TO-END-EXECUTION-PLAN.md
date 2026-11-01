# Release 1–2 R3 through qualification: end-to-end execution plan

Date: 2026-11-02, Asia/Manila. UTC is primary for evidence timestamps.

> For agentic workers: execute task by task using the executing-plans workflow. Checkboxes represent future work unless explicitly marked verified. This document records recommendations; it does not record human approval of D1–D4.

**Goal:** finish authenticated approval and revocation composition, prove deployment isolation and installed identity, obtain independent review, and prepare the operator-controlled production repin and activation decisions.

**Architecture:** Phylax owns human evidence, issuance and public verification. Oramasys adapts public verification into existing final-boundary ports and consumes authority transactionally. Serving stays seed-free; issuer/network calls stay outside the dispatch transaction. The current R0–2 freeze remains effective until separately amended.

**Tech stack:** existing Python, SQLite, public-key grant/permit/finalization verification, existing P5 issuance and consumer ports. No second scheduler, approval ledger or effect state machine.

**Spec:** [source handoff](https://github.com/oramasys/oramasys/blob/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff/README.md), [options and decisions](https://github.com/oramasys/oramasys/blob/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff/02-OPTIONS-DRAFT.md), [pinned reference index](https://github.com/oramasys/oramasys/blob/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff/01-REFERENCE-INDEX.md), [R1–R8 requirements](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/docs/release12-remaining-requirements-2026-10-29.md).

## 1. Verified starting point and completion boundary

| Repository | Live main verified in this session | Meaning |
| --- | --- | --- |
| oramasys/oramasys | 40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d | Includes merge of #84; production approval/revocation ports remain unwired in the inspected composition root |
| oramasys/phylax | cf3a300c6d39092ab64df54f0d1ab3fea3db3c38 | Matches the handoff's producer reference |
| diazMelgarejo/orama-system | 95fe5f88ba14f9171f6197164e4b2e29291c2b18 | Matches canonical contract reference |
| diazMelgarejo/Perpetua-Tools | 403d904f2001360129d50479a94487a0419346c3 | Matches memory reference |
| Download branch | 22cdfa87a28c24d77a22cf0642464794c0e21cdb | Original handoff commit, parent is the verified Oramasys main |

All four live heads match the supplied reference index. This session read the three handoff documents, current remaining-requirements document, final-boundary implementation, composition root, and relevant attempt-store sections. This is a planning review, not a rerun of the reported qualification suites.

The source ZIP exists as a 13,263-byte GitHub object, Git blob SHA 12bb1b76b808c07dd39f7f324e2778e9b3daa163. Its binary contents were not downloaded or unpacked here. The Markdown plan is published separately so a ZIP is not required to read or save it.

**Finished by this deliverable:** consolidated plan, source links, exact baseline, decision register, ordered tasks, acceptance criteria, rollback and agent handoff.

**Still required for actual release completion:** recorded authority choices, recovery of the operator-held patch, implementation and tests, deployment identity evidence, independent review, ratified new-generation repin, and any separate activation. No implementation or deployment is represented as complete by this document.

## 2. Global constraints

- ORAMA_GRANT_SERVING stays unset throughout this implementation/qualification round.
- No real effects, live grant issuance or provider calls follow from a successful test.
- Keep Phylax imports outside src/orama; composition adapters belong at the composition boundary.
- No seeds, P5 HMAC/signing secrets or issuer-write permissions in serving.
- Preserve the frozen wires, public refusal vocabulary and existing unknown-outcome behavior.
- Do not edit accepted generations. Repinning requires a new generation and operator ratification.
- No human login or approval comment by an agent. A shared bearer identifies a proxy, not a human.
- Commit logical batches; one final non-force publication per branch in a review cycle. No hook bypasses.
- The download-only branch is not an implementation branch and must not be merged as a release.
- Re-read current repository instructions before implementation; no root AGENTS.md was returned at the inspected Oramasys head.
- Never turn historical CI reports into claims that this session ran tests.

## 3. Ranked findings and design improvements

1. **Blocking authority ambiguity:** recommended option A proves a human-approved operation followed by issuer-bound attempt authority. It does not itself prove that the human approved the concrete final attempt tuple. D1 must explicitly resolve this for inert simulation; real effects require a separately ratified attempt-specific mechanism.
2. **Blocking freshness ambiguity:** reading a copied public database now is not evidence the issuer published it recently. A usable revocation view needs authenticated publication time/counter, scope and completeness evidence, not merely a successful local read or last-success timestamp.
3. **Blocking implementation dependency:** the handoff says R2, R3 cells and an R5(b) script are in an operator-held patch absent from the package. Recover and compare that patch before changing overlapping composition-root tests. Do not infer that the patch is on main.
4. **Signed-chain option needs durable inputs:** the inspected attempt schema stores permit/finalization digests and counters, while storing grant wire separately. Do not implement re-verification by treating digests as signed bodies. Determine and preserve the complete signed chain, or reject option A as currently implementable.
5. **Finalization counter is not a general freshness proof:** R_f orders issuer events under the frozen rules. It does not establish the absence of later revocations during a disconnected interval. Do not simplify Combined based on that unproven assumption.
6. **Freeze deliberately prevents a live sender:** real approval/revocation ports alone cannot make effects effective. The inspected root states “this repository wires no signature verifier.” Qualify ports without fabricating a capability signature or enabling a sender.
7. **Existing error semantics have operational consequences:** the final boundary currently converts an unavailable revocation/approval verifier into a terminal pre-dispatch refusal. Tests and operations must reflect that. Changing it into a retryable refusal requires contract review, not an adapter-local workaround.

## 4. Decisions to record before production code

“Finish all” directs completion of the workflow; it does not specify which human-approval semantics or deployment trust model to adopt. The following are concrete recommendations for operator selection.

| Decision | Recommended disposition | Exact limit and evidence needed |
| --- | --- | --- |
| D1 — approval granularity | Option A for inert.simulation only, subject to a documented contract interpretation | Human approves exact operation facts; issuer signs the bound attempt chain. No extension to real effects. If S4 cannot permit that interpretation, freeze option B's public-key attempt receipt first |
| D2 — human evidence | Extend existing GitHub device ceremony at issuance | Verify authenticated actor, exact intent/payload, freshness, immutability and single use through Phylax. Procedural evidence only; never claim attested MFA |
| D3 — revocation authority | Signed public-state publication plus authenticated event catch-up | Complete grant/approval-chain/issuer/cascade coverage; issuer-bound sequence and publication time; rollback/fork/gap detection and explicit expiry |
| D4 — enablement scope | Preserve R0–2 freeze | R3 real-port qualification remains test-only. A future effects-capability signing path needs its own reviewed contract and operator activation |

Record for each decision: ID, selected alternative, exact effect class and deployment scope, governing contract revision, rationale, operator identity/evidence reference and UTC timestamp. Never prefill an approval as if the operator signed it.

If any decision remains unresolved, proceed with WP0 evidence reconciliation and proposal refinement only. This plan neither asks agents to invent authority nor instructs them to discard the current contract.

## 5. WP0 answers and remaining investigations

| Question | Evidence from this session | Required closure |
| --- | --- | --- |
| Signed permit/finalization storage? | dispatch_attempts.py schema contains permit_digest, finalization_digest, r_p and r_f; effect_grant_bindings retains grant_wire and context | Trace every write and read of the permit/finalization chain; find another durable source or propose additive retention. Absence elsewhere was not proven |
| Does inert dispatch use permits/finalization? | authorize_dispatch accepts both wires and performs transactional authorization; root composes FinalBoundarySender and SealedInertDriver | Trace the complete actual producer-to-consumer path using real signatures, not a test helper alone |
| request_digest equals operation_digest? | Final boundary normalizes optional sha256: prefixes when comparing stored operation digests; authorization cross-checks request_digest against stored grant context | Document byte-level canonicalization and semantic equivalence across the full chain; add mismatch vectors. Normalization alone does not prove equivalence |
| Production permit/finalization/catch-up clients? | The source draft reports none; this session did not complete an exhaustive caller audit | Trace call sites across source, scripts, adapters and operator-held patch; report exact paths or verified absence |
| Must serving read a copy? | Same-user/public-state and isolation limits are documented; root opens existing public verifier state | Select deployment identity and publication topology under D3. Test real access; do not infer a shared/copy model from file names |
| Does R_f bound staleness? | No proof established here | Reconcile frozen ordering rules and adversarial offline timeline; retain freshness checks until a reviewed proof permits otherwise |

## 6. File and interface map

Existing contracts to reuse:

- [final_boundary.py](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/final_boundary.py): ApprovalVerifier.verify(binding: FinalBoundaryBinding) -> bool; RevocationLookup.revoked(*, grant_id: str, issuer_id: str) -> bool.
- [dispatch_attempts.py](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_attempts.py): durable attempt facts, signature checks, ingest_events, atomic authorization/send boundary.
- [dispatch_revocations.py](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_revocations.py): acknowledged issuer/grant/approval-chain/cascade interpretation.
- [effect_grant_composition.py](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/effect_grant_composition.py): trusted grant verification, binding and canonical sender.
- [serve_with_effect_grants.py](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/scripts/serve_with_effect_grants.py): composition ownership and resource lifecycle.
- [capabilities.py](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/api/capabilities.py): independent capability gate.
- [Phylax effect_grant.py](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/effect_grant.py) and [verifier_surface.py](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/verifier_surface.py): producer verification and current freshness limitations.

Proposed additions, names to freeze after patch reconciliation: Phylax effect-human-evidence verifier and signed public-state publisher/reader; Oramasys composition-level public approval/revocation adapters and event catch-up worker. Place these outside src/orama when they import Phylax. Freeze their exact files and method signatures in the contract PR before parallel implementation; do not guess them from the filenames proposed here.

## 7. Ordered execution work packages

### WP0 — Reconcile baseline, patch and authority

Owner: lead implementer plus operator for patch/decisions.

- [ ] Fetch the four heads and compare against section 1; write an additive successor receipt if they moved.
- [ ] Obtain the unpublished R2/R3/R5(b) patch from its actual owner; retain original bytes and hash.
- [ ] Check patch applicability in an isolated worktree; inspect every changed file, preserve unique work and do not apply it blindly.
- [ ] Answer the six questions in section 5 with immutable source citations and short quoted excerpts.
- [ ] Record D1–D4 and freeze the exact adapter/publication contracts and file map.
- [ ] Produce a scope/dependency receipt. Exit only when ambiguity about production authority and overlapping patch ownership is resolved.

### WP1 — Phylax human evidence at effect issuance

Depends on D2 and WP0. Reuse P5 and model-launch ceremony verification; do not copy a parallel receipt ledger.

- [ ] Write failing tests: arbitrary reference refuses; wrong actor/payload refuses; edited/expired/replayed evidence refuses; valid evidence binds one exact supported operation.
- [ ] Run focused tests and capture expected failing assertions.
- [ ] Implement the evidence adapter at issuance, with preview/approval/consumption and grant issuance preserving the existing transactional guarantees.
- [ ] Test crash/retry around evidence consumption and grant persistence; one evidence use must not mint two authorities.
- [ ] Test that serving imports/openers cannot reach this issuer-only code or its secrets.
- [ ] Run affected producer tests, then commit one coherent issuance-evidence batch.

Output: reviewed issuer-side evidence contract and real signed synthetic grant fixtures. A GitHub account ceremony is not a substitute for an attested human identity claim.

### WP2 — Authenticated public revocation publication

Depends on D3. Producer owner: Phylax; publication deployment owner: operator.

- [ ] Freeze publisher identity, issuer/key scope, sequence/counter, issued-at/expiry, state digest, completeness boundary and signature domain. Reuse ratified formats where sufficient.
- [ ] Pin freshness limits to the applicable reviewed contract. ADR 71's Level 1 60-second bound must not be silently generalized to every deployment tier.
- [ ] Write failing tests for never-published state, old signed state read now, rollback, fork, missing range, wrong issuer/key, expiry, backward clock and replay.
- [ ] Implement signed publication and public-only verification; publishers write atomically and readers retain monotonic checkpoints.
- [ ] Prove an old copy cannot become fresh through a new local read.
- [ ] Commit publisher/reader and conformance tests. Do not create a live publisher account or signing key from this step.

### WP3 — Consumer event catch-up and durable freshness

Depends on WP2's frozen wire. Owner: Oramasys composition layer.

- [ ] Freeze the event transport/catch-up contract, endpoint policy, cursor persistence and resource lifecycle.
- [ ] Write failing tests for a feed that never ran, disconnect, missing events, reordered duplicates, changed duplicate digest and partial crash.
- [ ] Verify signed events and call existing ingest_events; persist progress only with verified accepted state.
- [ ] Establish currency from issuer-authenticated scope/watermark and signed publication, not last successful polling alone.
- [ ] Keep network work outside the dispatch transaction. Supply a bounded local read view at dispatch.
- [ ] Test catch-up across restart and cursor/write crash boundaries; commit worker plus evidence tests.

### WP4 — Revocation port with complete coverage

Depends on WP2/WP3. Preserve current port shape unless the contract review proves it cannot express a required refusal.

- [ ] Test grant, issuer, approval-chain and cascade revocation separately.
- [ ] Test never-initialized, stale, inconsistent and unavailable views: raise rather than return False.
- [ ] Implement Combined policy: any authoritative revoked result denies; only a complete current authenticated view can answer exactly False.
- [ ] Test non-boolean outputs and exceptions at the real final boundary.
- [ ] Ensure cache/snapshot generation is revalidated at the send boundary; define the revocation linearization point against issuer ordering.
- [ ] Commit adapter and refusal tests. Preserve unknown after a send marker.

### WP5 — Public-key approval adapter

Depends on D1, WP1 and signed-chain retention closure from WP0.

- [ ] Test changed attempt ID, principal, operation digest, target, fencing epoch and expiry; every substitution refuses.
- [ ] Verify actual grant/permit/finalization signatures with trusted public keys and bind all signed facts to durable store facts.
- [ ] Persist missing signed inputs additively where required. Historical rows without proof refuse; never synthesize authority from a digest.
- [ ] Recheck grant expiry/revocation, issuer identity, lease epoch and fencing epoch with their existing distinct meanings.
- [ ] Test unknown/rotated keys, expired grants, wrong class, crash/reopen, duplicate send and a compromised caller supplying a plain value object.
- [ ] Keep the adapter read-only and Phylax-free inside src/orama; commit adapter/storage migration and tests together.

If D1 selects per-attempt human approval, stop option A work and first ratify option B's receipt wire, issuer boundary, lifetime and single-use transaction. Do not weaken the concrete-binding requirement to make A pass.

### WP6 — Real-port R3 matrix and lifecycle

Depends on WP4/WP5 and recovered patch. Owner: Oramasys.

- [ ] Add real public producer verification to the R3 test cells; distinguish test-only capability authority from production authority.
- [ ] Assert disabled, malformed, stale or unsigned capability keeps effects dark; missing any required final-boundary port refuses startup.
- [ ] Test true boolean gates, lease/fence separation, principal checks, unavailable verifier and exact public refusal bodies.
- [ ] Exercise the full synthetic signed chain through final boundary, one inert send, receipt persistence and restart.
- [ ] Inject process death before authorization commit, after authorization, before/after send-marker commit, during settlement and after durable receipt before publication.
- [ ] Prove exactly one send winner under concurrent processes, preserved unknown and refusal of automatic retry.
- [ ] Run focused cells and the complete affected suites on the required Python matrix with no omitted effect modules.
- [ ] Commit cohesive code/test batches; publish final reviewed branch once after local checks. No production capability activation.

### WP7 — R4/R5 deployment qualification

Operator performs host actions; implementer prepares reviewed commands and receipts.

- [ ] Select deployment host, actual service identity, public-state topology, provisioned paths and policy scope.
- [ ] Run qualify_serving_identity.py under the actual non-root serving identity against existing state; require real seed-read and issuer/public-write denials.
- [ ] For Windows, produce an equivalent effective ACL/access proof; POSIX UID/mode results are not portable isolation evidence.
- [ ] Run verify_installed_identity.py and verify_phylax_pin.py in the installed environment outside the source checkout.
- [ ] Define and review R5(b)'s configuration/policy digest receipt, reconciling the operator-held script. Record canonical file bytes and references without secrets or host-specific sensitive contents.
- [ ] Bind wheel hashes, source commits, import locations, producer URLs/pins, configuration/policy digests, publication freshness policy and service identity evidence to one receipt.
- [ ] Re-run after any relevant binary, policy, identity or configuration change. CI and same-user subprocesses cannot close R4/R5.

### WP8 — R6 independent review and R7 promotion preparation

- [ ] Assign a security reviewer who wrote none of the implementation. Same-session or same-model agreement is not independent review evidence.
- [ ] Review stale producer/consumer, omitted tests, forged or replayed approval, stale publication, modified frozen generations and overstated qualification.
- [ ] Fix supported findings, rerun affected checks and record final immutable candidate SHAs.
- [ ] Prepare a NEW generation folder and expected-generation tests. Keep accepted generation bytes unchanged.
- [ ] Prepare production pyproject.toml Phylax pin and compatibility-phylax-verify-only.txt together, following R7 conditions.
- [ ] Qualify the complete candidate set. Operator ratifies/merges producer before consumer; repin to actual merge SHAs and rerun post-merge qualification.
- [ ] Publish a dated successor receipt and sanitized PT memory through existing writers; preserve append-only history and supersession links.

### WP9 — R8 separate activation and downstream roadmap

- [ ] Operator names capability, exact effect class, deployment, approved artifact/config/policy identities, review/expiry date and disablement control.
- [ ] If activation would amend the R0–2 freeze, ratify that amendment first.
- [ ] Start with one approved inert cell and bounded canary, using the tested emergency stop.
- [ ] Verify actual receipts and current public-state freshness; disable on isolation, freshness, authority or audit failure.
- [ ] T4 provider transport, T5 continuation and C4 autonomy each require their own contract, test matrix and operator decision. This R3 plan does not enable them.

## 8. Review focus: five frequently missed cases

| Failure mode | Expected behavior | Owner/tests |
| --- | --- | --- |
| Old public-state copy read successfully now | Currency fails; no send | WP2/WP4 |
| Crash between evidence use and authority persistence | No second authority through retry | WP1 |
| Historical attempt lacks signed bodies | Refuse; no backfilled proof | WP5 |
| Valid issuer chain but changed attempt tuple | Refuse substitution | WP5/WP6 |
| Revocation races marker commit or result settlement | Apply frozen ordering; retain unknown if send may have started | WP4/WP6 |

## 9. Evidence, PR shape and rollback

Each receipt records: repository, branch/PR, full head/base/merge SHA, producer pin, wire/registry/manifest/config/policy digests, test command and interpreter, result count, skips and justification, review identity, and remaining limits. Unknown or unperformed items stay explicitly unknown.

Use one coordinated implementation PR per affected repository for the agreed round, with logical local commits. Check current open work first and obtain the operator's round-specific instruction before replacing or expanding an existing PR's scope. This document's download publication is one additive update to the explicitly supplied throwaway branch; it does not create an implementation PR.

Rollback disables new capability composition and issuance under the operator's deployment procedure. Retain attempts, grant uses, receipts, revocations, publication checkpoints, unknown holds and refusal overlays. Never erase uncertainty, reset quotas or reuse a spent approval to make a rollback look successful.

## 10. Definition of done

- [ ] D1–D4 recorded and relevant contract interpretations ratified.
- [ ] Operator-held patch reconciled with current code.
- [ ] Human evidence and complete signed-chain approval verification proven.
- [ ] Revocation feed and authenticated freshness proven across restart.
- [ ] Real-port startup and adversarial/process-crash matrix passes at final pins.
- [ ] Actual deployment identity denies seed reads and issuer/public-state writes.
- [ ] Installed artifact/config/policy receipt completed.
- [ ] Independent R6 review closed with final candidate evidence.
- [ ] New generation ratified; actual merged pins pass qualification.
- [ ] Separate activation record exists if activation is requested.
- [ ] Final GitHub handoff and PT continuity record name completed and still-gated capabilities accurately.

No unchecked item may be converted to “done” from a green unrelated CI run.

## 11. Immediate next agent action and information needed

Start WP0. Obtain the unpublished patch and record D1–D4 using section 4; then freeze exact interfaces and execute WP1 onward in dependency order. R4/R5 additionally need the actual deployment host/identity and approved existing state references; R6 needs an independent reviewer.

This session did not inspect the private patch, run implementation tests, verify the ZIP bytes, perform a complete WP0 caller audit, operate a deployment, produce human approval or move production pins. Those are explicit remaining tasks, not hidden completion claims.

## 12. Source downloads

- [Original handoff README](https://github.com/oramasys/oramasys/blob/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff/README.md)
- [Original options draft](https://github.com/oramasys/oramasys/blob/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff/02-OPTIONS-DRAFT.md)
- [Original reference index](https://github.com/oramasys/oramasys/blob/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff/01-REFERENCE-INDEX.md)
- [Original ZIP, pinned source commit](https://github.com/oramasys/oramasys/raw/22cdfa87a28c24d77a22cf0642464794c0e21cdb/docs/handoffs/release12-r3-approval-revocation-handoff.zip)
- [Latest handoff folder](https://github.com/oramasys/oramasys/tree/2026-11-02-002-throwaway-r3-handoff/docs/handoffs/release12-r3-approval-revocation-handoff)

End of plan.
