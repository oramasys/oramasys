# Local workspace proof of concept

- [x] Inspect architecture PR heads and owner boundaries.
- [x] Write product plan including both prior recommendations.
- [x] Implement offline artifact, privacy contract, and independent verifier.
- [x] Verify contracts, negative cases, and run instructions (API-only slice).
- [ ] Browser workspace UI (not shipped; the slice exposes JSON endpoints only).

## Follow-up: Release 1–2 R3 synthesis

1. [x] Reconcile bundle patches, historical candidate branches, and the live
   merged Oramasys/Phylax mains with a path-level three-way matrix.
2. [x] Preserve only behavior that is absent from live main and safe under the
   frozen, dark-by-default authority contract.
3. [x] Add the retained-authority regression first, then implement the smallest
   atomic persistence and read-only recovery surface that satisfies it.
4. [x] Run the focused dispatch, composition, revocation, and lifecycle suites.
   Host-bound qualification remains explicitly delegated in the handoff.
5. [ ] Commit the harmonized delta, push once, and open one draft Oramasys PR.
   No Phylax delta remains after the three-way synthesis.

### 2026-11-02 successor round

The preceding checklist records the original #90 candidate, not a claim that
the complete release is qualified. This round extends that draft additively.

- [x] Verify bundle hashes, current mains and existing PR #90 before editing.
- [x] Harden retained evidence with replacement protection and committed-row linkage tests.
- [x] Implement public-only, issuer-scoped inert approval verification outside the kernel.
- [x] Finish and review durable authenticated revocation-feed composition.
- [x] Rerun final focused, cross-repository and broad suites after all lanes finish.
- [ ] Commit logical batches, publish once per affected repo and reuse one draft PR per repo.
- [ ] Record final publication receipts and independently gated host/review work.

The [completion matrix](../docs/release12-r3-completion-matrix-2026-11-02.md)
classifies all W0–W9/WP0–WP9 areas; unchecked host, ratification and activation
items are not silently converted into software tasks.

### 2026-11-03 consolidation

- [x] Preserve Windows `1be852b` and all raw-connection upsert/migration tests by merge.
- [x] Integrate existing #91 H09 deployment profile without creating a second profile implementation.
- [x] Close send-window key-removal and broken-hook-descriptor regressions before publication.
- [x] Incorporate companion #30 platform primitives; preserve review-before-call-site-port order.
- [x] Verify Phylax full integrated suite: 982 passed, 1 platform skip, 92.62% coverage (Python 3.12).
- [x] Verify consumer focused supported-version suite: 321 passed (Python 3.11).
- [x] Review final consumer suite: 2,891 passed, 3 skipped, 93.34% coverage; final focused Python 3.11 selection: 242 passed.
- [x] Review final producer suite after platform repairs: 985 passed, 1 Windows-only skip, 92.63% coverage.
- [x] Record explicit author/actor/lane provenance; no independent R6 endorsement claimed.
- [ ] Publish exactly once to existing #91 and #30; remote receipts follow publication.
- [ ] Windows independent R6 review at published heads, then reviewed platform call-site port.
- [ ] Actual R4/R5 qualification, operator R7 generation and separate R8 activation.

### Approved next slice — 2026-11-04 (Manila), executed 2026-11-03 UTC

The preceding unchecked publication entries are historical. #91 and Phylax #30
are merged; this successor reuses draft #92 and adds producer draft #31 for a
reproduced defect, with no production pin or generation promotion.

- [x] Audit exact merged heads, open overlapping work and current CI; record
  inaccessible branch-protection data and skipped checks separately.
- [x] Test merged Phylax main on both Python versions with mandatory interop.
- [x] Repair refresh's second-lock clock race and exercise successful retry/replay.
- [x] Repair operator-assertion validity rechecks under the nonce write lock;
  test both merged and repaired producer candidates in the consumer workflow.
- [x] Review loaded-identity design and implement an opt-in, return-time public
  profile projection with explicit limits; no deployment evidence is fabricated.
- [x] Use fresh Terra review lanes; preserve the distinction from independent R6.
- [x] Prepare the [final qualification receipt](../docs/release12-postmerge-qualification-2026-11-04.md)
  for #92/#31; final publication and remote-byte readback are reported in the PR.
- [ ] Trust-aware snapshot cache and target-workload contention qualification.
- [ ] Deployment configuration/policy chain, actual R4/R5 host evidence, independent
  R6 endorsement, operator R7 generation and separate R8 activation.
