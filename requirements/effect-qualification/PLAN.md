# Effect candidate qualification implementation plan

Goal: bind fresh human approval and an installed Linux rehearsal to consumer
02e4f6d7b0b24a50fa3f50f11977cbccf2915bcb and Phylax
cf3a300c6d39092ab64df54f0d1ab3fea3db3c38 without changing active generations.

Design: additive candidate manifest, schema-2 install plan, version-2 coverage
packet and reusable workflow. The registered legacy workflow can dispatch the
new lane by an explicit packet selector; its default and old frozen bytes stay
unchanged. Approval remains on PR #81, with the exact new harness SHA. PR runs
are rehearsal-only. Approval enables software evidence collection, not deployment.
The existing fresh login and one-time marker verifier is reused unchanged.

Alternatives: rewriting the existing frozen packet would invalidate old receipts;
using only a new unregistered dispatch workflow cannot be invoked before merge.
The additive packet and registered dispatch bridge avoid both problems.

Execution: native implementation in this already isolated worktree, with tests
before behavior changes, then a separate review pass. User requested proceeding
after this preparation and no authentication yet.

## Tasks

- [ ] Extend install-plan schema validation additively: schema 1 stays pinned;
  schema 2 requires a full immutable consumer tuple matching its manifest.
  Verify legacy, new, malformed, mismatched and unknown schema cases.
- [ ] Add version-2 coverage rules: preserve all legacy module/gate requirements
  and additionally require real effect interop and sealed inert/crash modules.
  Verify omission and inactive-gate refusal, including collection enforcement.
- [ ] Add candidate packet/install plan and reusable qualification workflow;
  bridge registered dispatch and make PR rehearsal explicitly non-evidence.
  Retain existing provenance, collection, scenarios, approval and drift checks.
- [ ] Run focused and full tests, push a new stacked draft PR, run rehearsal,
  and publish precise fresh-login commands bound to its final harness SHA.

Review focus: stale consumer, stale producer, omitted effect tests, missing human
approval, replayed/expired authentication, modified frozen generations, accidental
deployment qualification claims. Keep production pins and activation disabled.

Live serving-UID isolation, installed deployment artifact/configuration identity,
hardware qualification and live policy/approval integration are separate evidence
gates. This workflow must not claim to establish those from CI fixtures.
