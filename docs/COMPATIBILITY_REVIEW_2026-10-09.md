# Compatibility implementation handoff — 2026-10-09

Canonical design and preserved research:
[Orama revision 3 index](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/loop-graph-compatibility-2026-10-09/README.md),
[resolutions](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/loop-graph-compatibility-2026-10-09/REVISION-3-RESOLUTIONS.md),
and [durable approval contract](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/2026-10-09-compatibility-refusal-hitl-contract.md).
PT's evidence plan and append-only memory follow-up link to the same authority.
These paths refer to the coordinated open Orama PR branch, not merged main.

New native compatibility facades, explicit replacement activation and lazy
caller-installed LangChain/LangGraph bridges belong here. Both v0.x and v1.x
release lines need isolated pinned oracles. Keep Core's two existing neutral
adapters and one scheduler; never grow `engine.py` to hold concrete framework
or security policy. Native patterns only for Pydantic AI; a production Agent
bridge is deferred to a separate explicit decision.

Core's local `abatch` repair rejects non-positive/non-integer/bool bounds before
effects, including empty batches. Current dependency pin is intentionally left
unchanged: after the Core repair is reviewed and merged, pin its immutable
merged SHA and rerun this repository's entire suite. No unpublished SHA or
branch reference is a valid substitute.

Replacement compatibility is a goal, not a current capability. The corrected
fake alias prototype proves neither real-framework parity nor pip installation.
Implement only supported matrix rows; retain explicit gap/refusal outcomes.
Admission belongs to Phylax, hardware to Agate, and endpoint security to Telos.
Foreign objects require enforceable sandbox/process egress controls; merely
wrapping them in a node is not a security boundary. Until durable HITL bindings
and use accounting exist, overrides remain denied/pending.

## Revision 4 approved slice

The earlier text describes the revision 3 handoff. The operator subsequently
approved D-LG-1's separate policy file/transclusion and D-LG-4 Phase 1.
This PR now implements import-free graph_tool, a lazy offline-only agent-as-node
bridge, tiered gap errors, strict graph-policy binding and the application
definition's linked summary. It does not activate replacement imports.

The real offline framework suite plus application suite passes 271 tests;
the framework-free application suite passes 261. The ten oracle cells never
use importorskip and prohibit socket connections. A built-wheel smoke confirms
the separate default policy JSON is packaged and loadable.
The test-only lock/workflow uses an immutable Core candidate overlay.
Core #8 is merged. At the time of this 2026-10-09 review, the production
dependency pin and the test-only candidate both named the merged Core commit
`04759a5` (tree-identical to the reviewed `b9b4477`).

## 2026-10-10 P0 promotion note

This dated review remains historical evidence. The promoted production baseline
is now the reviewed R3 Core commit `4d217f6`; the `04759a5` policy-R3 profile
and `34e4a8d` core-R3 profile remain immutable candidate evidence in separate
CI lanes. Production tests select the explicit production registry profile and
may not infer a candidate from installed Core capabilities.

Production foreign effects and automatic deferred approvals stay refused.
Budget/effect policy files are lintable intent; they are not an admission or
dedupe engine. See the [active decisions](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/loop-graph-compatibility-2026-10-09/EXECUTION-REVISION-4.md)
and [oracle reproduction](../tests/oracles/README.md).

## 2026-10-10 P0 single-pin invariant

`src/tests/test_compatibility_pins.py` makes each dependency edge name one immutable
revision. Both workflows must check out the same full-SHA Orama registry revision; each
oracle lane file must equal its registry profile's Core pin; and the package dependency,
production lane and clean-install check must agree on the production Core pin. A branch
name, a second pin table or a partial update fails before qualification evidence is
recorded.

The producer checkout stays at Orama `8287e40`, the registry-bearing #394 candidate.
Later #394 commits change documentation only, so the registry bytes this repository
qualifies against are unchanged; repin only to #394's actual merge SHA. The successor
evidence receipt in Orama
(`docs/v2/references/r4-safety-compatibility-platform-2026-10-10/P0-SUCCESSOR-EVIDENCE-RECEIPT-2026-10-10.md`)
records the heads, pins and digests. P0 remains unqualified until the six-cell manifest
and the clean, non-editable install verifier exist and pass.

## Budget stop and portable gap errors (follow-up)

- **Budget exhaustion now stops the run.** `as_node` returned an error delta
  on `UsageLimitExceeded`, so downstream nodes, including effect nodes, still
  executed and the final status was `done`. It now raises Core's structural
  `Interrupt` with payload reason `budget_exhausted` and `resumable: false`.
  The oracle test uses a two-node graph and asserts the downstream node never
  runs; it fails on the previous head.
- **Gap errors survive pickling.** Both gap error classes rebuild from their
  constructor arguments, so diagnostics cross worker and process boundaries.

Verification on Python 3.12 against Core candidate `b9b4477`: oracle
environment 284 passed; framework-free application suite 271 passed.
