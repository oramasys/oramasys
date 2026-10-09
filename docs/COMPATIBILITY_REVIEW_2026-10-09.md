# Compatibility implementation handoff — 2026-10-09

Canonical design and preserved research:
[Orama revision 3 index](https://github.com/diazMelgarejo/orama-system/blob/docs/loop-graph-compatibility-r3/docs/v2/references/loop-graph-compatibility-2026-10-09/README.md),
[resolutions](https://github.com/diazMelgarejo/orama-system/blob/docs/loop-graph-compatibility-r3/docs/v2/references/loop-graph-compatibility-2026-10-09/REVISION-3-RESOLUTIONS.md),
and [durable approval contract](https://github.com/diazMelgarejo/orama-system/blob/docs/loop-graph-compatibility-r3/docs/v2/references/2026-10-09-compatibility-refusal-hitl-contract.md).
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
Core #8 is merged. The production dependency pin and the test-only candidate
now both name the merged Core commit `04759a5` (tree-identical to the reviewed
`b9b4477`), so the overlay no longer differs from the production install.

Production foreign effects and automatic deferred approvals stay refused.
Budget/effect policy files are lintable intent; they are not an admission or
dedupe engine. See the [active decisions](https://github.com/diazMelgarejo/orama-system/blob/docs/loop-graph-compatibility-r3/docs/v2/references/loop-graph-compatibility-2026-10-09/EXECUTION-REVISION-4.md)
and [oracle reproduction](../tests/oracles/README.md).

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
