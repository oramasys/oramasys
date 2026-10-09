# Compatibility implementation handoff — 2026-10-09

Canonical design and preserved research:
[Orama revision 3 index](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/loop-graph-compatibility-2026-10-09/README.md),
[resolutions](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/loop-graph-compatibility-2026-10-09/REVISION-3-RESOLUTIONS.md),
and [durable approval contract](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/references/2026-10-09-compatibility-refusal-hitl-contract.md).
PT's evidence plan and append-only memory follow-up link to the same authority.
These paths are local publication targets, not claims of remote availability.

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
