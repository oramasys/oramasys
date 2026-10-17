# v2 Constellation Router-and-Map Plan

## Purpose

Use the root architecture map to build Oramasys as a constellation of explicit
contracts. It points from a user outcome to the component that owns each
decision, the adapter boundary, the offline proof, and the receipt.

## Current Starting Point

- The local workspace proof materializes an extractive CSV and independently
  verifiable receipt without model, retrieval, provider, or durable-memory
  dependencies.
- Oramasys composes application behavior above the dependency-minimal Core
  kernel.
- Privacy is local by default. Progressive sharing is explicit, visible in
  receipts, and may be refused when a required verifier is unavailable.

## Delivery Sequence

1. Start with a user outcome and declare audience, inputs, privacy profile,
   real artifact, verifier, and limits.
2. Model only the required typed execution graph: transitions, checkpoints,
   recovery rule, effect owner, and measurable stop condition.
3. Assign ownership: Core structures; Oramasys composes; Telos controls
   endpoint decisions; Phylax controls grants/provenance; Agate controls
   placement; satellites own their knowledge or retrieval policy; operators
   approve consequential transitions.
4. Specify each satellite adapter independently: capability discovery, typed
   request/response, privacy label, provenance, receipt, failure semantics,
   and removal path.
5. Demonstrate an offline, local artifact flow and independent verification
   before enabling a provider, retrieval source, model, or persistence layer.
6. Extend one contract at a time, using tests and receipts to promote a
   capability from planned to implemented.

## Acceptance Checks

- Every constellation edge names both its owner and contract.
- Core retains no upward Oramasys or satellite dependency.
- Missing required authorization or provenance verification fails closed.
- The artifact, its privacy profile, and its receipt can be inspected locally.
- Maps link to evidence and limitations rather than duplicating authority.
- PT closure and Phase 0 Wiki remain secondary reference matches.

## Deferred

Provider serving, durable recovery, configured retrieval, model execution,
scheduler activation, package promotion, and qualification require their own
contracts, tests, receipts, independent review, and operator decision.
