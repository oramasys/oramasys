# v2 Constellation Router-and-Map Plan

## Purpose

Use the root architecture map to build Oramasys as a constellation of explicit
contracts. It points from a user outcome to the component that owns each
decision, the adapter boundary, the offline proof, and the receipt.

## Current Starting Point

- The local workspace proof materializes an extractive CSV and independently
  verifiable receipt without model, retrieval, provider, or durable-memory
  dependencies
  ([plan](2026-10-16-local-workspace.md), [code](../../src/orama/workspace/),
  [tests](../../src/tests/test_local_workspace.py)).
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
  The System Shape diagram labels every edge and links the existing contract
  surfaces; dashed controller and satellite edges remain planned boundaries.
- Core retains no upward Oramasys or satellite dependency.
- Missing required authorization or provenance verification fails closed.
- The artifact, its privacy profile, and its receipt can be inspected locally.
- Maps link to evidence and limitations rather than duplicating authority.
- PT closure and Phase 0 Wiki remain secondary reference matches.

## Deferred

Provider serving, durable recovery, configured retrieval, model execution,
scheduler activation, package promotion, and qualification require their own
contracts, tests, receipts, independent review, and operator decision.

## Cross-map parity

Both maps preserve their own questions and record details while sharing exactly
five graph names and **Shared meaning** definitions. The `Architecture map parity`
workflow checks out legacy Orama at a full immutable SHA and runs its canonical
`scripts/review/check_architecture_map_parity.py`; this repository does not fork it.

For local review using explicit candidate checkouts:

```bash
python /path/to/orama-system/scripts/review/check_architecture_map_parity.py /path/to/orama-system/ARCHITECTURE.md ARCHITECTURE.md
```

For a taxonomy change, prepare both maps and update both workflows' peer `ref`
values to reviewed counterpart SHAs. Run against that exact pair before publishing
and recheck both merged revisions. Pinned checks are reproducible compatibility
evidence, not continuous monitoring of another repository's moving `main`.
Documentation validation never adds a runtime dependency on legacy services.

## Local versus production kernel evidence

`pyproject.toml` pins Core to `6d75cfe08af95992dddffab13ae3019aa9c41350`.
The development Makefile supports an editable sibling; neither installation should
be described as the other. Record the actual imported location, installed metadata,
and sibling revision when applicable:

```bash
python -c 'import perpetua_core; print(perpetua_core.__file__)'
python -m pip show perpetua-core
git -C /path/to/perpetua-core rev-parse HEAD
```

Production CI separately performs a clean non-editable install and checks the
pinned revision from outside the checkout. Local editable results do not replace
that evidence. This documentation change neither repins Core nor enables serving.
