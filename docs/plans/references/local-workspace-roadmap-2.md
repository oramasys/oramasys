# Roadmap 2: screenshot-grounded product architecture
Preserved recommendation from the preceding conversation; the subsequent implementation
plan incorporates the user's choice to serve both audiences and configure privacy.

This is an architectural goal: build an open-source, local-first AI workspace and library.

The screenshots define the product contract:
- Local models run on the user's device; conversations and files remain local by default.
- Users can select by capability across GGUF, Ollama, hosted models, and OpenRouter,
  with cost shown before any paid call.
- Autonomous commands can plan and execute bounded work with minimal input.
- File requests produce the actual downloadable artifact.
- Each material claim has inspectable source passages and ranked source quality.
- Every task has a durable run record: model, inputs, tool actions, generated files,
  tests, citations, and outcome.
- The same workflow is usable through CLI first, then desktop/mobile/web surfaces.

The key product primitive should be an evidence-backed task run:
request -> plan -> retrieve/local inputs -> execute -> verify -> materialize files
-> evidence receipt (sources, rankings, tests, hashes, model/tool trace).

A hash proves a file did not change; it does not prove the answer is correct.
The receipt therefore needs both artifact hashes and task-specific verification results.

| Repository | Responsibility |
| --- | --- |
| Perpetua-Tools | Legacy compatibility, operational fixtures, proven task patterns |
| orama-system | Normative workflow, evaluation/source-ranking rules, parity reference |
| perpetua-core | Small reusable graph/task kernel: typed state, bounded execution, checkpoints, receipts |
| oramasys | Product composition: model catalog/router, local files, evidence UI/API, CLI, clients |

The first vertical slice:
Given a local input corpus and a fixed task, create a CSV, cite every factual
row/claim, rank sources, independently verify the CSV, and return an evidence
receipt, all without network access.

It should refuse unsafe paths, formula injection, unsupported file types,
missing citations, and unverifiable claims. This becomes the golden fixture
each model/provider must pass before being advertised as capable.

Evolve in this order:
1. Deterministic offline artifact task with evidence receipt.
2. Local-model adapter matrix: GGUF and Ollama; record tested capabilities.
3. Local file retrieval, citations, and semantic verification.
4. Optional web retrieval through the existing policy boundary; source ranking
   based on relevance, primary-source status, recency, corroboration.
5. Bounded autonomous repair loops with time/cost/iteration limits and terminal states.
6. Hosted/OpenRouter behind explicit consent, visible price, redacted inputs,
   and the same receipt format.
7. Desktop/mobile/web over stable CLI/API.

For autonomous agents, every assigned slice carries owning repo, allowed files,
input/output schema, budget, acceptance tests, expected receipt, and an independent
verifier. No agent should self-certify its own generated artifact.

The existing PR sequence is a foundation: independently qualify grounded-graph
architecture before provider adapters or UI production claims. Keep v1 as the
behavioral reference until v2 passes the same fixtures.

The earlier audience question offered researchers/analysts or general consumers.
The user has now explicitly selected both audiences with privacy enabled by default.
