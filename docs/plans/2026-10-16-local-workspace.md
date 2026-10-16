# Local workspace: v1 and v2 implementation plan
Date: 2026-10-16. Method: /oramasys-method; AFRP C / Practitioner / Mode 2.
Status: authorized minimal proof of concept; production roadmap remains gated.

## Intent and assumptions
Serve both general users seeking useful files and researchers needing inspectable evidence.
Local processing and privacy are defaults. Sharing is a per-run, explicit opt-in.
The Local Keep AI screenshots describe the target; marketing claims are not independently verified.
The two prior comprehensive recommendations are preserved in
[roadmap 1](references/local-workspace-roadmap-1.md) and
[roadmap 2](references/local-workspace-roadmap-2.md).
This plan supersedes the earlier either-audience question: both are in scope.

## Foundations and owner boundaries
Build additively on the exact architecture PR heads:
- v1 [#409](https://github.com/diazMelgarejo/orama-system/pull/409), a6693d792be93501d6677f5629efedeb6768a5fe.
- v2 [#49](https://github.com/oramasys/oramasys/pull/49), 46aa4e21133ec31680c75851f75db638d06973e7.
- v2 #49 remains stacked on #46 and #45; this prototype does not qualify that stack.
Use isolated child branches; no rebase, force-push, merge, or restart of existing services.
Perpetua-Tools owns operational reference fixtures and its existing Periscope adapter.
Orama v1 owns its portal integration and normative migration/evaluation contracts.
Perpetua Core remains a small structural kernel: this sequential proof exposes no kernel gap.
Oramasys owns the v2 application workflow, API, CLI, and thin workspace.
Telos retains network authority; Phylax retains security/provenance/grants;
Agate retains placement authority. Consent preferences do not mint their grants.
New implementation is authored for each repository under its existing license;
no legacy implementation is imported into the clean v2 kernel.

## Minimal accepted slice
Task + selected local source passages -> extractive records -> CSV -> separate verifier -> receipt.
There is no model or web inference in this slice. A claim must equal its cited quote,
and the quote must occur verbatim in the selected source passage.
This proves bounded source attribution, not real-world truth or general semantic entailment.
General-user mode emphasizes the task and file; research mode expands source/check details.
The existing v1 operator console remains reachable; the new workspace is the front door.
v2 serves an independent small workspace from its existing FastAPI application.
Both API contracts have the same fields and synthetic parity fixtures.
All UI assets are local; no fonts, telemetry, analytics, or remote JavaScript.

## Privacy contract
| Profile | Future permitted disclosure | Prototype effective behavior |
| --- | --- | --- |
| local (default) | No external disclosure | No outbound work |
| sources | Public source queries only; no private document text | No outbound work |
| redacted | User-reviewed redacted excerpts | No outbound work |
| open | User explicitly permits full selected task inputs | No outbound work |
Profiles are per-run, reset to local on reload, and cannot weaken authentication.
No silent cloud fallback. A privacy-off choice never authorizes arbitrary filesystem,
shell, or network access. Future transport adapters must enforce disclosure at each effect.
Receipts record requested profile and actual disclosure independently.
Task content and bearer tokens are never written to browser persistent storage.
Result content remains in browser/request memory until download or page close.
Manual CSV/receipt downloads contain selected source material and remain private local files.
Private mode does not hide data from the operator hosting the backend: run it on your device.

## API and migration ledger
Add POST /api/workspace/run and GET /api/workspace/capabilities.
POST accepts task, privacy, bounded sources, and bounded extractive records.
Sources contain id/title/passage/kind; records contain claim/source_id/quote.
Response binds run_id, CSV, canonical receipt bytes, hashes, checks, and limitations.
Source rank is explicitly declared provenance quality: primary, secondary, unverified;
ties are stable, and ranking is not a confidence probability.
Inputs reject extras, duplicate IDs, blank content, unsupported quotes, and spreadsheet formulas.
Fixed download filenames eliminate user-controlled server paths; no server file reads/writes.
The independent verifier reparses CSV and checks schema, row count, source bindings,
quote support, and artifact hash. It can recheck a downloaded CSV and receipt offline.
Receipt integrity is unsigned; source authenticity and independent human review remain separate.

| Layer | Old contract | Additive contract and proving check |
| --- | --- | --- |
| Storage | Existing portal stores unchanged | Request-memory only; no migration or server retention |
| Callers | Existing operator APIs | New workspace caller; same v1/v2 fixture |
| Transport | Existing authenticated API | Authenticated POST, no-store responses, bounded JSON |
| Lifecycle | Existing graph/admission behavior | Offline chain only, no provider/scheduler bypass |
| Observability | PT Periscope adapter | Metadata-only compatible envelope; no automatic emission |
| Recovery | Existing services | Retry computes a fresh read-only result; no external effects |
Rollback: remove new routes/front-door wiring; prior APIs and operator console remain intact.
No claim of durable replay, crash-resume, or provider admission is made by this chain.

## Delivery and acceptance
1. Plan/spec: preserve both earlier replies; document permissions and boundaries.
2. Backend: RED -> GREEN offline artifact and verifier tests on both versions.
3. Frontend: RED -> GREEN form/privacy/error/download tests; preserve operator navigation.
4. Integration: exercise real API, negative cases, auth, and no external calls.
5. Verification: affected suites, full Python suites (legacy processes may exceed 300 seconds),
   frontend tests/build, and rendered desktop/mobile inspection when tooling is available.
6. Handoff: document exact run commands, observed checks, limitations, and remaining gates.

## Follow-on roadmap and agent contracts
Gate 0: reproducible capability inventory with code, tests, package SHAs, and limits;
qualify existing PR dependency stack separately before production reliance.
Gate 1: expand checked local corpus, malformed cases, deterministic file materializers,
independent verifiers, tamper/fault injection, source hashes and actual downloadable bundles.
Gate 2: capability-tested GGUF/Ollama adapters; local corpus retrieval; optional Telos web;
then explicit hosted/OpenRouter options with disclosed estimated/max cost.
Test unsupported capabilities and never advertise universal model compatibility.
Citations bind claim -> passage -> source -> acquisition time -> limitations.
Ranking considers relevance, primary evidence, recency, and corroboration; domains alone do not prove truth.
Gate 3: bounded generate/verify/repair loops, budgets, durable attempts and terminal states,
idempotency, interrupted publication, verifier timeout, unavailable model, duplicate requests,
uncertain effects, and independent re-verification. Checkpoints alone do not prove safe replay.
Gate 4: stable Python/CLI/API, richer desktop UI, then mobile clients and optional synchronization.
Keep v1 operational until v2 passes the same observable parity cases.
Only introduce meta-autoresearch after fixed evaluators and held-out datasets exist:
optimize one bounded surface; the optimizer cannot edit tests, grants, permissions, or budgets.
An outer loop proposes changes; independent evaluation controls promotion.

Every agent task declares outcome, owning repo, allowed files, input/output schema,
dependencies, acceptance command/evidence, time/cost/iteration limits, reviewer, blocked state.
Use Cass -> Aria -> Sena -> Rourke -> Vera -> Crystal responsibilities:
implementation and independent verification remain separate.
First next slices: richer source fixture contract, additional file materializers,
model capability adapters, bounded graph integration, crash/retry qualification.
Do not grow the kernel, introduce a second scheduler, or claim UI success as runtime qualification.

## Risks and mitigations
- Extractive checks are narrow: display their scope and explicit limitations.
- User-declared source kinds may be false: labels stay inspectable, never a truth score.
- Receipts may carry sensitive text: local downloads only, no implicit export or emission.
- Broader sharing preferences are inert until properly qualified transport adapters exist.
- Default local setup and explicit auth protect different boundaries; verify both.
- Full cross-platform and real-model qualification require actual target environments.
