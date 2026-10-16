My recommendation: **give your agents one repeatable product outcome to deliver: “Produce a source-backed CSV, verify it independently, and return the actual file with an evidence receipt.”** Expand from that working example.

I read all five attachments and checked the referenced PRs. The X post wasn’t retrievable, so I’m using the capabilities described in `instruction.md` as your target.

Your foundation is further along than that document suggests: v2 already has `MiniGraph`, typed graph specifications, routing, verification hooks, and execution/admission boundaries. The next step is connecting these into a useful, qualified workflow.

### Keep the four repositories’ roles clear

| Repository | Role toward the goal | Next contribution |
|---|---|---|
| `Perpetua-Tools` | Existing orchestration and operational experience | Supply reference behavior, reusable fixtures, and parity tests |
| `orama-system` | Methodology, normative decisions, agent workflows | Define task contracts, acceptance criteria, evaluation rules |
| `perpetua-core` | Small execution kernel | Fix execution primitives only when a concrete workflow demonstrates a gap |
| `oramasys` | Target library and software composition | Build the grounded artifact workflow, Python entry point, CLI, and API |

Treat v1 as the operational reference while v2 earns parity. Extract proven behavior through tests and explicit adapters. Review licensing before moving implementation between the legacy and clean repositories.

Preserve satellite ownership: Telos handles transport, Phylax handles security/provenance decisions, and Agate handles hardware placement.

### Gate 0 — Establish exactly what can be built upon

Give an agent this bounded assignment:

> Produce a capability inventory linking every claimed capability to its implementation, test, qualified package revision, and known limitation.

Resolve the relevant qualification dependencies before relying on them. Currently, `oramasys#46` is stacked on `#45`; architecture PR `#49` is stacked on `#46`. The v1 architecture PR `orama-system#409` is independent. These architecture documents remain maps, not proof that the artifact workflow works.

**Exit criterion:** one reproducible environment can execute an existing graph through its required gates, with versions and evidence recorded. Every missing capability becomes a bounded issue.

### Gate 1 — Deliver one complete offline artifact

Use a small, checked-in dataset with source documents and deliberately malformed examples. Build this application workflow in `oramasys` using existing Core contracts:

```text
Task + local sources
        ↓
Extract supported records
        ↓
Write CSV into staging
        ↓
Independent verifier
        ↓
Publish file + evidence receipt
```

The initial implementation can be deterministic. A model should earn its place by solving a demonstrated problem.

The output bundle should contain:

- The actual CSV.
- Source references for each factual record.
- A verification report with checks performed and failures.
- A manifest binding task, source hashes, artifact hash, and implementation version.

**Exit criterion:** a fresh checkout produces the bundle offline. Unsupported facts, malformed rows, unsafe paths, spreadsheet-formula hazards, and tampered artifacts prevent successful delivery.

A hash proves file integrity; the verifier must separately check content.

### Gate 2 — Add real retrieval and local-model execution

Once the deterministic path works, replace one seam at a time:

1. Add a configured local model through the existing provider boundary.
2. Add retrieval over an operator-selected local corpus.
3. Add optional web retrieval through Telos.
4. Add explicit, policy-controlled cloud execution.

For citations, record **which claim is supported by which passage**, its source, collection time, and limitations. Rank by relevance, primary-source status, recency where appropriate, and corroboration. `.gov` and `.edu` are useful metadata—not automatic truth scores.

Make verification task-specific: research needs evidence checks; CSVs need schema and record checks; generated code needs execution tests. Define required checks when accepting the task.

**Exit criterion:** the same task works with a real local model; unsupported claims are exposed or refused; an offline policy test confirms zero outbound traffic.

“Any model” should become **a tested provider/capability matrix**, with graceful refusal when a model lacks a required capability.

### Gate 3 — Make autonomy recoverable, then package it

Add bounded repair loops around the working workflow:

```text
Generate → Verify → Repair
              ↑        |
              └────────┘
```

Each loop needs an attempt limit, time/cost budget, durable history, and explicit terminal result. Exhaustion should produce an inspectable failure.

Prove recovery with injected failures: crash during artifact writing, unavailable model, verifier timeout, repeated request, and uncertain external effect. A checkpoint alone does not provide safe replay—the Core README explicitly distinguishes these.

**Exit criterion:** retries cannot silently duplicate effects or publish an unverified artifact, and completed receipts can be checked independently.

Then expose the same workflow through a Python library, CLI, and FastAPI. Build a thin web client next; desktop and mobile clients can follow the stable API.

### Give every agent a small, testable contract

Use your existing Cass → Aria → Sena → Rourke → Vera → Crystal workflow. Parallelize independent implementation work after contracts are agreed.

Every assignment should specify:

```text
Outcome:
Owning repository and allowed files:
Inputs and output contract:
Dependencies:
Acceptance command and expected evidence:
Iteration/time/cost limits:
Required reviewer:
Definition of blocked:
```

Separate implementation ownership from verification ownership. Vera should test the externally observable result against the agreed contract; Rourke should not be able to relax the evaluator to make its own output pass.

For the first development batch, assign these sequential slices:

1. Source fixture and artifact contract.
2. Deterministic CSV materializer.
3. Independent verifier and negative cases.
4. Graph integration and CLI delivery.
5. Crash/retry qualification.

### Introduce meta-autoresearch after you have a benchmark

The useful idea in `meta-AutoResearcher.md` is measurable experimentation. Start by allowing agents to optimize one bounded surface—such as extraction prompts—against a fixed evaluation set.

Keep acceptance tests, held-out cases, permissions, and budgets outside the optimizer’s editable scope. An outer loop can propose a better search strategy, but promotion should require independent evaluation.

Your first team objective should be:

> **From a fresh checkout, produce a correct, cited CSV offline, reject unsupported content, recover safely from an interrupted write, and deliver independently verifiable evidence.**

That milestone exercises the essential promise behind the larger product and gives every subsequent agent a concrete foundation to improve.
