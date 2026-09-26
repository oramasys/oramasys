# Orchestrator Controller Invariants (module home)

> **Status:** v2.1 design; no runtime code exists yet
> **Module (definitive home):** `src/orama/orchestrator_controller/`
> **Normative spec:** [`68-orchestrator-controller-satellite.md`](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/68-orchestrator-controller-satellite.md)

This repository is the **definitive home** of the Orchestrator Controller. A
standalone satellite repository is a later and unlikely option, reachable only
through the admission gate in the spec's §9.

## Authority in one paragraph

The controller is the sole writer of claim state. GossipBus/GossipMesh is
post-commit, redacted fan-out and can never claim, renew, release, or resolve a
claim. Telos provides transport, Phylax provides admission and capability
verification, and this application composes: it submits declared jobs and renders
controller state but never reimplements claim semantics.

## The 27 invariants, by family

| Family | Ids | Rule in one line |
| --- | --- | --- |
| Authority | IC-1 … IC-6 | one writer; observations never mutate state; fail closed; capability before task lookup; gossip is never a second writer; no topology-as-authentication |
| Identity and envelope | IC-7 … IC-10 | tier-U fields carry no default; tier-C fields are declared explicitly; `lineage` is required when author ≠ actor; an actor never inherits the author's authority |
| Atomicity | IC-11 … IC-14 | one transaction decides a claim; **claim-scope** idempotency is the controller's, **workflow-scope** is this application's; same key + different content is rejected; stale version cannot mutate |
| Leases | IC-15 … IC-18 | lease-bound execution with an unguessable token; conservative recovery; restart safety; `recover-expired` is controller-only |
| Provenance | IC-19, IC-20 | `source_ref` + `expected_base_sha` for every new job; legacy rows need an explicit disposition |
| Egress and privacy | IC-21 … IC-23 | redact before egress; no topology/paths/identity in any artifact; tamper evidence on the card |
| Outcomes | IC-24, IC-25 | explicit `400`/`401`/`403`/`409`, never a generic success; denials audited without proof material |
| Dependency direction | IC-26, IC-27 | one-way imports (Core only); this application composes and never becomes a second job-state writer |

Full text, including the envelope-card and agent-state building blocks and the
per-invariant test list, lives in the spec's §3 and §10.1. That document is
normative; this file is the module-side index and must not diverge from it.