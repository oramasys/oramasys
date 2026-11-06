# Orchestrator Controller Claim Contract (v2, executable)

> **Status:** partial implementation of register rows C2 (v2 claim contract part),
> C2a, C3, C3a, C3b and C3c in `src/orama/orchestrator_controller/`. Not reviewed,
> not deployed, not activated; no serving path composes it. C3d (security review,
> legacy-job disposition, rollback and operational runbook acceptance) is **not closed**.
> **Normative design:** [doc 68](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/68-orchestrator-controller-satellite.md)
> §1–§4, §8–§11 and invariants IC-1 … IC-29; claim kind mapping in
> [doc 69 §7](https://github.com/diazMelgarejo/orama-system/blob/main/docs/v2/69-agent-envelope-standard.md).
> **Module index:** [orchestrator-controller-invariants.md](orchestrator-controller-invariants.md).
> **Ratified scope:** D1 (2026-11-06) — automatic stale-claim release belongs to
> the v2 Controller only, under explicit expiry and fencing in the authoritative
> claim transaction. PT remains manual.

This document turns doc 68 into an executable protocol for the first internal
module. Where doc 68 leaves a choice open, this contract records the narrower
reading and says so. Doc 68 stays normative; if the two disagree, doc 68 wins
and this file is corrected.

Job-claim leases here are **not** the execution run leases in
`src/orama/graph/execution_guard.py`. Those fence one graph run's scheduler; these
fence one principal's claim on one declared job. The two share no table, epoch
or token.

## 1. Surfaces

| Surface | Module | Who calls it |
| --- | --- | --- |
| Request envelope and canonical digest | `envelope.py` | the controller service |
| Refusal vocabulary | `refusals.py` | every layer |
| Reviewed migrations | `migrations.py` | the store, at open |
| Authoritative SQLite state | `store.py` | the controller service and the expiry worker only |
| Telos and Phylax ports, fail-closed defaults | `ports.py` | composition (scripts, tests) supplies adapters |
| Request admission pipeline | `service.py` | the composing application |
| Opt-in expiry worker | `expiry.py` | an operator or composition, explicitly |
| Redaction and outbox publisher | `outbox.py` | composition, explicitly |

Importing the package starts nothing: no thread, no timer, no database, no
network. No install-time entry point exists.

## 2. Records

One controller-owned SQLite database (WAL, `synchronous=FULL`, private `0600`
file in a `0700` directory via `prepare_private_store`). Schema version 1:

| Table | Purpose |
| --- | --- |
| `schema_migrations` | applied migration version, name and reviewed SHA-256 digest |
| `controller_meta` | random opaque `store_id`; controller clock high-water mark |
| `tasks` | `task_id`, `state`, `version`, `source_ref`, `expected_base_sha`, `payload_digest`, `effect_class`, `result_digest`, `failure_class` |
| `leases` | `lease_id`, `task_id`, `principal_id`, `token_digest`, `fence`, `issued_at`, `expires_at`, `state` |
| `idempotency` | claim-scope key `(principal_id, operation, idempotency_key)`, `request_digest`, committed receipt |
| `outbox` | `sequence`, `event_id`, `kind`, `redacted_payload`, `payload_digest`, `published_at` |
| `audit` | `event_id`, `actor`, `action`, `outcome`, `lineage`, `policy_version`, `occurred_at` |
| `maintenance_owner` | one expiry-worker owner per database: `owner_id`, `epoch`, `expires_at` |

A partial unique index allows at most one `active` lease per task.

### Reviewed migrations

Each migration is a tuple of SQL statements with a SHA-256 digest. The module
holds `REVIEWED_MIGRATION_DIGESTS`; a migration whose digest is absent from that
map is refused before it runs. Opening a database refuses when an applied
migration's recorded digest differs from the reviewed one, or when the database
records a version newer than this code knows. Adding a migration therefore
requires changing the statements and the reviewed digest together, which is the
review point. Migrations run inside `BEGIN IMMEDIATE`, one per transaction.

## 3. States and transitions

Task states: `pending`, `claimed`, `completed`, `failed`, `reconcile`.
Lease states: `active`, `completed`, `released`, `failed`, `expired`.

| Operation | Caller | Preconditions (all inside one `BEGIN IMMEDIATE`) | Effect | Version |
| --- | --- | --- | --- | --- |
| `claim` | principal | task `pending`; `expected_task_version` equals stored version; source line equals stored | new `active` lease, `fence` = new version, expiry = now + TTL; task `claimed` | +1 |
| `renew` | lease holder | lease `active`, same principal, token matches, lease fence equals task version, now < expiry, version matches | expiry = now + TTL | unchanged |
| `complete` | lease holder | as `renew`; `result_digest` present | lease `completed`; task `completed` with `result_digest` | +1 |
| `release` | lease holder | as `renew` | lease `released`; task `pending` | +1 |
| `fail` | lease holder | as `renew`; closed `failure_class` | lease `failed`; task `failed` | +1 |
| `recover-expired` | controller expiry worker only | current maintenance owner and epoch; lease `active`, expiry ≤ now, lease fence equals task version, task `claimed` | lease `expired`; task `pending` (pure) or `reconcile` (external effects) | +1 |

`completed`, `failed` and `reconcile` are terminal for this slice. Doc 68 lets
`release` name a terminal disposition; this contract takes the narrower reading
and `release` always returns the task to `pending`. A handoff is `release` then a
fresh `claim` by the next principal with its own capability (doc 68 §4.3).

Tasks are declared in-process by the composing application through
`ControllerStore.declare_task`. Re-declaring identical content is a no-op;
different content for an existing `task_id` is refused. A network-facing task
submission authority is outside this slice.

## 4. Request envelope and idempotency

The claim kind panel is the doc 68 §4.2 request. Unknown fields are refused
(`extra="forbid"` semantics); required fields carry no default. Fields:

| Field | Rule |
| --- | --- |
| `schema_version` | exactly `"1"` |
| `operation` | `claim`, `renew`, `complete`, `release`, `fail` |
| `task_id`, `principal`, `idempotency_key` | opaque identifiers: `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` that do not look like topology (§8 scan) |
| `expected_task_version` | integer ≥ 1 |
| `source_ref` | opaque reviewed ref, 1–200 chars, no leading `/` or `~`, no `\`, no `..` |
| `expected_base_sha` | 7–40 lowercase hex (doc 69 §6) |
| `capability_proof` | opaque; consumed by the Phylax port only; never stored, logged or emitted |
| `lease_id`, `lease_token` | required for lease-bound operations, forbidden for `claim` |
| `result_digest` | 64 lowercase hex, `complete` only |
| `failure_class` | `worker_error`, `source_mismatch`, `abandoned`, `timeout`; `fail` only |
| `lineage` | optional; keys `on_behalf_of`, `prior_agent`, `prior_agent_status`, `takeover`, `superseded_ref` |
| `correlation_task_id`, `actor_principal_id` | optional projections; exact equality with `task_id` / `principal` |

**Claim-scope idempotency (IC-12, IC-13).** The key is
`(principal_id, operation, idempotency_key)`. The request digest is SHA-256 over
canonical JSON of every covered field: all fields above except
`capability_proof` and the projections; `lease_token` is covered by its SHA-256
digest. An identical replay returns the original committed receipt, marked
`replayed`. The same key with a different digest is refused `409
idempotency.key_reused`. Only committed transitions create idempotency records;
a refusal changes no claim state, so a retried refused request is evaluated
afresh. Workflow-scope idempotency is the application's and shares no table.

Replay still passes transport and capability checks first: a revoked principal
cannot read back an earlier receipt.

## 5. Fencing, expiry and the clock rule

- **Lease token.** 256 random bits (`secrets.token_urlsafe(32)`). `leases` stores
  only its SHA-256; comparison is constant time. The claim receipt, including the
  token, is kept in the private idempotency row so a timed-out client can replay
  its claim; it never enters `audit` or `outbox`.
- **Fence.** A lease's `fence` is the task version its claim produced. Every
  later transition increments the version, so a lease whose fence differs from the
  current version is stale, whatever its token.
- **Controller clock (IC-18).** The controller's injected clock is the only time
  source; a client never declares expiry. The effective time is
  `max(clock(), stored high-water mark)` and the mark advances in the same
  transaction, so a backward clock step cannot revive a lease.
- **Expiry rule.** A lease is expired when effective now ≥ `expires_at`. Every
  lease-bound operation requires now < `expires_at`. A late or partitioned worker
  is therefore refused `409 lease.expired` even before a sweep runs, and
  `409 lease.not_active` or `409 lease.fenced` after one.
- **Renewal racing expiry.** Renewal and recovery both run in `BEGIN IMMEDIATE`.
  Recovery re-reads the lease and uses compare-and-set updates
  (`WHERE lease_id = ? AND state = 'active' AND expires_at <= ?` and
  `WHERE task_id = ? AND version = ? AND state = 'claimed'`), so whichever commits
  first wins and the other observes the committed state.

## 6. Recovery and uncertain effects

Doc 68 IC-16 forbids reissuing work merely because a client timed out. Each task
is declared with an `effect_class`:

- `pure` — no external effects; an expired lease returns the task to `pending`.
- `external` — may have caused external effects; expiry cannot prove that none
  happened, so the task moves to `reconcile`. It is never reissued and never
  reported as success. Resolving it needs a reconciliation decision that is
  outside this slice (owner-held under C3d).

The expiry worker (`ExpiryWorker`) is opt-in. `start()` acquires the
`maintenance_owner` row for this database (refused `worker.owner_conflict` while
another owner's row is live), `status()` reports state and counters, and
`stop()` cancels between sweeps, waits for the current transaction, and releases
the owner row. Each sweep processes at most `batch_limit` leases in one
transaction that also verifies and extends the owner row; a worker whose owner
epoch was superseded is refused `worker.fenced` and stops. A repeated sweep finds
nothing to do. A crashed owner's row expires after its TTL, after which a new
worker may start.

## 7. Admission order and refusal vocabulary

Every request passes, in this order, before any task or idempotency row is read:

1. envelope validation and projection equality (IC-7, IC-8 partial, IC-28) → `400`;
2. Telos transport attestation via `TransportVerifier` → `401`;
3. Phylax capability via `CapabilityVerifier`, then the controller re-checks the
   decision's principal, operation, task scope, audience and expiry → `401`/`403`;
4. the store transaction (idempotency, task, lease, version) → `404`/`409` or a receipt.

Default ports deny everything. A port that raises is treated as a denial.

**2026-11-06 operator-confirmed timing rule (CL-1).** The controller samples
an aware clock again after capability verification and propagates the verified
expiry through `Admission.expires_at`. Under the SQLite write lock, before
idempotency or task lookup, effective controller time must remain strictly
less than that deadline. Expiry refuses the mutation; safe denial audit and
clock-highwater writes remain required. This capability deadline is distinct
from the claim's lease expiry and never authorizes a missing capability.

| Code | Status | Meaning |
| --- | --- | --- |
| `envelope.invalid` | 400 | malformed, missing or unknown field |
| `envelope.projection_mismatch` | 400 | projected task/principal differs from canonical value |
| `transport.unverified` | 401 | no Telos attestation, or verification failed |
| `capability.missing` | 401 | no proof presented |
| `capability.invalid` | 401 | proof rejected |
| `capability.unverifiable` | 401 | verifier absent, failing or returned an unusable decision |
| `capability.expired` | 401 | decision expired at controller time |
| `capability.revoked` | 401 | principal or proof revoked |
| `capability.insufficient` | 403 | operation, task scope or audience not covered |
| `capability.principal_mismatch` | 403 | proof bound to another principal |
| `lease.principal_mismatch` | 403 | lease belongs to another principal |
| `lease.token_invalid` | 403 | lease token does not match |
| `task.unknown` | 404 | no such declared task (extension; see below) |
| `task.already_claimed` | 409 | task is claimed |
| `task.not_claimable` | 409 | task is terminal or held for reconciliation |
| `task.version_conflict` | 409 | stale `expected_task_version` |
| `task.source_mismatch` | 409 | source line differs from the stored task |
| `lease.unknown` | 409 | lease id not found for this task |
| `lease.not_active` | 409 | lease already ended |
| `lease.fenced` | 409 | lease fence differs from current task version |
| `lease.expired` | 409 | controller clock passed the lease expiry |
| `idempotency.key_reused` | 409 | same claim-scope key, different request digest |
| `controller.busy` | 503 | write lock not obtained; no state changed |
| `task.declaration_conflict` | 409 | `declare_task` content differs for an existing id |
| `worker.owner_conflict` | 409 | another live expiry-worker owner |
| `worker.fenced` | 409 | expiry worker's owner epoch is superseded |

IC-24 names 400/401/403/409. `404 task.unknown` and `503 controller.busy` are
additions recorded here: both are determinate refusals that change no state.
No path returns a generic success for an indeterminate outcome.

Refusals at stages 2–4 are audited with the opaque principal (or `unknown`), the
operation and the code; proof material and lease tokens never enter the audit
row (IC-25).

## 8. Outbox and egress

The task mutation, its audit row and its outbox row commit in one transaction.
Outbox payloads are built from an allowlist (`event_id`, `kind`, `task_id`,
`task_version`, `state`, `lease_id`, `disposition`, `failure_class`,
`occurred_at` as integer microseconds, `lineage`) and then scanned for topology fragments (absolute or
home paths, backslashes, IPv4/IPv6 literals, `localhost`, `.local`/`.lan`/
`.internal`/`.home` hosts, `host:port`); a match aborts the transaction. The same
scan rejects topology-shaped identifiers at intake, so in practice the outbox scan is
defense in depth. Each row carries the payload digest and the allowlist digest; the
publisher refuses a row whose digests no longer match (IC-23 partial).

`OutboxPublisher.publish_pending` reads pending rows in sequence order, hands
each to an `EventSink`, and marks it published only after the sink returns.
Delivery is at least once; consumers deduplicate by `event_id`. The publisher
and the mark touch only `outbox.published_at`. No controller API ingests events,
so duplicated, reordered or forged events cannot create, renew, complete or
release a claim (IC-5).

## 9. IC-by-IC mapping

Tests live under `src/tests/orchestrator_controller/`.

| IC | Coverage in this slice | Evidence |
| --- | --- | --- |
| IC-1 | Partial: only this package writes the claim tables; SQLite transactions serialize concurrent controller instances. Single-process enforcement is a deployment decision (C3d). | `test_conformance.py::test_ic1_*`, `test_ic27_*` |
| IC-2 | Covered: an `availability` field is refused and leaves every table unchanged; no liveness input exists. | `test_conformance.py::test_ic2_*` |
| IC-3 | Covered for missing, invalid, unverifiable, expired, revoked and insufficient proof. | `test_ports.py` |
| IC-4 | Covered: denials precede task lookup (unknown task still yields `401`; store spy untouched). | `test_ports.py::test_ic4_*` |
| IC-5 | Covered: replayed, reordered and forged events cannot mutate state. | `test_outbox.py::test_ic5_*` |
| IC-6 | Covered: a verified transport alone never authorizes; capability requests carry no topology. | `test_ports.py::test_ic6_*` |
| IC-7 | Partial: claim envelope required fields carry no default. Common-header Tier U validator is owned by Core — not in this slice. | `test_envelope.py` |
| IC-8 | Partial: unknown fields refused; Tier C header declaration is Core's — not in this slice. | `test_envelope.py` |
| IC-9 | Not in this slice: the author/actor `lineage` requirement is a Core header validator. The controller persists supplied lineage in audit and outbox. | `test_conformance.py::test_lineage_*` |
| IC-10 | Covered: a handoff successor needs its own capability; lineage grants nothing. | `test_ports.py::test_ic10_*` |
| IC-11 | Covered: one transaction decides a claim; ten-worker races in threads and processes. | `test_store.py`, `test_conformance.py::test_ten_worker_*` |
| IC-12 | Covered: claim scope is principal + operation + key; no workflow table exists. | `test_store.py::test_ic12_*` |
| IC-13 | Covered: same request replays; changed content refused. | `test_store.py` |
| IC-14 | Covered: stale version returns `409` with state unchanged. | `test_store.py` |
| IC-15 | Covered: lease token, principal, fence and expiry required for every lease-bound operation. | `test_store.py`, `test_expiry.py` |
| IC-16 | Covered: client timeout replays rather than reissues; external-effect expiry is held in `reconcile`. | `test_expiry.py`, `test_conformance.py` |
| IC-17 | Covered: reopen preserves pending outbox and never reissues an unexpired lease, including after process kill. | `test_outbox.py`, `test_conformance.py::test_ic17_*` |
| IC-18 | Covered: no client operation expires a lease; recovery needs the maintenance owner; clock high-water rule. | `test_expiry.py` |
| IC-19 | Partial: source line required and mismatch refused. The worker-side fresh-worktree base proof is outside the controller. | `test_store.py`, `test_conformance.py` |
| IC-20 | Not in this slice: legacy-job disposition is owner-held under C3d. | — |
| IC-21 | Covered: allowlisted payloads; proof and token absent from audit and outbox. | `test_outbox.py::test_ic21_*`, `test_ports.py::test_ic25_*` |
| IC-22 | Covered for controller-emitted envelopes, receipts and events (topology scan). Published-document scans are repository hygiene, not this module. | `test_outbox.py::test_ic22_*` |
| IC-23 | Partial: payload and allowlist digests on outbox rows; card-level tamper evidence is Core's header. | `test_outbox.py` |
| IC-24 | Covered: vocabulary in §7; no generic success. | `test_ports.py`, `test_store.py` |
| IC-25 | Covered: denials audited without proof material. | `test_ports.py::test_ic25_*` |
| IC-26 | Covered: import scan allows stdlib, this package and `orama.graph.private_store` only; no PT, Phylax or Telos imports. | `test_conformance.py::test_ic26_*` |
| IC-27 | Partial: no other `src/orama` module touches the claim tables; application composition is not built yet. | `test_conformance.py::test_ic27_*` |
| IC-28 | Partial: task and principal projections reject before capability lookup; round projections do not occur on claims. | `test_envelope.py`, `test_ports.py` |
| IC-29 | Not in this slice: the common header is not accepted until Core's header validator exists; the envelope refuses it, so it cannot alter §4.2 semantics. | `test_envelope.py::test_header_not_accepted_*` |

### Doc 68 §10 acceptance mapping

| Criterion | Evidence |
| --- | --- |
| Concurrent claims produce exactly one active lease | `test_conformance.py::test_ten_worker_*` (one controller, ten connections, ten processes) |
| Same idempotency request replays; changed reuse rejected | `test_store.py` |
| Stale source line, lease, capability or version cannot mutate | `test_store.py`, `test_ports.py`, `test_expiry.py` |
| Restart preserves pending outbox; no unexpired lease reissued | `test_outbox.py`, `test_conformance.py::test_ic17_*` |
| Gossip replay cannot create, renew, complete or release | `test_outbox.py::test_ic5_*` |
| Unauthorized, revoked, expired fail closed and are audited without proof | `test_ports.py` |
| Event egress is redacted; topology scans clean | `test_outbox.py` |
| Testable without v1 runtime repositories | `test_conformance.py::test_section10_*`, `test_ic26_*` |

## 10. Rollback (draft, C3d not closed)

The module is not wired into any serving path, so rollback today is removing the
composition that constructs it. The database is controller-owned and additive;
rolling code back to a revision without a migration it recorded is refused at
open (newer schema). Do not delete a controller database that holds `active`
leases or `reconcile` tasks: export it for reconciliation first. No PT state is
read or written, so v1 coordination is unaffected by rollback.

## 11. Operational runbook (draft, C3d not closed)

- Start the expiry worker only by explicit composition; one per database.
- `status()` reports `running`, `stopped`, `fenced` or `failed`, sweep counts and
  the last refusal code. A `fenced` worker means another owner holds the
  database; do not force it.
- After a crash, wait for the owner TTL before starting a replacement.
- `reconcile` tasks require an operator reconciliation decision; the module has
  no automatic resolution for them.
- Back up the database file with SQLite's online backup, not a file copy, while
  WAL is active.

Missing for C3d: accepted security review, legacy-job disposition, accepted
rollback and runbook, Telos/Phylax contract review, and real adapters composed
outside `src/orama`.

## 12. Out of this slice

Network API and Telos-backed HTTPS surface; real Phylax/Telos adapters; common
header acceptance (IC-29); reconciliation tooling for `reconcile` tasks;
idempotency and audit retention clock; legacy-job disposition (IC-20); multi-host
qualification; any PT change.
