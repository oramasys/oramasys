# Execution witnesses (Part 3 section 4, gates 1 to 3)

**Status:** implementation contract for review. Dark by default: nothing records a witness in any
serving path, no sender is wired, and this ratifies nothing; `ORAMA_GRANT_SERVING` stays unset.
Section 4 of the Part 3 amendment leaves the witness contract open for a later slice; this document
proposes it for review and closes its three gates in code. Code:
`src/orama/graph/execution_witness.py`; tests: `src/tests/test_execution_witness.py`.

## Gate 1: field set, encoding, identity

Closed 14-field body: `schema_version`, `consumer_id`, `sequence`, `previous_witness_id`, `run_id`,
`attempt_id`, `grant_id`, `permit_id`, `ledger_store_id`, `outcome`, `revocation_version`,
`recorded_at`, `retention_owner`, `signer_key_id`. `outcome` is one of `started`, `committed`,
`aborted`, `fenced`, `unknown`. Canonical JSON (the consumer wire encoder). `witness_id` is the
SHA-256 of the canonical unsigned body, so identity is content-addressed; `sequence` and
`previous_witness_id` chain one consumer's witnesses from a genesis of 64 zeros. The wire adds
`witness_id` and a `signature` over the id. `recorded_at` must be timezone-aware and is converted to
UTC before signing; a naive time is refused (`witness.malformed`).

## Gate 2: medium, retention owner, durability

* `SqliteWitnessLog` is the local durable source of truth for what **must** exist. It is append-only
  and immutable by trigger, and idempotent per `(attempt_id, outcome)`, so a retry after a crash
  returns the existing record instead of forking the chain. A log file is bound to one consumer on
  first open (an older file to the consumer of its first witness); reopening it as another consumer
  is refused.
* A `WitnessMedium` port holds the published copy under immutable names `witness-<sequence>.json`.
  Which medium is a deployment decision; the contract is the port.
* The accountable `retention_owner` is a signed field of every witness, so the party responsible for
  retention travels with the record. Naming that owner and the retention period is an operator
  decision.

## Gate 3: authenticated read-back, failure is unavailable

`publish_pending` writes each witness, reads it back and compares bytes before marking it published;
`read_verified` re-reads the whole logged range from the medium and checks canonical bytes, identity,
signature, equality with the local record and the chain. A missing, unpublished, unreadable, forged,
swapped or out-of-chain witness raises `WitnessUnavailable`. It never returns a short list, and an
empty medium is never read as "nothing affected". Signing and verification are injected ports; the
module imports no crypto library (pinned by a test).

## Use in recovery

`affected_attempts(read_verified(...), revoked_grants=...)` returns attempts under a revoked grant
that show `started`, `committed` or `unknown` and no `aborted`/`fenced` witness. That is the
fail-closed recovery input Part 3 section 4 calls for; wiring it into `recover_lost_run` is a
separate change because it alters recovery behaviour.
