# E1 T3 first effect-authorization seam (consumer side)

**Status:** implementation of the plan approved by the operator on 2026-10-19 against the ratified E1
specification (`orama-system` main `59c623fa27497183d3a1c4ed19585d87623eae22`). It adds no provider
transport, no retry, no serving, no pin change. `ORAMA_GRANT_SERVING` stays unset.

**Next actions:** an independent checker reviews this PR at its exact head; the operator merges;
provider transport, retry of `unknown`, serving and production pin promotion stay closed.

## What it adds
| Piece | Where | Contract |
|-------|-------|----------|
| Proposal | `effect_proposals` table, `SqliteAttemptStore.propose` | Records the six-field scope (principal, graph, policy hash, operation digest, artifact identity, destination). Carries no authorization state; exists before any grant lookup. |
| Reservation | `reservations` table, `SqliteAttemptStore.reserve` | Binds one proposal's scope to one use with an expiry. The scope passed must equal the proposal's. |
| Consumption | inside `authorize_dispatch`, same `BEGIN IMMEDIATE` as rules 1-6 | A governed store consumes the attempt's reservation or refuses: `scope_required`, `reservation_unknown`, `reservation_consumed`, `scope_mismatch`, `reservation_expired`. A refusal rolls everything back. |
| Outcome | `outbox.outcome`, `effect_outcomes.check_transition` | Only `confirmed`, `failed`, `unknown`. Authorization writes `unknown`. `unknown` settles to `confirmed` or `failed` only with a non-blank evidence reference; both are terminal. |
| One send | `outbox.send_started`, `begin_send` | The single allowed send is marked durably before it starts. A second send is refused (`send_already_started`); an outcome cannot be recorded before a send (`send_not_started`). |

## Limits that remain
- `governed` defaults to False so the slice-1 callers, tests and the byte-identical interop probe keep
  working. A test (`test_no_product_code_builds_an_attempt_store_without_governed_true`) fails if any
  module under `src/orama` builds the store without a literal `governed=True`, so a forgotten switch
  on a product path cannot merge silently. Flipping the default to True, with the probe and the
  slice-1 tests updated, is a precondition for enabling serving.
- Nothing here proves a provider applied or refused an effect. `confirmed` and `failed` record an evidence
  reference supplied by a later reconciliation step that does not exist yet.
- Reconciliation, provider transport and the issuer-side revoke-versus-consume race are out of scope.
