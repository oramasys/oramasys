# E1/C2 consumer slice 2

**Status:** implementation against the ratified E1 specification (`orama-system` main
`59c623fa27497183d3a1c4ed19585d87623eae22`), stacked on the T3 first seam (PR 67). No provider transport,
no serving, no pin change. `ORAMA_GRANT_SERVING` stays unset.

**Next actions:** independent review at the exact head; the operator merges PR 67 first and retargets this
PR to `main`; the open items below stay closed until the operator decides them.

## What it adds
| Piece | Where | Contract |
|-------|-------|----------|
| Request validators | `dispatch_consumer_wire.py` | The 12-field permit request and 8-field finalization request, validated like the issuer wires |
| Catch-up envelope | `catchup_envelope.py` | Exactly `from_version`, `through_version`, `events`; refusals in order `catchup_malformed`, `catchup_too_large` (more than 64), `catchup_range`, `catchup_gap`; an empty envelope only when already at `R_f` |
| Window and deadline | `finalization_window.py` | A finalization is requested only with at least 15 s left (exactly 15.0 allowed); deadlines read an injected monotonic clock |
| Circuit breaker | `circuit_breaker.py` | Opens on the 5th consecutive authenticated failure, one probe per 15 s, closes only on a usable response, a signed refusal is not a failure, alert after 120 s |
| Availability gate | `issuer_availability.py` | Deadline, then window (finalization only), then breaker; a refusal is the visible status `dispatch.issuer_unavailable`; bounded identical-retry delay |
| Durable clock mark | `observe_clock`, `clear_clock_quarantine` | A governed store persists the UTC high-water mark; a backward step quarantines dispatch until an operator reconciliation names a reference; it survives restart |
| Consumer abandon | `build_abandon_attestation`, `record_abandon_outcome` | Requires the committed fence and no 4.2 commit; the attestation has the issuer's eight fields; the authenticated outcome must name this attempt, permit and attestation digest, ends the attempt and records `release_authorized` |
| Sender precondition | `begin_send` | Refused (`send_precondition_failed`) unless the outbox row is complete, the attempt is authorized, not fenced and not abandoned |

## Choices to confirm (FREEZE-CHOICE 18 to 20)
18. An event in a catch-up envelope without an integer `version` is `catchup_malformed`.
19. A governed authorization records the clock observation durably even when it refuses; the "refused writes
    nothing" invariant therefore excludes the clock mark.
20. The retry delay is `min(4 s, 0.5 s * 2^failures)` and is refused when it exceeds the remaining budget; the
    numbers are starting values, not safety boundaries.

## Limits and open items
- Performing the reservation release belongs to the reservation owner; this store only records
  `release_authorized` after the authenticated abandon outcome.
- Revocation and cascade event body shapes, the effect grant v2 parser, retention and signed checkpoints, and a
  real operator authenticator are not built: the specification leaves them open or unfrozen.
- The shared interop probe is unchanged; extending it with abandon and successor scenarios needs both slice-2
  PRs merged and a paired pin bump.
