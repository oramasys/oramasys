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
| Durable clock mark | `observe_clock`, `clear_clock_quarantine` | A governed store persists the UTC high-water mark; a backward step quarantines dispatch and survives restart. Recovery is an audited administrative action (below) |
| Consumer abandon | `build_abandon_attestation`, `record_abandon_outcome` | Requires the committed fence and no 4.2 commit; the attestation has the issuer's eight fields; the authenticated outcome must name this attempt, permit and attestation digest, ends the attempt and records `release_authorized` |
| Sender precondition | `begin_send` | Refused (`send_precondition_failed`) unless the outbox row is complete, the attempt is authorized, not fenced and not abandoned |

## Choices to confirm (FREEZE-CHOICE 18 to 20)
18. An event in a catch-up envelope without an integer `version` is `catchup_malformed`.
19. A governed authorization records the clock observation durably even when it refuses; the "refused writes
    nothing" invariant therefore excludes the clock mark.
20. The retry delay is `min(4 s, 0.5 s * 2^failures)` and is refused when it exceeds the remaining budget; the
    numbers are starting values, not safety boundaries.
22. **Clock recovery follows the approved clock policy** (`CONTRACT-DURABLE-HITL-EFFECTS.md` section 5, and
    the draft's 8.2 step 6): `clear_clock_quarantine(operator=, trusted_time_evidence=, accepted_at=, now=)`
    needs an injected `OperatorAuthority` (no default; a None or blank reference raises `OperatorRefused`),
    non-blank trusted-time evidence and an existing quarantine. It appends the previous and the accepted
    timestamps, the evidence and the operator reference to `clock_reconciliations` (append-only), resets the
    mark to the accepted time (which may be earlier than the poisoned mark), and revalidates every pending
    reservation: one whose expiry is at or before the previous mark is marked `expired:<id>` for good, so the
    accepted time cannot revive it. Consumed, revoked and uncertain authority is untouched.
21. The clock mark's skew is the constructor argument `clock_skew_tolerance` (signed policy supplies the value).
    The default is zero, so any backward step quarantines (fail closed). A tolerated step never lowers the
    mark, a step one microsecond past the tolerance quarantines, an existing quarantine is never relaxed by a
    larger tolerance, and a value outside zero to five minutes is refused as a misconfiguration guard. The
    five-minute ceiling is a sanity bound, not a recommended value.

## Limits and open items
- Performing the reservation release belongs to the reservation owner; this store only records
  `release_authorized` after the authenticated abandon outcome.
- Revocation and cascade event body shapes, the effect grant v2 parser, retention and signed checkpoints, and a
  real operator authenticator are not built: the specification leaves them open or unfrozen.
- The shared interop probe is unchanged; extending it with abandon and successor scenarios needs both slice-2
  PRs merged and a paired pin bump.

## Decisions needed before serving is enabled
- **Skew value:** the approved clock policy is strict: a clock earlier than the mark is refused and alerted
  (`CONTRACT-DURABLE-HITL-EFFECTS.md` section 5), so zero is the contract default. A non-zero
  `clock_skew_tolerance` would be a deliberate relaxation needing a policy amendment; the 60-second figure
  in the draft (13.2) is the provider `NOT_ACCEPTED` window allowance, a different use.
- **Wiring the operator authenticator:** the role is the operator (an audited administrative action); the
  port exists and has no default. Binding it to the existing P5 trusted-human approval path is still to do.
