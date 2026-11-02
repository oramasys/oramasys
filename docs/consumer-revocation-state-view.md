# Consumer view of the signed public revocation state (decision D3, consumer side)

**Status:** implementation contract for review. Dark by default: this is a pure `RevocationLookup`
adapter that wires nothing, enables no sender and ratifies nothing; `ORAMA_GRANT_SERVING` stays
unset. Per D4 the real approval and revocation ports are qualified in tests only. Code:
`src/orama/graph/revocation_state_view.py`; tests: `src/tests/test_revocation_state_view.py`.
Producer side: oramasys/phylax `docs/revocation-publication.md`.

## What it is

`SignedStateRevocationView` implements the final boundary's `RevocationLookup` over the issuer's
signed public state. The state is a signed *summary*: this view only ever adds refusals, and
`CompositeRevocationLookup` takes the union with the consumer's own acknowledged-event facts.

## Fail closed

Every one of these makes `revoked(...)` answer `True`, never "nothing revoked":

| Condition | Code |
| --------- | ---- |
| source absent or raising | `state.unavailable` |
| not canonical JSON, extra/missing fields, unsorted lists, bad head/digest pairing | `state.malformed` |
| signature invalid or key unknown to the port | `state.signature` |
| state names another issuer, or the query is for another issuer | `state.issuer_mismatch` |
| older than 60 s or more than 5 s in the future | `state.stale` |
| head version below the consumer's acknowledged head | `state.behind_acknowledged` |
| same version as the acknowledged head with a different digest | `state.head_conflict` |

## No cryptography in `src/orama`

The signature check is the injected `StateSignatureVerifier` port, as for issuer events. A test pins
that the module imports no crypto library. The Ed25519ph adapter used in tests lives in the test
file; the production adapter belongs outside `src/orama` and is an operator wiring step.

## Lockstep with Phylax

* `src/tests/vectors/revocation-lookup-v1.json` is Phylax's shared truth table, vendored byte for
  byte and pinned by SHA-256. The test runs every row through both the consumer's existing
  `dispatch_revocations.refusal_reason` and this view; both must agree.
* `src/tests/vectors/revocation-state-v1.json` is a golden state produced by Phylax's real
  `build_state` and verified here with an independent Ed25519ph implementation.

## Approval chain

The port carries no approval reference. Without an `approval_ref_for` resolver the view treats
every grant as having an undeclared approval, so any approval revocation refuses it (conservative);
with a resolver the match is exact. `""` means a single approval and matches no approval revocation.

## Review-driven tightening (2026-11-02)

- `CompositeRevocationLookup` treats any answer other than an exact `False` (including `None`) as revoked, matching the final boundary, so wrapping a broken member can no longer turn it into "not revoked".
- Signed state is rejected as malformed when `schema_version` is not exactly the integer `1` (`true` and `1.0` no longer pass) or when a cascade entry's `version` or `issuer_authority_version` is not an integer in range, or its `approval_id` is not a well-formed identifier string.
