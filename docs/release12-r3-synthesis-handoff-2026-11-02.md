# Release 1–2 R3 synthesis handoff

**Status:** software-only follow-up; serving and effects remain dark by default.

## What this change retains

This branch reconciles the 2026-11-02 recovery bundle against live merged
Oramasys `4a3be3f` and Phylax `36f67b9`. It retains one missing, compatible
consumer invariant: an authorization transaction stores the canonical signed
permit and finalization wires in an append-only table. The read surface returns
them only when both parse and retain canonical bytes, and it can reverify them
through the existing public `SignatureVerifier` port after restart.

This is retained evidence, not a fresh approval, a revocation decision, or an
effect enablement path. Historical rows without signed wires return no retained
authority and are not reconstructed from digests.

The branch also carries regression coverage for the existing verify-only
composition boundary: incomplete final-boundary ports refuse, the serving root
imports only the public Phylax verifier, and an unavailable verifier opens no
effect store.

## Three-way disposition

| Bundle area | Current synthesis |
| --- | --- |
| Recorded local revocation facts | Superseded by the merged signed-state consumer view; do not add a second, potentially misused allow path. |
| Malformed approval-binding guard | Covered by current canonical binding validation; no parallel diagnostic API is added. |
| Retained permit/finalization wires | Integrated as the atomic, append-only `retained_dispatch_authority` record. |
| Composition tests | Integrated where they prove the existing dark verify-only boundary. |
| Phylax signed-public-state proposal | Superseded by merged durable publication, feed, and checkpoint work. |
| Deployment config/policy receipt | Not integrated: arbitrary file digests and leaf-only symlink checks do not prove the loaded configuration or safely handle secret-bearing inputs. |
| Operator-decision note | Not republished: it is a conversation record, not a cryptographic ceremony or deployment receipt. |

## Verification on this branch

```text
186 passed
src/tests/test_retained_dispatch_authority.py
src/tests/test_dispatch_attempts.py
src/tests/test_serve_with_effect_grants.py
src/tests/test_effect_grant_composition.py
src/tests/test_revocation_state_view.py
```

## Remaining work after merge

1. Define and review a real public final-boundary approval adapter that verifies
   the retained signed chain against current trusted keys, current revocation,
   effect, attempt, operation, and finalization facts. Keep it outside
   `src/orama` if it imports Phylax, and retain the no-sender default.
2. Complete the consumer catch-up lifecycle against the merged Phylax signed
   publication/feed: durable cursor, authenticated completeness/freshness,
   restart, gap, fork, rollback, and crash tests. Only a complete, current,
   authenticated view may answer non-revoked.
3. Design R5(b) around the configuration actually loaded by the deployment,
   with a secret-safe commitment and parent-path race protection. Do not revive
   the rejected arbitrary-path digest script.
4. Run the complete candidate matrix at exact producer and consumer SHAs,
   including cross-repository real-signature, concurrent sender, process-crash,
   stale-publication, and malformed-substitution cases.
5. On the real deployment host, collect R4 serving-identity denial and R5
   installed-artifact/configuration/policy evidence. Windows ACL evidence must
   be collected on Windows; local CI cannot substitute for it.
6. Obtain an independent R6 review tied to the final candidate SHAs. Then, and
   only then, create a new R7 generation and rerun qualification at its actual
   pins. R8 activation remains a separate operator decision with rollback and
   canary evidence.

No item above is completed merely by this PR. `ORAMA_GRANT_SERVING` stays unset
and no real sender, issuer secret, grant issuance, production repin, or effect
activation is introduced here.

## Successor completion round, 2026-11-02

The sections above preserve the original `beb43afa` candidate receipt. They do
not describe the final expanded candidate. The
[path-level completion matrix](release12-r3-completion-matrix-2026-11-02.md)
now reconciles the recovery bundle, historical branches and current mains.

The successor adds public-only inert approval verification and explicit durable
authenticated-feed composition outside `src/orama`, without wiring them into
startup. Retained signed wires now also resist `INSERT OR REPLACE` and refuse
inconsistent committed authorization rows. Phylax has a companion review delta
for registry/nonce clock races, durable ceremony claims and publication shape
and genesis checks; the weaker recovered snapshot implementation is not revived.

The original remaining-work items 1 and 2 now have candidate software and
regressions, not production completion. Deployment transport and trust mapping,
Windows locking/durability, R4/R5 host evidence, independent R6, new-generation
R7 and separate R8 authority remain open. The first-round `186 passed` above is
historical; final verification and publication receipts belong to the successor
handoff. No accepted generation or production pin is changed.
