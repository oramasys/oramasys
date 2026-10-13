# ADR 56: Operator-Provisioned Recovery Grants and C4 Autonomous Tier

**Date:** 2026-10-13
**Status:** APPROVED POLICY; NOT DEPLOYED
**Decision scope:** Phylax grant authority and Oramasys recovery consumer

---

## Context

The adjustment-grant contract separates durable grant issuance and verification
from ledger consumption. The baseline is deliberately deny-all until a Phylax
verifier is composed into Oramasys. Recovery must remain auditable and
fail-closed when ownership, revocation freshness, quota state, or downstream
admission cannot be proven.

This ADR records the C4 policy selection. It does not provision keys, activate
autonomous recovery, or alter an existing deployed service.

## Decision

### Ownership

- **Phylax** owns seed provisioning, signing, public-key registry, issued-grant
  index, revocation, immutable key tier, issuance intent, and quota admission.
- **Oramasys** owns authenticated hold creation, durable recovery intent,
  injected verification, and transactional consumption against the StepLedger.
- The web-serving process uses a verify-only Phylax interface. It must not load
  a seed, P5 secret, or issuer-write capability.

### C4 caps

| Policy level | Grant constraints | Rate limit | Activation |
| --- | --- | --- | --- |
| Level 0 | `settle` only, `steps` basis, units `1..3`, fixed 900-second lifetime | 6 autonomous grants per rolling 3600 seconds per authenticated principal | Explicit Level 0 policy registration |
| Level 1 | Same immutable per-grant constraints | 12 autonomous grants per rolling 3600 seconds per authenticated principal | Reviewed isolated-issuer deployment plus explicit operator activation |

Quota counts accepted autonomous issuances across all runs, key rotations, and
policy revisions in the authoritative issuer domain. Expiry, revocation, and
consumption do not refund quota. Exact durable issuance retries return the
stored grant without consuming another slot. Human-gated grants do not consume
the autonomous quota solely because both may settle a hold.

### Recovery and identity

- A passive UNKNOWN hold never causes issuance. Recovery starts only through an
  explicit operator command.
- Recovery identity is a versioned canonical object that binds authenticated
  principal, store/run/hold identifiers, fencing epochs, requested units and
  basis, action, and evidence digest. It is persisted before issuance.
- New holds persist an authenticated creating principal. Legacy NULL-owner
  holds refuse autonomous recovery. Their existing authenticated human-tier,
  P5-gated settlement compatibility path remains available without inventing
  historical ownership.
- A later owner repair is a separate human-authorized, audited operation; it is
  never an automatic bulk backfill.

### Revocation and serving

Verification reads public registry data, the issued-grant index, and revocation
state through a read-only SQLite connection. A revocation observation older
than `REVOCATION_MAX_AGE_SECONDS = 60` refuses verification. The serving path
does not create, migrate, or write issuer state.

## Level 1 activation gate

Different file-owner UIDs, file modes, ACL output, key labels, or caller flags
do not activate Level 1. Before the higher quota is enabled, the operator must
approve evidence that demonstrates all of the following:

1. An isolated signer account and authenticated, run-scoped issuer invocation.
2. The serving and agent identities cannot read seeds or issuer-write state.
3. The verifier has an independently reviewed local transport or signed public
   state publication with a revocation-freshness proof.
4. The server is proven seed-free by startup, file-access audit, and read-only
   database-write refusal tests.
5. A versioned deployment-policy activation record binds the evidence to the
   selected quota level.

Until those conditions are met, Level 0 is the only permitted autonomous
policy. No automatic inference or configuration value may raise the cap.

## Consequences

- The shared control-plane bearer identifies one local-operator capability, not
  distinct agents. All callers using it share the Level 0 quota bucket.
- Same-user Level 0 remains an explicitly documented trust limitation: a
  process under the same OS identity can potentially access both seed files.
- The policy is intentionally separate from implementation rollout. PR merges
  do not demonstrate provisioning readiness, secret isolation, or autonomous
  activation.

## Non-goals

- No resident privileged recovery daemon.
- No automatic recovery, automatic legacy-owner assignment, or UID-only cap
  upgrade.
- No cryptographic implementation, key material, local paths, or credentials in
  this record.

## Required implementation evidence

The implementation must provide focused red/green tests and a real file-backed
issuance-to-authenticated-consumption flow covering exact retry, revocation,
seed-free serving, and read-only verification. The merge order remains Phylax
grant authority before Oramasys adjustment composition, because the latter
imports the former's public interfaces.

## References

- [Phylax adjustment-grant design](https://github.com/oramasys/phylax)
- [Oramasys adjustment-grant consumer](https://github.com/oramasys/oramasys)

The [Task 6 operator-provisioning and autonomous-tier plan](57-task6-operator-provisioning-and-autonomous-tier-plan.md)
is the implementation roadmap for this decision. This ADR controls policy;
implementation details in the plan must not weaken its quotas, isolation gate,
or recovery rules.
