# Oramasys closure handoff — 2026-11-06

Canonical register: Orama repository,
`docs/v2/MASTER-CLOSURE-AND-IMPLEMENTATION-PLAN-2026-11-06.md`.
That register owns C0–C12 and D1–D3; maintain one shared status ledger.

Publication is held for the user's merge confirmation and push release. Verify
the actual merged producer/consumer revisions before continuing implementation.

Oramasys owns C2a and C3–C3d, the v2 Controller implementation and conformance
sequence, and C6/C7;
it supports operator C8: revocation availability under a
chosen workload, actual consumed-configuration binding, and deployment evidence.
Use `docs/revocation-capacity-handoff-2026-11-03.md`, the loaded-identity ADR and
`docs/serving-activation-runbook.md`. Source tests, private topology projections
and installed host qualification remain separately evidenced claims.

C8 collects actual identity/configuration evidence on both platforms. C9/R6
independently reviews that evidence at the exact revisions; C10/R7 then records
the operator's generation/pin decision, followed by C11/R8's separate activation
decision with canary, expiry and rollback. Ratified D3 requires
POSIX and native Windows evidence before any promotion. No host or service
manager is assumed here. Ratified D1 leaves PT manual and assigns automation
only to v2 with explicit expiry and fencing. D2 retains compatibility shims.

C3 must atomically check expiry and claim identity/version, fence the old worker
before reassignment, and preserve unknown effect outcomes for reconciliation.
Exercise renew/expiry races, partitioned workers, duplicate sweeps and restart.
Implement SQLite state and claim/idempotency first (C2a), then expiry (C3),
Telos/Phylax adapters (C3a), transactional outbox (C3b), isolated-worker
IC-1–IC-29 conformance (C3c), and security/operational closure (C3d).
Expiry-worker tests alone do not close the controller deliverable.
These ratified scope decisions do not release the current publication hold.
