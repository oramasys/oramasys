# Oramasys closure handoff — 2026-11-06

Canonical register: Orama repository,
`docs/v2/MASTER-CLOSURE-AND-IMPLEMENTATION-PLAN-2026-11-06.md`.
That register owns C0–C12 and D1–D3; maintain one shared status ledger.

Publication is held for the user's merge confirmation and push release. Verify
the actual merged producer/consumer revisions before continuing implementation.

Oramasys owns C6/C7 and supports operator C8: revocation availability under a
chosen workload, actual consumed-configuration binding, and deployment evidence.
Use `docs/revocation-capacity-handoff-2026-11-03.md`, the loaded-identity ADR and
`docs/serving-activation-runbook.md`. Source tests, private topology projections
and installed host qualification remain separately evidenced claims.

C8–C11 follow actual identity/configuration evidence, independent R6 review,
operator R7 generation approval and separate R8 activation. D3 determines the
first platform; no host or service manager is assumed here. PT's v1 daemon and
the planned v2 job-claim Controller are distinct deliverables.
