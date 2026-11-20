# Controller replay migration ledger — source candidate

Canonical decisions: Orama `docs/v2/queue-fencing-and-recovery/decision-record.md`
§2, `amendment-drafts.md` §2.7, and `plan.md` Q-AGE.

Database migration 2 adds a private one-use retry-token table and records its
pinned digest. It preserves existing request digest calculation and wire schema 1.
New and empty schema-1 stores can migrate. A populated schema-1 store is refused
before migration statements, preserving its rows and high-water mark; no drain,
compatibility mapping, counter reset, or destructive cleanup is selected.
Schema-1 cross-version replay identity and recovery remain held until an accepted
disposition. Older binaries must refuse the recorded newer database version.
Rollback requires a compatible binary or a reviewed disposition, never deletion
of unresolved claims. This is a source candidate, not C3d-base acceptance or
deployment qualification; real SQLite host evidence, R4/R5 and R6 remain open.
