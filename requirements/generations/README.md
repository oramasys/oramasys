# Generation records (G1, data only)

Each folder is one immutable, named compatibility generation: copies of the bound inputs, the
registry snapshot, the published evidence digests and a canonical inventory
(`generation.json`: path, sha256, size, role, plus an inventory digest). The records are
migrated from sources that are retained where they were; nothing is moved or rewritten.

- `m1-gen1`: harness `3332b615`, consumer `f8898b35`, run `38916773943`. Sources:
  `requirements/history/m1-gen1/` and `src/tests/fixtures/graph-ownership-registry-m1-gen1.json`.
- `m1-gen2`: harness `902d2a8e`, consumer `133553a6`, run `39070456148`. Sources: the live files
  at the time of the migration.

Rules (design: orama-system `docs/v2/references`, virtual-versioning design, G0 approved):

- Accepted generations are never edited. A change is a new generation and a reviewed addition to
  the pinned expectations in `src/tests/test_generations_g1.py`.
- Nothing at runtime, in CI, in a script or in the install path reads these folders, and there is
  no active-generation pointer yet. The tests check that.
- A generation carries no status here. States, the pointer and rollback receipts belong to later,
  separately reviewed stages (G2 and G3).
