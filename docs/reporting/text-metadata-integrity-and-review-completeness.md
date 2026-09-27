# Text-Metadata Integrity and Review-Completeness (oramasys v2)

**Owner:** `oramasys/oramasys` `scripts/reporting/`
**v1 origin:** mined from `orama-system` git-history-surgery reference card +
CIDF remote-content integrity companion (PR #357 / 2026-09-13 incident).
**Tools:** `report_pr.py` (comment-first default), `append_pr_summary.py`
(body-edit secondary path for the `## Summary` convention).

## Transport decision — `gh` is local, not Telos

`gh` is invoked as a **local trusted subprocess**. Do **not** route it through
Telos `request()`. Telos owns IdP and purpose-scoped HTTP dials; the `gh`
CLI's own auth (stored token / `GH_TOKEN`) is a different trust surface.
This is a decided choice in the ported tools' docstrings, not an open question.

## Rule 1 — choose the canonical representation before choosing a hash

| Target | Correct integrity relation |
| --- | --- |
| Git blob / tracked artifact / binary payload | exact bytes |
| Encoded transport reconstructed into a tracked file | exact decoded bytes + length/hash |
| GitHub PR/issue text metadata (body, comment) | canonical logical text — **at most one** trailing LF normalized out before comparison |
| JSON object with schema semantics | schema/value equivalence |

**Narrowed contract (do not regress):** remove at most one trailing LF before
hashing (`scripts/reporting/canonicalize.py`). An unbounded `.rstrip(b"\n")`
hashes `x`, `x\n`, and `x\n\n` identically and can hide a real loss of
meaningful trailing blank lines.

## Rule 2 — a new regression test passing is not TDD GREEN by itself

Run the whole neighboring test file, not just the new test.

## Rule 3 — do not resolve a review thread while the affected head is CI-red

`FINDING -> CURRENT HEAD -> RED PROOF -> MINIMAL FIX -> FOCUSED GREEN -> FULL GREEN -> RE-READ FINDING -> RESOLVE`

## Rule 4 — an automated review finding is scoped to the commit range it reviewed

A finding correct for a deliberate RED intermediate commit is not a veto of a
later GREEN fix the reviewer had not yet seen.

## Rule 5 — a CI-only compatibility dependency is not package metadata

Do not publish CI-only fixtures through package metadata or optional extras.
Install from a separate requirements file in CI.

## Rule 6 — a relayed incident report is a claim to verify, not a fact to inherit

Reproduce the central technical claim in isolation before building on it.

## Rule 7 — a client-side re-read is not a compare-and-swap

GitHub's PR-body PATCH has no usable server-side CAS (community discussion
[#50084](https://github.com/orgs/community/discussions/50084) — `If-Match`
returns 412 but the body updates anyway). Pre-write re-reads detect concurrent
edits *before* the check; the window between final check and write is real and
currently unclosable. State that bound honestly.

**v2 mitigation (does not close the race — avoids needing it for the common case):**
default reporting is comment-first (`report_pr.py`). Comments are independent
objects with no lost-update race. Body-edit (`append_pr_summary.py`) keeps all
three guards for the `## Summary` case only:

| Code | Meaning |
| --- | --- |
| `PR_BODY_E_STALE_ON_REREAD` | body changed after initial read |
| `PR_BODY_E_STALE_PREWRITE` | digest changed immediately before write |
| `PR_BODY_E_POSTWRITE_MISMATCH` | remote ≠ merged after write (canonicalized) |

Out of scope for this port: `PR_BODY_E_ANAMNESIS_UNRECORDED` (tentative; anamnesis
contract not mature enough to design against).

## Durable checklist

- [ ] Identify bytes vs structured values vs text metadata before hashing
- [ ] Trace every serialization boundary end to end
- [ ] Prefer `report_pr.py` unless the body `## Summary` convention requires a body edit
- [ ] Keep `canonicalize.py` as the single SSoT for trailing-LF normalization
- [ ] Runtime-prove each guard with a ledgered fake transport (not a source scan)
- [ ] Bidirectional structural test: catch guard addition *and* deletion
- [ ] Falsify before trusting — break each guard, confirm the test fails, restore
