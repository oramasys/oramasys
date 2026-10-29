# Release 1–2 remaining requirements

Status: draft requirements, 2026-10-29. This is a work list, not a qualification
claim. Nothing here activates serving, effects, T3–T5 or remote autonomy, and
no production pin is promoted by this document.

## Established (software evidence only)

- Evidence-mode run `40762683507` at harness `09cd1fb4bee8cbd7d29538620a3b4add49ef9221`:
  Python 3.11 and 3.12 each passed 2,550 tests with 0 skipped and all 21 required
  modules collected; both artifacts report `evidence=true`.
- The approval comment on PR #81 (`6479776651`) is unedited and binds consumer
  `02e4f6d7`, harness `09cd1fb4` and the manifest and coverage digests of the handoff.
- Since main `79536ac2`, no change to `pyproject.toml`, `requirements/generations/`,
  `requirements/ACTIVE-GENERATION.json`, `requirements/pin-promotion-record.v1.json`,
  the production Core pin file or `src/orama/`. The only pin edits are the
  test-only candidate files `effect-grant-test.txt` and
  `compatibility-phylax-effect-grant.txt` (`6b9ad567` to `cf3a300c`).
- The production Phylax pin is still `0c3e860749b3ff8f62e102679f1f415f8acf0a61`.

## Not established

The packet's own residual limits apply. In short: GitHub-hosted Linux on Python 3.11
and 3.12 only; synthetic scenario drivers; verify-only serving is same-UID and
local-only; Phylax is composition-only and the grant-serving extra is opt-in; effect
composition uses real producer signatures with inert drivers, so policy, approval and
revocation fixtures do not qualify a live deployment; serving-UID isolation and the
deployed artifact, configuration and policy identity remain operator evidence.
The packet also states that no production-pin promotion is qualified by it.

## Requirements

| ID | Requirement | Acceptance evidence | Where |
| --- | --- | --- | --- |
| R1 | Reviewed producer v2 effect-verifier API. The pinned Phylax recovery verifier cannot stand in for effect authority. | Public API spec and tests in Phylax; composition tests in oramasys using real signatures | Phylax, oramasys |
| R2 | Trusted consumer adapter that only verifies. The inspected dispatch adapter exposes issuer signing only. | Test that the consumer path cannot reach issuer signing; adapter verifies through the R1 API | oramasys |
| R3 | Authenticated approval and final-boundary composition. `scripts/serve_with_effect_grants.py` already refuses effects without the approval verifier, revocation view and issuer id ports. | Startup-matrix tests with the real ports wired; no sender wired unless the capability bit is effective | oramasys |
| R4 | Seed-read and issuer-write denial under the real serving identity. | Output of `scripts/qualify_serving_identity.py --expected-uid <serving uid> --seed-file <seed file> --issuer-db <issuer db> --public-state <public verifier state dir>`, run as that non-root serving user on the deployment (it refuses root or any other uid) and kept as operator evidence | Operator |
| R5 | Installed-set identity on the deployment, in two parts. (a) Package identity: consumer wheel and provenance, producer commits, Phylax URL, commit and install location. (b) Deployed configuration and policy identity. | (a) Output of `scripts/verify_installed_identity.py` and `scripts/verify_phylax_pin.py` from the deployed environment; these verify package, wheel digest, provenance, import location and the Phylax URL and commit only. (b) A configuration and policy identity receipt (digests of the deployed configuration and policy files). No script produces this yet, so it must be defined and reviewed first; R5 is not satisfied without it | Operator, oramasys |
| R6 | Independent reviews by a reviewer who did not write the code. | Written review per scope below, tied to exact commit SHAs | Reviewer |
| R7 | Repin after R1 to R6. A new generation, never an edit to an accepted one. | See the repin conditions below | Operator ratifies |
| R8 | Operator activation (deferred). Separate switches; `ORAMA_GRANT_SERVING` stays unset until then. | A separate operator decision and receipt | Operator |

### R6 review scope

Stale consumer; stale producer; omitted effect tests; missing human approval;
replayed or expired authentication; modified frozen generations; accidental
deployment-qualification claims. These match the review focus in
`requirements/effect-qualification/PLAN.md`.

### R7 repin conditions

1. R1 to R6 are complete and recorded against the exact commits being pinned.
2. A new generation folder is added under `requirements/generations/`, with its
   reviewed pinned expectations added in `src/tests/test_generations_g1.py`, as
   `requirements/generations/README.md` requires.
3. The production pin in `pyproject.toml` moves together with the file a test
   requires it to equal, `requirements/compatibility-phylax-verify-only.txt`.
4. The operator ratifies and merges. An agent prepares drafts and never promotes.

## Order

```text
R1 -> R2 -> R3 -> (R4, R5 in parallel) -> R6 -> R7 -> R8
```

R1 to R3 are code and can start now. R4 and R5 need the real deployment and cannot
be done from CI. R6 can review R1 to R3 as each lands, before R4 and R5 finish.

## Open questions for the operator

- Which Phylax commit will carry the v2 effect-verifier API (R1)?
- Which account is the serving UID for R4, and where is the deployment for R5?
- Who is the independent reviewer for R6?
