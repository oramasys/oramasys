# Release 1–2 R3: reconciliation and completion matrix

Status: software-only candidate; no serving, issuance, production repin or activation.

## Outcome and ownership

The common purpose of the recovery bundle and both completion plans is one
auditable authority chain: human procedural evidence at issuance, signed grant,
signed permit/finalization, authenticated complete current revocation, durable
consumer binding, and the existing single-use sealed send boundary. Retaining
evidence is not current authority. Current authority is not deployment
qualification. Neither authorizes activation.

Phylax owns signing and public cryptographic verification. Oramasys owns the
attempt journal, final boundary, and composition adapters outside `src/orama`.
The core remains crypto-free. Existing accepted generations, public refusal
vocabulary and frozen wire encodings are unchanged.

## Verified comparison inputs

| Input | Immutable reference | Meaning |
| --- | --- | --- |
| Bundle base | `40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d` | Historical Oramasys baseline, not the target tree |
| Oramasys main | `4a3be3f7bf3b2ca365993f960e705990c60102ca` | Merged revocation view, witnesses, T4 transport and compatibility façade |
| Existing draft #90 | `beb43afa5d64ad832bdf8b163c0fda10839f20ad` | Retained wires and composition regressions; extended, not duplicated |
| Phylax main | `36f67b9579089759110b06ca6ab7b9e1da259184` | Merged operator assertions, publication and retained checkpoints |
| Phylax test candidate | `97443e749977d20d7fc88a19b5e5a9422413927f` | Reviewed repair tree used by the separate source-level R3 CI lane; not a production pin |
| Historical handoff branch | `0ef905d2dea56093e3d4348c6b2d27ce078a17df` | Reference documents only; whole-tree replay would remove newer main behavior |
| Witness branch | `fdc11ee29dffbca925c144f5810e24110ffccd91` | Its behavior is already merged; preserve main's fixes |
| Activation-runbook branch | `1ea66930e040e36465ef4816403406113d9fd535` | Historical proposal; not activation authority |
| Recovery ZIP | SHA-256 `4353abde841134047114cc5139cfbbadbbbef38ec6c5bc521f45dd6bcecb6dbb` | All 17 payload checksums passed; raw/WIP duplicates are alternatives |

## Path-level three-way disposition

Compare historical intent with live main and retain only a missing safe delta.

| Repository/path | Historical candidate | Main/candidate reality | Synthesis |
| --- | --- | --- | --- |
| Oramasys `src/orama/graph/dispatch_attempts.py` | Patches 01/02 expose recorded revocation facts | Signed-state view and canonical binding validation already exist | No second diagnostic-as-authority path |
| Oramasys `src/tests/test_recorded_revocation_view.py` | Tests for 01/02 | `test_revocation_state_view.py` covers the authoritative view | Preserve stronger current tests; no duplicate implementation |
| Oramasys `src/orama/graph/dispatch_attempts.py` | WIP approval retention | #90 stores signed wires atomically | Harden against replacement, malformed or mismatched evidence, mutable constructor inputs and inconsistent committed rows |
| Oramasys `src/tests/test_signed_dispatch_authority.py` | WIP and duplicate raw recovery copies | #90 uses `test_retained_dispatch_authority.py` | One consolidated regression suite, not cumulative duplicate patches |
| Oramasys `src/tests/test_serve_with_effect_grants.py` | Missing-port/startup WIP | #90 includes dark composition regressions | Retain and rerun; do not activate the root |
| Oramasys `scripts/public_dispatch_approval.py` | WP5 public-chain adapter | Absent from main/#90 | Explicit inert-only public adapter; current issuer-scoped keys, grant proof, immutable chain and exact store binding |
| Oramasys `src/orama/graph/final_boundary.py` and `sealed_inert_driver.py` | Existing verify-only approval port | Preflight key verification alone permits a send-window trust change | Optional transaction-safe public-trust recheck is combined with, never substituted for, the existing mandatory grant check; snapshot before locking, no attempt-store access in callback |
| Oramasys `scripts/revocation_feed_adapter.py` | WP3/WP4 catch-up | Main has pure view but no durable composition adapter | Explicit synchronous authenticated catch-up, durable anti-rollback and fail-closed read surface; no network or daemon |
| Phylax `src/phylax/signed_public_state.py` | Unfinished WIP snapshot | Replaced by merged `revocation_publication.py` and `dispatch_retention.py` | Do not revive weaker in-memory proposal; audit the merged public surface |
| Phylax `src/tests/test_effect_grant.py` | WIP procedural-evidence changes | Merged `github_effect_approval.py` plus dedicated tests | Preserve existing issuance ownership; no agent-generated human ceremony |
| Phylax `operator_assertion.py`, `github_device_approval.py`, `revocation_publication.py` | Stronger merged replacements | New audit reproduced registry/cleanup-clock races, missing spent-claim directory sync and invalid publication boundaries | Repair the canonical modules with RED/GREEN regressions; do not add parallel ledgers or cryptography |
| Oramasys `scripts/deployment_identity_receipt.py` and its test | Arbitrary-path SHA receipt | Absent; deployment still unknown | Do not ship as R5(b): it does not bind loaded config and can expose guessing or parent-symlink risks |
| Oramasys `docs/release12-remaining-requirements-2026-10-29.md` | Patch 03 closes receipt gap | R4/R5 still host-bound | Keep gate open; software tests cannot close it |
| Oramasys proposal-era operator decision note | Patch 04 | Recovered conversation summary, not ceremony evidence | Preserve original in bundle; do not republish as ratification or signature |
| Oramasys immutable generations and production dependency pins | Suggested later promotion | Still frozen | No edits; test-only source candidate has a separate CI lane |

## Work-package status and acceptance

| Plan area | Software disposition | Remaining evidence/owner |
| --- | --- | --- |
| W0 / WP0 | Checksummed bundle, verified mains/PR and branch comparison | Original owner-held patch is still unavailable; recovered ZIP is not that original |
| W1 / WP1 | Merged GitHub procedural adapter and signed operator assertions retained | Operator ceremony and issuance provenance must be verified on the actual deployment; no MFA attestation claim |
| W2 / WP5 | Retained signed chain and public inert approval adapter | Independent review at final heads; real effects still require separately ratified attempt-specific authority |
| W3 / WP2–4 | Merged publication plus candidate durable consumer composition | Deployment transport, publisher identity/key provisioning, topology and freshness policy; no source-cache API implies a live feed |
| W4 | Merged checkpoint/retention code remains dark | Part 3 §§3.1–3.2 semantic ratification, full replay/restore equivalence and host crash/prune evidence remain separate gates |
| W5 | Existing continuation and unknown-outcome behavior preserved | No new scheduler; saved-frontier continuation and exhaustive process-crash proof are not claimed by this R3 patch |
| W6 | Merged guarded foreign transport retained | Actual Telos-backed dialer, admitted providers and host isolation remain separately gated |
| W7 / WP6–9 | Focused and broad local tests plus test-only immutable producer CI | R4 service identity, R5 installed/configuration identity, independent R6, operator R7 new generation and separate R8 activation |
| W8 | Merged framework-free façade retained | Versioned upstream differential matrix; no universal drop-in claim |
| W9 | Existing peer/lease ownership unchanged | Multi-host partitions, split-brain, deployment trust and telemetry qualification remain roadmap gates |

## R5(b): implementation prerequisites, not a guessed receipt

The deployment owner must identify the service UID, installed artifacts and the
exact configuration loader before this receipt can be implemented correctly.
Instrument that loader to capture immutable validated effective non-secret
configuration and policy identities. Do not hash arbitrary operator-supplied
paths and call that loaded configuration. Secret-bearing or low-entropy values
must not acquire a public bare digest; use a reviewed redacted public projection
or a separately keyed, operator-held commitment with explicit access policy.

Parent path and leaf identity must remain pinned through the actual open/read;
checking `lstat` once is not race protection. Bind the receipt to artifact hashes,
source revisions, service identity, loader/policy version and the same evidence
generation. Test parent/leaf replacement, symlinks, secret exclusion, loader
substitution, restart and mismatched artifacts before using it for qualification.

## Publication and follow-up

Reuse Oramasys draft #90, with one non-force push after local verification.
Publish at most one Phylax review branch if its audit yields a real delta.
No PR is merged by this round. A test-only producer checkout is not a production
repin or R7 generation. See the [original synthesis handoff](release12-r3-synthesis-handoff-2026-11-02.md)
for the historical candidate receipt; its earlier test counts are not this
round's final verification evidence.

## Adapter limits that must survive handoff

- `RevocationFeedAdapter.refresh` accepts an explicitly supplied complete feed
  from genesis, bounded by 4,096 events and 8 MiB by default; it does not fetch a
  remote feed, run a watcher or silently truncate history. A checkpoint bootstrap
  for a pruned consumer remains a separate reviewed contract. Missing history
  refuses rather than weakening the completeness requirement.
- Each instance begins unavailable, including after restart. A complete explicit
  refresh must reconcile its attempt-store acknowledgements before it can answer
  non-revoked. Preserve both consumer databases together; restoring/deleting both
  to an old backup defeats local anti-rollback and needs operator reconciliation.
- A removed historical verification key can prevent re-verifying the previous
  cache; key-history retention and compromise/rotation recovery need deployment
  policy, not an automatic reset of the durable floor.
- The transactional approval callback snapshots retained evidence before locking,
  then performs bounded local public-key, expiry and revocation checks. Injected
  trust/resolver callbacks must not call the attempt store or network. The
  deployment must define trust-update ordering; this is not a distributed atomic
  revocation claim across unrelated stores or machines.
- Phylax publication/retention currently imports POSIX `fcntl`. Windows execution,
  interprocess locking, ACLs and directory durability are not qualified by these
  macOS tests. Do not bypass or stub the lock to obtain a green Windows result.
