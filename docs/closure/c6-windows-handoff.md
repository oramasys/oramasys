# Native Windows C6 Design and Qualification Handoff

Date: 2026-11-07. Originating author: claude-sonnet-5-5, self-reported,
unverified identity; source artifact `2026-11-07-windows-c6-design-handoff.md`.
Integrating actor: codex-reviewer, self-reported, unverified identity.
K9 places this handoff beside the [Mac runbook](c6-qualification-runbook.md)
in the same C6 candidate. This is a design assignment and evidence request,
not qualification, acceptance, deployment, pin promotion or serving authority.

## Boundary and Inherited Contract

Decision D3 requires both POSIX and native Windows qualification before
promotion; neither substitutes for the other. Keep `ORAMA_GRANT_SERVING`
unset. No credential, trust, firewall, service-account, ACL or antivirus
configuration change is authorized by this document. Propose required
changes for operator approval rather than silently weakening a control.

- Selected baseline: Python 3.13.18 / SQLite 3.53.1. Verify the actual
  Python-linked engine, source ID and build; a CLI version is insufficient.
  The runtime gate accepts mainline SQLite >=3.51.3. Earlier official
  backports need separate provenance review, not a version-string bypass.
- Workload: 256 complete-from-genesis events, eight senders at five sends
  per second each, 2,400 sends, separate refresh every 15 seconds; two
  retries with 50 ms pauses for the existing retryable refusal only.
- Both scheduled and successful-call p95 <=60 ms, operator re-ratified
  2026-11-07 from 50 ms; scheduled p99 <=250 ms; first-attempt
  unavailability <=1%; final errors <=0.1%; steady refresh p95 <=1,000 ms;
  zero refresh failures. Test zero fail-open through the adversarial suite,
  not the performance harness alone.
- Error-rate point estimates and statistical bounds are separate. Zero
  errors in 2,400 sends gives a one-sided 95% upper bound about 0.1247%,
  not a population guarantee <=0.1%. Report temporal-correlation limits.

## Establish Native Facts First

Report verified or unverified status for each fact, without exporting
workstation identities or private paths in shared evidence:

1. Windows edition/build, service-manager type and actual service-account
   class; use a local-only mapping for concrete identities.
2. A local NTFS volume for SQLite/WAL files, outside network shares and
   synchronization directories; record sanitized volume evidence.
3. Whether Python 3.13.18 is available for this Windows architecture and
   the exact SQLite embedded in the selected build. Do not infer Windows
   availability from the Mac distribution.
4. Existing antivirus/indexer treatment of that data directory. Observe
   and report it; do not create an exclusion without operator approval.
5. Native handle/file capacity. The POSIX 7,367-descriptor estimate is
   not a verified Windows capacity requirement or qualification receipt.

## Dependency Order and Deliverables

### Tier 1: Runtime and Standard-Library Evidence

Use the actual serving interpreter for the C7/C8 runtime receipt:

```powershell
& $ServingPython -I scripts/c6_runtime.py
if ($LASTEXITCODE -ne 0) { throw 'SQLite serving-runtime qualification failed' }
```

Keep its JSON receipt. Run the reviewed standard-library SQLite lock
experiment three times on the selected NTFS volume, preserving every
output and the experiment digest. A stdlib experiment can run before
the producer is portable; it does not qualify the full adapter.

### Tier 2: Reviewed Producer-First Portability Slices

Inspection of Phylax `1d2f2bb2ed7792c48f6320da36de9bc7459f0da3`
found unconditional top-level `fcntl` imports in
`phylax/revocation_publication.py` and `phylax/dispatch_retention.py`.
The adapter imports the publication module, so this producer pin blocks
native Windows benchmark import. Recheck these facts at the chosen head;
do not stub `fcntl` or silently substitute another producer.

Design and review the Phylax portability slice first, preserving durable
publication and retention locking through its platform filesystem layer.
Then address Oramasys `scripts/reporting/grant_lib.py` locking and any
POSIX identity assumptions (`geteuid`, `O_DIRECTORY`, mode bits) with
reviewed SID/ACL and reparse-point semantics. Each slice must identify
owned paths, RED regressions, refusal behavior and rollback. A mocked
portable import is not proof of real Windows durability or access control.

### Tier 3: Full Native Qualification

After Tier 2, freeze exact producer/candidate/runtime/dependency identities.
Preserve absolute arrival schedules, complete outcome/error accounting,
unchanged retry policy and the same metric populations as the Mac harness.
Run controls A (no refresh) and B (one sender), then three consecutive
operator-run candidate passes. Preserve unique JSON, JSONL and stderr
receipts, including failed cells; do not cherry-pick or overwrite trials.

Include native tests for sharing violations and bounded `os.replace`
retries, FULL durability cost, WAL behavior, owner-only ACL enforcement,
junction/symlink refusal, long paths and 8.3 aliases. Exercise actual OS
denials as the service account with operator supervision. Do not weaken
security semantics merely to make POSIX tests pass on Windows.

## Mac Comparison: Agent Diagnostics Only

With the same corrected harness and patched runtime, the original adapter
recorded 7 final errors in 2,400 sends, scheduled p95 about 93 ms, p99
625 ms and maximum cache write hold about 593 ms. The candidate moved
exact-input crypto outside ingestion locks and preserved under-lock trust,
byte and durable-clock checks. Two agent diagnostics recorded zero final
errors, scheduled p95 47.6 to 57.7 ms, p99 132 to 209 ms and maximum
write hold below 7 ms. First-attempt unavailability was 2/2,400 and 0/2,400.
These are explanatory Mac observations, not Windows predictions, operator
passes or proof that every workload meets the amended budget.

## Review and Return Evidence

### PR 98 review closure and native-agent checklist

The review fix creates new parents and stores with an explicit current-token
user owner and protected DACL, allowing only that user, SYSTEM and
Administrators. Directory grants inherit into SQLite sidecars. Python 3.11+
uses the same Win32 security mechanism, not POSIX `mode=0700` emulation.
Existing parents, databases and sidecars are inspected, never silently repaired.
An elevated token's default owner does not authorize accepting arbitrary
existing administrator-owned stores.

Native CI observed that ordinary sidecar creation under an elevated token can
choose Administrators as owner, even beneath a protected parent. Such existing
sidecars deliberately refuse rather than being repaired or accepted globally.
This candidate does not qualify elevated SQLite WAL operation: native agents
must test the actual service token and full create/reopen lifecycle. Prefer the
reviewed non-elevated service identity; do not change its privileges silently.

Creation and later validation still perform separate pathname resolutions.
New-file security is inspected through its handle, but this is not a
handle-relative traversal guarantee for the parent or ancestors. The selected
deployment location must have ancestors that unrelated users cannot write,
rename or replace with junctions/reparse points. Do not qualify a shared or
attacker-writable namespace. If that precondition cannot be established, block
qualification pending a separately reviewed handle-pinned traversal design.
No test here proves isolation from the same user or an administrator.

The native CI lane tests Windows Python 3.11, 3.12 and 3.13. Linux simulations
are not native Windows security evidence. Native cases live in `tests/windows/`
and run in their dedicated required evidence lane; platform-independent ACL
policy tests remain in the application suite. Linux compatibility-oracle skip
budgets are unchanged. Native-agent tasks:

1. Freeze source head, interpreter/build, SQLite source ID and NTFS facts.
   Use a disposable checkout and test directory, never production data.
2. Run under the actual non-elevated serving account, then in a separately
   authorized elevated test shell. The created-store test must pass in both.
   Record token class without publishing the actual account name/SID.

   ```powershell
   $env:PYTHONPATH = 'src'
   python -m pytest -q tests/windows/test_private_store_native.py
   if ($LASTEXITCODE -ne 0) { throw 'Native security verification failed' }
   python -m pytest -q src/tests/test_private_store.py -k 'safe_replace or nonce_lock_failure'
   if ($LASTEXITCODE -ne 0) { throw 'Replacement/lock verification failed' }
   ```

3. Provision a foreign-owned disposable fixture through an approved second
   principal. Set `ORAMA_TEST_FOREIGN_OWNER_FILE` locally and rerun the native
   suite. The test reads but does not modify that fixture. Without it, report
   the negative-owner case as skipped, not verified.
4. Confirm existing administrator-owned objects are refused for a different
   token user. Exercise actual second-account read/write denial for the parent,
   database, WAL and SHM. Everyone-grant tests alter only their own temporary
   fixtures; never grant access on real data.
5. Establish trusted-ancestor ACL/rename restrictions and test real junction
   refusal and handle cleanup. Test SQLite WAL creation/reopen and advisory-lock
   serialization across actual processes. Mocks do not establish these claims.
6. Continue Tier 3 full producer/consumer controls and qualification above.
   Preserve failed trials and return sanitized receipts and unresolved limits.

`safe_replace` uses deterministic backoff: five default sleeps total 62 ms,
without jitter. Only explicit WinError 5/32 candidates retry. WinError 5 can
also be permanent ACL denial, so exhaustion propagates it. Missing-source,
cross-device and POSIX permission failures propagate immediately. The original
implementation overgeneralized contention to every Windows `OSError` and
duplicated subclass/base-class handlers. That was correctness debt, not a team
style requirement. Do not repeat the old description's unimplemented jitter.

These source fixes do not close Windows qualification, independent review,
promotion or activation. Both platforms must supply evidence before the
C8 → C9/R6 → C10/R7 → C11/R8 sequence can close.

Return sanitized facts, exact source/build identifiers, experiment digests,
test outputs and a design per slice through the approved peer inbox or
GossipBus. Preserve originating author, current actor, bounded review and
any takeover separately. Keep raw databases and concrete topology local.
No endpoint is considered delivered without its receiver receipt.

The operator accepts exact revisions; agents cannot convert measurements
into approval. Windows remains unqualified until its native gates and
receipts are independently reviewed and accepted. This handoff neither
starts a listener nor authorizes a push, merge, deployment or activation.
