# C6 Revocation Availability Qualification

## Boundary and Ownership

This is an inert diagnostic/qualification harness, not serving activation. Keep
`ORAMA_GRANT_SERVING` unset. Agent diagnostics do not satisfy the three
operator-run Mac passes. Native Windows qualification remains separate. No K4
commit is permitted until the applicable safety suites and those three passes
complete. Accepted PR #95 remains untouched; no push, new PR or merge is implied.

The owner plan and Claude review are the dated 2026-11-07 C6 reference documents.
The first diagnostic used UNMODIFIED base `89da844c` before any harness or adapter
edit. Python 3.13.18 / embedded SQLite 3.53.1 reproduced seven final errors/2400,
send p99 412.79 ms and refresh p95 1007.49 ms. Updating SQLite fixes a correctness
hazard; it is not evidence of a contention repair. Old and scheduled-time
percentiles are not equivalent measurements.

## C7/C8: Actual Serving Interpreter Evidence

The production attempt store already enables WAL. Its actual serving Python,
not just a CLI or the benchmark Python, must carry the WAL-reset fix. Record the
following separately on macOS and native Windows using the Python executable
that the service manager/configuration actually launches:

```bash
"$SERVING_PYTHON" -I scripts/c6_runtime.py
```

```powershell
& $ServingPython -I scripts/c6_runtime.py
if ($LASTEXITCODE -ne 0) { throw 'SQLite serving-runtime qualification failed' }
```

This preflight refuses mainline SQLite older than 3.51.3. Official backports
3.44.6 and 3.50.7 need separately verified provenance and are not accepted by
this minimal gate. Record exact Python, SQLite source ID, compile options and
crypto package/build evidence; compare those exact fingerprints between runs.
A newer fixed patch release passes the floor but requires a fresh comparison
baseline. This command is deployment evidence, not a modification to startup,
the service manager, a production dependency pin, or an activation approval.

## Isolated Environment

Use a dedicated Python 3.13 environment with pinned test/crypto dependencies.
The selected initial build is CPython 3.13.18 / SQLite 3.53.1. Record the full
Phylax source SHA, resolved dependencies and wheel/build evidence. Do not reuse
another Python version's site-packages. Producer-present qualification and the
intentionally producer-free base suite are independent lanes.

```bash
PY=/private/tmp/codex-c6-python313-runtime-20261107/bin/python
export PYTHONPATH="src:scripts:$PHYLAX_SOURCE/src"
export ORAMA_R3_INTEROP_REQUIRED=1
unset ORAMA_GRANT_SERVING
$PY -I scripts/c6_runtime.py
```

Run from the K4 worktree. Operator supplies `PHYLAX_SOURCE`, `EVIDENCE` and
`TMPDIR`: both directories must be protected and on the approved local APFS
volume. Capture actual filesystem/volume identity rather than infer it from
`--label`. Do not place SQLite/WAL files on a network filesystem. Preserve the
current process FD limit; the harness refuses insufficient capacity and does
not raise it. On Windows missing POSIX resource checks mean not checked, not
qualified; collect native capacity evidence separately.

## Workload and Receipts

First run the unchanged adapter/store baseline with the same corrected harness,
patched runtime and dependencies as the candidate. Keep the original unmodified
diagnostic as historical evidence, not an apples-to-apples scheduled baseline.
Then controls:

```bash
$PY scripts/benchmark_revocation_availability.py --events 256 --senders 8 --sends 100 --send-interval 0.2 --refresh-interval 0 --refresher separate --retries 2 --samples-jsonl "$EVIDENCE/control-a.jsonl" --label "Mac APFS no refresh"
$PY scripts/benchmark_revocation_availability.py --events 256 --senders 1 --sends 600 --send-interval 0.2 --refresh-interval 15 --refresher separate --retries 2 --samples-jsonl "$EVIDENCE/control-b.jsonl" --label "Mac APFS one sender"
```

Freeze the reviewed candidate with an owned-path index and `git write-tree`.
Record base SHA, tree SHA, harness digest, runtime/dependency/producer identity,
full test results and crypto timing. Run the following THREE times, with distinct
run-1/run-2/run-3 JSONL/JSON/stderr files and no intervening candidate changes:

```bash
$PY scripts/benchmark_revocation_availability.py --events 256 --senders 8 --sends 300 --send-interval 0.2 --refresh-interval 15 --refresher separate --retries 2 --samples-jsonl "$EVIDENCE/run-1.jsonl" --label "Mac APFS candidate run 1"
```

Each run must account for all 2400 sends and refresh overlap. The harness uses
absolute schedules and includes queue delay and failed outcomes. Its primary
acceptance metric is `scheduled_latency`, not successful-call-only `send_latency`.
Require scheduled p95 and successful-call send p95 <=60 ms (operator
re-ratified 2026-11-07; previously 50 ms), scheduled p99 <=250 ms;
first-try unavailability <=1%; final
errors <=0.1%; steady refresh p95 <=1000 ms; zero refresh failures and zero
fail-open in the accompanying adversarial suite. Review all outcomes, not just
retryable unavailability. Retries are limited to the retryable approval-verifier
unavailable reason, twice, with 50 ms pauses. Unknown worker failures fail the
cell rather than disappear from its denominator.

Cold initialization is reported separately as `initial_refresh_ms` and
`cold_cache_lock_spans`. Steady refresh includes snapshot construction and
adapter time with raw stage records. Cache write acquisition wait and actual
hold through commit/rollback are distinct; record raw spans and hold p50/p99.
The wait envelope includes connection setup and BEGIN acquisition; the hold
envelope conservatively includes context exit/connection close after commit.
Compare those with the unchanged 100 ms cache busy timeout as explanatory
evidence; no new numeric hold-time SLO is ratified. The instrumented adapter
subclass exists only in the harness; it changes no production diagnostics.
Error evidence contains classes and SQLite codes/names, not exception messages,
locals, environment dumps or secrets. JSONL files are exclusively created and
must never overwrite earlier evidence.

Report exact counts and one-sided 95% binomial upper bound separately. Zero
errors/2400 yields about 0.1247%, not <=0.1%; temporal correlation further limits
the independent-trial interpretation. A longer confidence run needs operator
agreement and a bounded-resource harness: do not bypass the existing sends/FD
caps or preallocate 144000 stores blindly.

## Safety and Completion Gates

- Public ingest still verifies duplicate signatures and refuses forks, gaps and
  below-anchor events. The private prepared verifier is exact-input and
  trust-sampled; a miss never starts crypto under the store lock.
- Test changed/absent/once-raising trust, caller mutation, previous-cache changes,
  concurrent refresh, clock rollback/expiry, and process exit after ack before
  freshness. Denials may lead freshness after a crash; freshness cannot lead
  acknowledgements. Keep FULL and durable time observations on refusals.
- Do not increase timeouts, merge clock transactions, restructure lock ordering
  or add cache WAL unless the first candidate demonstrably misses budgets and
  the next measured design is reviewed. In-memory/group-committed clocks require
  a separate security decision.
- After all gates, local logical commits may be made with repository hooks;
  final commit tree must equal the measured tree. Hook edits invalidate results.
  Obtain fresh operator authentication plus exact-head C3d acceptance; do not
  represent account control as an independent review or new second factor.
- Native Windows qualification, deployment/pins and serving activation are
  independent remaining gates. A Mac diagnostic is not any of those receipts.
