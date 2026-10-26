# Release 1–2 review fixes and remaining deployment evidence

## Candidate boundaries

Phylax candidate `e3e954a0253d7d4b452af1da71348a06b23118ae` restricts issuance to
`inert.simulation` with single approval. Nonempty second-approval references
refuse before approval consumption or signing. This closes the false attestation
bug; it does not implement or qualify dual approval. The parser applies the
consumer's printable-ASCII, no-space, 1–1024-byte identifier grammar.

`EffectGrantLookup` resolves permit-admission facts from actual durable v2
issuance and verification. Recovery and production compatibility pins remain
unchanged. The separate effect candidate is recorded in
`requirements/compatibility-phylax-effect-grant.txt` and exercised by the
Python 3.11/3.12 candidate workflow.

Oramasys persists the signed wire and complete verified request binding. Permit
authorization checks that binding, and the trusted sender verifies the wire
again and checks the authenticated principal. The sender transaction checks
persisted permit/finalization expiry, acknowledged revocations, divergence and
clock quarantine before setting the single-send marker. Existing attempts
without send-authority evidence refuse inert sending. Migration creates additive
tables; it never invents authority for historical rows.

The authenticated `/effects/inert` route accepts only an attempt identifier.
`scripts/serve_with_effect_grants.py` wires the public verifier and trusted sender
only when the explicitly supplied configuration requests it. Default application
construction leaves effects disabled. No activation variable was set in this work.

## Evidence and limits

The real-signature integration covers v2 issuance, verified consumer projection,
issuer permit and finalization using the durable lookup, signature verification,
reservation consumption, one inert send, wrong-principal refusal and revocation
refusal. Admission policy ports in that test remain test fixtures: this is not a
qualification of a deployment's identity or policy provider.

The full Phylax suite passed: 714 tests, 91.21% coverage on Python 3.11.
The full Oramasys source suite passed with the producer source available:
2030 tests passed, 2 skipped. Fresh noneditable installs on Python 3.11.17 and
3.12.14 each passed the same 2030-test source suite with 2 skips. Both installed
producer provenance checks matched the candidate SHA above. Pytest still uses
the repository's configured source path; the separate isolated import checks
exercise installed package locations. These checks do not establish a sealed
deployment qualification.

## Required deployment evidence

`scripts/qualify_serving_identity.py` must run as the actual non-root service UID
with its existing seed path, issuer database and public verifier state. It
requires kernel denial of seed reads and issuer writes, successful public
verifier opening, and read-only database write refusal. Missing state and an
incorrect UID fail; file-mode inspection cannot produce a passing receipt.

No service UID, provisioned authority paths, or deployment configuration was
provided in this environment. Therefore actual identity isolation, authenticated
public-state publication/freshness under that deployment's threat model, sealed
deployment artifact/configuration evidence, and post-merge producer repinning
remain unqualified. A developer run cannot substitute for those results.

Independent reviews and separate operator activation remain subsequent steps.
Rollback disables effect composition while preserving all authority, attempt,
reservation, revocation and outcome records. Never retry an uncertain send.

## Follow-up: oracle gate, expiry and documentation

The optional real-signature test formerly contributed a skip to every baseline
oracle cell without Phylax. It now lives in `src/tests/effect_interop`, collected
only when the v2 module exists. The candidate job requires that API explicitly
with `ORAMA_EFFECT_INTEROP_REQUIRED=1`; an absent or broken producer fails that
job. Existing frozen qualification gates and skip allowances are unchanged.

The reported policy-r3/Python 3.11 cell was reproduced with the exact Core and
oracle dependency pins plus canonical registry profiles: 1951 passed, 5 skipped,
and its manifest result gate passed. One upstream Starlette/AnyIO deprecation
warning remains. The opt-in signed-effect and qualification-packet checks passed
76 tests with the real producer available.

Phylax `6b9ad5673ac402c0909c0218ccdcdd25c9ef90c6` adds an admission-only verifier
that permits expired facts only after signature and durable issuance checks.
The permit store returns `permit.grant_expired`; ordinary consumer verification
still refuses expiry. Its full suite passed 715 tests. Dependent Phylax PR 23
integrates that parent and uses the supported single-approval fixture in
`cc58716e7e4b7e01c9bb21b9c4a2d4adfc3d74f9`: 798 tests passed.

AST documentation audit of all changed Python files, including modules, classes,
nested functions and methods: Phylax PR 22 167/167; dependent PR 23 293/293;
Oramasys PR 77 154/154. These are docstring-presence counts, not executable
coverage percentages or an audit of unrelated repository files.

## R0-2 draft D2 integration (supersedes parts of the sections above)

This section records how the R0-2 draft D2 (stacked on this branch) changes the
behaviour described above. It is a draft; it is not an activation or
enablement record, and `ORAMA_GRANT_SERVING` stays unset.

- One canonical send path. `TrustedEffectGrantComposer` only verifies and
  binds. Its send re-verifies the durable signed grant, derives the attempt's
  final-boundary tuple from the store and goes through the sealed final
  boundary (`authorize_final_boundary`, then `begin_bound_send` with the
  single-use human approval). The plain `InertEffectDriver` is a store-level
  primitive only; `POST /effects/inert` accepts only `FinalBoundarySender`.
- The send-time rechecks (clock quarantine, missing or expired send authority,
  acknowledged revocation, divergence, anchor quarantine) are one helper,
  `_recheck_send_authority`, run inside the send transaction for every inert
  send, including the final-boundary send. The send-authority expiry is the
  earlier of the permit and finalization expiry compared as parsed instants.
- The signed grant is verified again inside the send transaction, after the
  send marker is written and before commit, so a revocation between the
  pre-check and the marker rolls the send back.
- `ORAMA_INERT_EFFECTS=enabled` is no longer enough. The composition root also
  needs the R0-2 capability record to make `effects` effective (with the
  startup refusal matrix) and the final-boundary ports. No operator signature
  verifier is wired, so in R0-2 no sender is ever wired and the route answers
  `404 serving.route_not_exposed`.
- `/effects/inert` errors use the contract body
  `{"error": {"code", "correlation_id"}}` with public codes only; the mapping
  from internal reasons is documented in `orama/api/public_errors.py`.
  Principal and binding mismatches have their own internal codes
  (`effect.principal_mismatch` maps to `deny.unauthorized_caller`,
  `effect.binding_mismatch` to `deny.malformed_grant`).
- In-doubt dispatch on `/effects/inert`: when the send marker committed but
  the outcome could not be proven or recorded (`SendOutcomeUnknown`: the
  simulation failed, its evidence was invalid, or the settlement write
  failed), the answer stays `503 deny.verifier_unavailable` and also carries
  `receipt_ref`, the opaque attempt reference (`attempt_ref_for`) of the
  durable attempt record. It is the same reference the startup reconciliation
  report lists and the eventual receipt carries. A pre-dispatch deny never
  carries a `receipt_ref`, so a caller can tell the two apart; an in-doubt
  attempt is reconciled by an operator and never retried. No public code is
  added.
- The authenticated principal is the single shared control-plane bearer's
  principal. Checking it against the attempt's bound principal proves that the
  caller holds that bearer, not per-caller ownership of the attempt.

### D2 hardening after the second verification round

Each item has a test that fails without the change; all of them only make
behaviour stricter.

- The single send path is enforced by the store. `begin_send` (and so the
  plain `InertEffectDriver`) refuses an attempt that has an effect-grant
  binding (`effect_grant_bound_send_required`), and `begin_bound_send`
  refuses one without the signed-grant recheck
  (`effect_grant_recheck_required`). Both refuse inside the send transaction
  before any write and record nothing, so the canonical path stays available.
- The composer commits the attempt and its effect-grant binding in one
  transaction (`create_bound_attempt`), so an authorization can never run in
  between and skip the effect-grant cross-check; `bind_effect_grant` refuses
  an attempt that already authorized without a binding.
- `begin_bound_send` refuses a caller issuer other than the one recorded in
  the attempt's send authority (`send_authority_issuer_mismatch`).
- A final-boundary refusal is never recorded over a started send: a request
  that loses the race to the send marker still gets its own refusal, but the
  attempt keeps only the winner's receipt.
- Approval and reconciliation-ticket expiry compare parsed instants, never
  formatted text; an unreadable stored expiry refuses.
- `/effects/inert` asks the `effects` capability when it is installed and
  again on every request. Its auth-failure hook answers the contract's
  `401 deny.unauthorized_caller` only while the route is exposed; on a dark
  route the middleware's plain 401 and the 404 for authenticated callers are
  unchanged, and a hook can never turn a denial into an allow.
- The composition root passes the effect store it opened to `create_app`, so
  the startup reconciliation report covers its in-doubt attempts.
- The internal reasons added here map to existing public codes; the closed
  public vocabulary is unchanged.
