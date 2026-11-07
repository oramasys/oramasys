# Serving activation runbook (operator)

Nothing here activates serving. `ORAMA_GRANT_SERVING` stays **unset** until the
operator ratifies the receipt.

## 1. Preconditions the operator owns

Dedicated serving UID; registry authority key ceremony done; archive medium and retention owner named;
independent reviewer assigned for Release R6; Phylax pin recorded; deployment
files (seed, issuer DB, public state) in place. This is distinct from the
operator-only C3d controller review.

Recording the pin is not effect-authority evidence: the current verify-only pin
(`requirements/compatibility-phylax-verify-only.txt`) is the recovery-grant verifier, which
[cannot authenticate effect authority](release12-process-crash-evidence.md#remaining-release-gates).
`serving_permitted` in `src/orama/deploy/profile.py` requires its injected `approval_matcher`
to return `True`; it does not itself read or validate a D6 record. Activation requires a trusted
matcher wired to verify the applicable D6 record. The default matcher never matches, and no D6
record exists in this repository.

## 2. Run the evidence script (as the serving UID, on the serving host)

```bash
export SERVING_UID SEED_FILE ISSUER_DB PUBLIC_STATE INSTALL_PLAN \
       CONSUMER_WHEEL CONSUMER_PROVENANCE PHYLAX_PIN_FILE ORAMASYS_CHECKOUT PYTHON
set -o pipefail   # keep the script's non-zero exit when tee succeeds
bash "$ORAMASYS_CHECKOUT/scripts/operator_serving_checks.sh" 2>&1 | tee serving-evidence.txt
```

It runs `qualify_serving_identity.py`, `verify_installed_identity.py` and `verify_phylax_pin.py` under
`python -I` from a scratch directory, prints the resolved input paths (the reviewer
compares them with the service configuration), each exit code and output digest,
and refuses if the switch is set.
Exit 0 means evidence was printed, not that activation is approved.

## Required qualification gates before the receipt and activation

The current [qualification handoff](release12-postmerge-qualification-2026-11-04.md)
records R4–R8 as open at its cutoff. Reconcile newer signed evidence and exact
producer, consumer, installed-artifact and configuration revisions before treating
any gate as complete. A successful evidence script alone does not close them:

1. **R4 and R5:** demonstrate access denial under the actual serving identity and
   verify the installed set. R5(b) also needs a reviewed collector outside the
   checkout that binds the configuration and policy actually consumed by the
   service to that installed set and identity; the public topology projection
   alone is not that receipt.
2. **R6:** obtain an independent review of the exact producer, consumer and
   deployment configuration after the host evidence is available.
3. **R7:** the authorized operator decides whether to create a new immutable
   generation and paired production/test pins after the preceding gates. Prior
   approvals for other candidates are not approval of this generation.
4. **R8:** activation is a separate operator decision with a scoped canary,
   expiry, monitoring and a tested rollback. Record the applicable approval
   record, including D6 where the governing activation plan requires it.

Verify the actual serving entrypoint constructs its dispatch store with
`governed=True`; the underlying store defaults to `False`. Neither a green CI
run nor a filled template proves that the deployed entrypoint enforces this.
Keep serving disabled if any required gate is missing or cannot be verified.
The R3/R4 names in graph compatibility documents describe a different gate
series (reducers/joins and durable resume), not these Release 1–2 gates.

## 3. Receipt

Fill `docs/templates/serving-activation-receipt.md` from `serving-evidence.txt`;
the independent Release R6 reviewer signs separately. The operator, not an
agent, decides whether to set the switch afterwards.

## 4. Rollback

Unset `ORAMA_GRANT_SERVING` and restart the service; no data migration is involved.
