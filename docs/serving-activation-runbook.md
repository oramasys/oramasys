# Serving activation runbook (operator)

Nothing here activates serving. `ORAMA_GRANT_SERVING` stays **unset** until the operator ratifies the receipt.

## 1. Preconditions the operator owns
Dedicated serving UID; registry authority key ceremony done; archive medium and retention owner named;
independent reviewer assigned; Phylax pin recorded; deployment files (seed, issuer DB, public state) in place.

## 2. Run the evidence script (as the serving UID, on the serving host)
```bash
export SERVING_UID SEED_FILE ISSUER_DB PUBLIC_STATE INSTALL_PLAN \
       CONSUMER_WHEEL CONSUMER_PROVENANCE PHYLAX_PIN_FILE ORAMASYS_CHECKOUT PYTHON
set -o pipefail   # keep the script's non-zero exit when tee succeeds
bash "$ORAMASYS_CHECKOUT/scripts/operator_serving_checks.sh" 2>&1 | tee serving-evidence.txt
```
It runs `qualify_serving_identity.py`, `verify_installed_identity.py` and `verify_phylax_pin.py` under
`python -I` from a scratch directory, prints the resolved input paths (the reviewer compares them with the service configuration), each exit code and output digest, and refuses if the switch is set.
Exit 0 means evidence was printed, not that activation is approved.

## 3. Receipt
Fill `docs/templates/serving-activation-receipt.md` from `serving-evidence.txt`; the independent reviewer signs
separately. The operator, not an agent, decides whether to set the switch afterwards.

## 4. Rollback
Unset `ORAMA_GRANT_SERVING` and restart the service; no data migration is involved.
