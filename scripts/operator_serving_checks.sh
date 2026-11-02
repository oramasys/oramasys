#!/usr/bin/env bash
# Run the three serving-host checks and print evidence. Read-only: creates no accounts, keys,
# permissions or activation records, and never sets ORAMA_GRANT_SERVING. Run as the serving UID.
#
# Required environment (no defaults; nothing is guessed):
#   SERVING_UID, SEED_FILE, ISSUER_DB, PUBLIC_STATE   serving-identity isolation inputs
#   INSTALL_PLAN, CONSUMER_WHEEL, CONSUMER_PROVENANCE installed-set identity inputs
#   PHYLAX_PIN_FILE                                   pin file for the Phylax pin check
#   ORAMASYS_CHECKOUT                                 checkout holding the scripts
#   PYTHON                                            interpreter of the installed environment
set -u
fail=0
for name in SERVING_UID SEED_FILE ISSUER_DB PUBLIC_STATE INSTALL_PLAN CONSUMER_WHEEL \
            CONSUMER_PROVENANCE PHYLAX_PIN_FILE ORAMASYS_CHECKOUT PYTHON; do
  if [ -z "${!name:-}" ]; then echo "MISSING $name" >&2; fail=1; fi
done
[ "$fail" -eq 0 ] || { echo "RESULT: NOT-QUALIFIED (inputs missing)"; exit 2; }
if [ -n "${ORAMA_GRANT_SERVING:-}" ]; then
  echo "RESULT: NOT-QUALIFIED (ORAMA_GRANT_SERVING is set; it must stay unset during qualification)"
  exit 2
fi
# Resolve every path-valued input against the invoking directory before the checks cd to scratch.
abspath() { ( cd "$(dirname -- "$1")" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$(basename -- "$1")" ) || printf '%s' "$1"; }
for name in SEED_FILE ISSUER_DB PUBLIC_STATE INSTALL_PLAN CONSUMER_WHEEL CONSUMER_PROVENANCE \
            PHYLAX_PIN_FILE ORAMASYS_CHECKOUT; do
  printf -v "$name" '%s' "$(abspath "${!name}")"
done
# An interpreter given as a path (contains '/') is resolved too; a bare name stays on PATH.
case "$PYTHON" in */*) PYTHON="$(abspath "$PYTHON")" ;; esac
scripts="$ORAMASYS_CHECKOUT/scripts"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "evidence-started: $stamp"
echo "euid: $(id -u)  host: $(hostname)"
echo "paths (reviewer must compare these with the service configuration):"
for name in SEED_FILE ISSUER_DB PUBLIC_STATE INSTALL_PLAN CONSUMER_WHEEL CONSUMER_PROVENANCE \
            PHYLAX_PIN_FILE ORAMASYS_CHECKOUT PYTHON; do echo "  $name=${!name}"; done

run_check() {  # name, command...
  local name="$1"; shift
  local out="$scratch/$name.out"
  ( cd "$scratch" && "$@" ) >"$out" 2>&1; local rc=$?
  echo "--- $name exit=$rc sha256=$(sha256sum "$out" | cut -d' ' -f1)"
  sed 's/^/    /' "$out"
  [ "$rc" -eq 0 ] || fail=1
}

run_check serving-identity "$PYTHON" -I "$scripts/qualify_serving_identity.py" \
  --expected-uid "$SERVING_UID" --seed-file "$SEED_FILE" --issuer-db "$ISSUER_DB" \
  --public-state "$PUBLIC_STATE"
run_check installed-identity "$PYTHON" -I "$scripts/verify_installed_identity.py" \
  --consumer-wheel "$CONSUMER_WHEEL" --consumer-provenance "$CONSUMER_PROVENANCE" "$INSTALL_PLAN"
run_check phylax-pin "$PYTHON" -I "$scripts/verify_phylax_pin.py" "$PHYLAX_PIN_FILE"

echo "switch-state: ORAMA_GRANT_SERVING is unset (this script never sets it)"
if [ "$fail" -eq 0 ]; then echo "RESULT: QUALIFIED-EVIDENCE-PRINTED (operator must still sign the receipt)"; exit 0; fi
echo "RESULT: NOT-QUALIFIED"; exit 1
