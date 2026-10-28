#!/usr/bin/env bash
# Run in a trusted Codespaces Bash terminal, NOT native LibTerm.
(
set +x
set -euo pipefail
umask 077

for qualification_tool in git gh python3; do
  command -v "$qualification_tool" >/dev/null || {
    printf 'Missing required tool: %s. Stop; use a Codespaces Bash terminal.\n' "$qualification_tool"
    exit 1
  }
done
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"'

qualification_repo=oramasys/oramasys
qualification_branch=draft/effect-qualification-packet-20261028
qualification_harness=09cd1fb4bee8cbd7d29538620a3b4add49ef9221
qualification_consumer=02e4f6d7b0b24a50fa3f50f11977cbccf2915bcb
qualification_parent="$(mktemp -d)"
qualification_checkout="$qualification_parent/repository"
qualification_config="$qualification_parent/fresh-github"
qualification_record="$qualification_parent/approval.json"

# Use existing repository-read credentials only for the initial clone.
git clone --single-branch --branch "$qualification_branch" \
  "https://github.com/$qualification_repo.git" "$qualification_checkout"
cd "$qualification_checkout"
test "$(git rev-parse HEAD)" = "$qualification_harness" || {
  printf 'Preparation branch changed. Stop and request an updated reviewed handoff.\n'
  exit 1
}
test -z "$(git status --porcelain)"

qualification_manifest=requirements/effect-qualification/manifest.v3.json
qualification_coverage=requirements/effect-qualification/coverage.v2.json
python3 scripts/qualification_freeze.py propose \
  "$qualification_manifest" "$qualification_coverage" \
  --consumer "$qualification_consumer" --harness "$qualification_harness"

python3 - "$qualification_manifest" "$qualification_coverage" <<'PY'
import hashlib
import json
import sys
expected = (
    "876f9b824fe554908d23cda030a20075d0d91c828312e9425dc61936651d9364",
    "680854d25bd9d685d65f657ad261a024d855936ed68e6a3489b5ca8e07c8e18d",
)
for path, wanted in zip(sys.argv[1:], expected):
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if hashlib.sha256(raw).hexdigest() != wanted:
        raise SystemExit("Packet digest mismatch: stop, do not approve")
print("Both packet digests match the reviewed handoff.")
PY

printf '\nRead the pinned guide and residual limits before proceeding:\n'
printf 'https://github.com/oramasys/oramasys/blob/%s/requirements/effect-qualification/OPERATOR.md\n' "$qualification_harness"
printf '\nThis approves Linux/inert software qualification only. It does not approve live deployment or activation.\n'
read -r -p 'Type APPROVE to begin fresh login, or anything else to stop: ' qualification_answer </dev/tty
test "$qualification_answer" = APPROVE || exit 1

# A cached Codespaces token must never satisfy the fresh-login procedure.
unset GH_TOKEN GITHUB_TOKEN GITHUB_PERSONAL_ACCESS_TOKEN GITHUB_COPILOT_PAT
python3 scripts/qualification_approval.py authenticate \
  --config-dir "$qualification_config"
qualification_login="$(GH_CONFIG_DIR="$qualification_config" gh api user --jq .login)"
test "$qualification_login" = diazMelgarejo || {
  printf 'Wrong GitHub account. Stop; a new isolated login is required.\n'
  exit 1
}

qualification_remote="$(GH_CONFIG_DIR="$qualification_config" gh api \
  "repos/$qualification_repo/git/ref/heads/$qualification_branch" --jq .object.sha)"
test "$qualification_remote" = "$qualification_harness" || {
  printf 'The preparation branch changed during login. Stop; do not approve stale inputs.\n'
  exit 1
}

python3 scripts/qualification_approval.py approve \
  "$qualification_manifest" "$qualification_coverage" \
  --consumer "$qualification_consumer" --harness "$qualification_harness" \
  --repository "$qualification_repo" --pull-request 81 \
  --record "$qualification_record" --config-dir "$qualification_config"

python3 scripts/qualification_freeze.py verify \
  "$qualification_manifest" "$qualification_coverage" \
  --consumer "$qualification_consumer" --harness "$qualification_harness" \
  --record "$qualification_record"

GH_CONFIG_DIR="$qualification_config" gh workflow run final-producers.yml \
  --repo "$qualification_repo" --ref "$qualification_branch" \
  -f packet=effect -f rehearsal=false -F "freeze_record=@$qualification_record"

printf '\nApproval posted and evidence-mode workflow requested. This is not a passing qualification result yet.\n'
python3 -c 'import json,sys; print("Public approval receipt:", json.load(open(sys.argv[1]))["approval_ref"])' "$qualification_record"
printf 'Local approval record: %s\n' "$qualification_record"
printf 'Credential configuration (private; do not share): %s\n' "$qualification_config"
printf 'Workflow status: https://github.com/oramasys/oramasys/actions/workflows/final-producers.yml\n'
)
