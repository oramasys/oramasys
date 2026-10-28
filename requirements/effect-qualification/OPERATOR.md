# Fresh approval of the effect candidate software-qualification packet

This is a successor packet, not a replacement for M1 generation 2. It tests the
consumer from PR #81 against merged Phylax main, without promoting production
pins or activating serving/effects. Approval means permission to collect scoped
software evidence. It is **not deployment qualification or deployment authorization**.
Real serving-identity isolation and deployed artifact/configuration/policy evidence
are still separate gates. Read `coverage.v2.json` residual limits before approving.

## Review and rehearse before login

Use a trusted local terminal with Python and GitHub CLI. Fetch and check out
`draft/effect-qualification-packet-20261028` from `oramasys/oramasys`.
Verify its published review head and require a clean worktree. Review the manifest,
install plan and coverage packet here; do not edit frozen generation files.

The immutable consumer is `02e4f6d7b0b24a50fa3f50f11977cbccf2915bcb`;
the candidate Phylax producer is `cf3a300c6d39092ab64df54f0d1ab3fea3db3c38`.
The harness is the **exact final commit of this preparation branch**, not its
mutable name, not the old consumer, and not a synthetic PR merge SHA.

The registered workflow `final-producers.yml` dispatches this additive lane when
`packet=effect`. Its default stays `legacy`. PR runs of the additive workflow
always rehearse, even if an approval is present. Rehearsal artifacts must say
`evidence=false`; a green rehearsal never constitutes approval.

```bash
gh workflow run final-producers.yml --repo oramasys/oramasys \
  --ref draft/effect-qualification-packet-20261028 \
  -f packet=effect -f rehearsal=true
```

For dispatch availability, the reusable candidate workflow is reached through
the already registered `final-producers.yml`; it need not first be merged.

## Freeze the exact reviewed inputs

Run from the root of that clean checkout, before starting the 15-minute login window:

```bash
test -z "$(git status --porcelain)" || exit 1
consumer=02e4f6d7b0b24a50fa3f50f11977cbccf2915bcb
harness="$(git rev-parse HEAD)"
manifest=requirements/effect-qualification/manifest.v3.json
coverage=requirements/effect-qualification/coverage.v2.json
python scripts/qualification_freeze.py propose "$manifest" "$coverage" \
  --consumer "$consumer" --harness "$harness"
```

Compare the proposal's digests, consumer and harness to the reviewed packet. A
proposal is not approved and cannot pass the evidence gate. If the branch changes,
review it again and regenerate both proposal and approval; do not reuse a stale record.

## Fresh human login — local terminal and browser only

The following Bash/WSL commands deliberately use a new, isolated GitHub CLI
configuration. Keep the terminal private. Never paste the device code, password,
token or MFA response into chat. The helper calls `gh auth login --web`; you
complete GitHub's actual browser/device interaction as `diazMelgarejo`.

```bash
unset GH_TOKEN GITHUB_TOKEN GITHUB_PERSONAL_ACCESS_TOKEN GITHUB_COPILOT_PAT
approval_parent="$(mktemp -d)"
approval_config="$approval_parent/github"
python scripts/qualification_approval.py authenticate \
  --config-dir "$approval_config"
```

The configuration path must be absolute and must not already exist; the helper
creates it. The resulting account-bound marker lasts 15 minutes and is single-use.
The CLI may retain OAuth credentials in this isolated configuration or your OS
credential store: this is not a credential-free operation. Do not upload that
configuration, marker or terminal transcript as an artifact.

## Approve within 15 minutes, then dispatch evidence mode

Keep using the same shell variables and reviewed clean checkout:

```bash
python scripts/qualification_approval.py approve "$manifest" "$coverage" \
  --consumer "$consumer" --harness "$harness" \
  --repository oramasys/oramasys --pull-request 81 \
  --record "$approval_parent/approval.json" \
  --config-dir "$approval_config"

python scripts/qualification_freeze.py verify "$manifest" "$coverage" \
  --consumer "$consumer" --harness "$harness" \
  --record "$approval_parent/approval.json"

GH_CONFIG_DIR="$approval_config" gh workflow run final-producers.yml \
  --repo oramasys/oramasys --ref draft/effect-qualification-packet-20261028 \
  -f packet=effect -f rehearsal=false \
  -F "freeze_record=@$approval_parent/approval.json"
```

An account-owned comment is posted on PR #81. Preserve it unchanged: edited
approval comments are rejected. The local record contains that public comment
reference and input digests, not credentials. A failed posting attempt consumes
the marker too; start a new isolated login rather than forging or refreshing it.
The dispatch ref is a branch name, as required by the GitHub dispatch API. Its
resolved run SHA must equal the approved harness SHA; if the branch advances,
verification refuses the stale approval rather than silently testing new bytes.

The workflow independently verifies the comment author, unedited body and exact
repository/PR/consumer/harness/manifest/coverage/allowlist binding with GitHub's
read-only workflow token. It does not trust chat identity or a hand-written marker.
The local marker records that the helper procedure ran; remote comment verification
alone cannot independently attest that a human completed device/MFA interaction.

## Read the result without activating anything

Both Python 3.11 and 3.12 cells must succeed. Inspect retained install identities,
wheel provenance/rebuild comparison, full collection/execution, zero-skip results,
scenario traces and the sanitized approval binding. Evidence mode can produce
`evidence=true` only for a complete successful run with the verified binding;
that evidence is limited to the packet's Linux/inert software claims.

Do not read a successful workflow as proof of physical Windows canaries, actual
serving-UID separation, a live policy/approval provider, external effect execution,
or a qualified deployed artifact/configuration. No merge, production promotion,
generation transition, serving activation or T3–T5 activation follows automatically.
