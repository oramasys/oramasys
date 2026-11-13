# Oramasys C6 Execution Plan (2026-11-13)

**Status:** agent-executable prerequisites + inert diagnostics only  
**Derived from:** `OpenClaw/references/2026-11-13-lockstep-fleet-remediation-plan-STEELMAN.md`  
**Authorities (do not replace):**

- `oramasys/oramasys/docs/closure/c6-qualification-runbook.md`
- `oramasys/oramasys/docs/closure/c6-windows-handoff.md`
- `oramasys/oramasys/docs/serving-activation-runbook.md`
- `oramasys/oramasys/docs/revocation-capacity-handoff-2026-11-03.md`
- `oramasys/oramasys/docs/release12-postmerge-qualification-2026-11-04.md`
- `orama-system/docs/v2/MASTER-CLOSURE-AND-IMPLEMENTATION-PLAN-2026-11-06.md` (CL-3 / C6 last)

Serving stays **OFF**. `ORAMA_GRANT_SERVING` stays unset. This plan never authorizes
merge, host qualification, R6–R8, or activation. Both Mac and Windows remain
**UNQUALIFIED** until operator-owned gates close.

Gossip/LAN guidance folded in: append-and-merge; Mac uv 3.13.15 / SQLite 3.53.1;
Windows census all answering interpreters at 3.53.1 (3080); 5080 offline; installs
and merges operator-held.

---

## 1. Prerequisite matrix (2026-11-13 inventory)

| Gate | Authority | State | Evidence |
| --- | --- | --- | --- |
| Phylax producer portability (`platform_fs`, reserved names) | C6 Windows handoff Tier 2 | **Software landed** | Phylax `origin/main` `2c11d15` (ex `#32`) |
| Oramasys Windows private_store / grant_lib slice | C6 Windows handoff Tier 2–3 software | **Software landed** | Oramasys `main` `f33d809` (ex `#98`) |
| Mac SQLite floor on the service-manager interpreter | C6 Mac runbook C7/C8 | **Open** | The uv 3.13.15 receipt shows SQLite 3.53.1 for that interpreter only. The serving-runtime gate stays open until a receipt from the service-manager interpreter. |
| Framework / default Mac Python 3.13.0 | same | **Fail closed** | SQLite **3.45.3** — do not use for C6 |
| Selected runtime baseline | runbook unchanged adapter/store comparison | **Open** | Whichever CPython the operator selects needs a fresh comparison on the same harness, runtime, and dependencies as the candidate. 3.13.18 is not installed. 3.13.15 with SQLite 3.53.1 meets the floor and does not replace that comparison. |
| Dedicated env with `.[dev]` + `PyNaCl==1.6.2` | runbook isolated environment | **Done (agent)** | `/private/tmp/c6-venv-20261113` on uv 3.13.15 |
| Crypto packages on dedicated venv | runtime receipt | **Done (agent)** | PyNaCl 1.6.2 + cffi in `c6-runtime-receipt.json` |
| Inert CI-scale availability smoke | CI rehearsal only | **Done (agent)** | 6/6 sent; not target-filesystem qualification |
| Target-filesystem Mac 3-pass (256×8, p95≤60 ms) | C6 Mac runbook | **Operator-held** | Agent diagnostics ≠ three operator passes |
| Native Windows Tier 1–3 qualification | C6 Windows handoff | **Operator/Win-held** | Software slices ≠ native qualification |
| R4–R8 / serving activation | serving-activation-runbook | **Open** | Separate from C6 availability |

---

## 2. Execution order (agent vs operator)

### Agent-completable (this plan)

1. Freeze identities: Oramasys `f33d809`, Phylax `2c11d15`.
2. Build dedicated C6 venv on uv CPython 3.13.15 (matches CI
   `r3-authority-composition.yml`).
3. Capture `scripts/c6_runtime.py` receipt with crypto packages present.
4. Run **inert** availability smoke at CI scale only (16 events / 2 senders / 3
   sends) — label explicitly *not* target-filesystem qualification.
5. Publish checklist + receipts on GossipBus and LAN peer outbox.
6. Leave operator three-pass commands ready-to-run; do not invent pass results.

### Operator-held (cannot finish by agent claim)

1. Protect evidence + TMPDIR on approved local APFS; confirm FD capacity.
2. Controls A/B then **three consecutive** candidate runs (2400 sends each) under
   the Mac runbook; scheduled + successful-call p95 ≤ 60 ms; zero fail-open
   adversarial suite.
3. Native Windows Tier 1 stdlib lock experiment ×3; Tier 3 full native suite as
   service account.
4. Independent R6; R7 generation; R8 activation decision — still separate.

---

## 3. Frozen commands (Mac, serving OFF)

```bash
unset ORAMA_GRANT_SERVING
export PHYLAX_SOURCE=/path/to/phylax   # pin 2c11d15
export C6_VENV=/private/tmp/c6-venv-20261113
uv venv --managed-python --python 3.13.15 "$C6_VENV"
uv pip install --python "$C6_VENV/bin/python" '.[dev]' 'PyNaCl==1.6.2'
"$C6_VENV/bin/python" -I scripts/c6_runtime.py

PYTHONPATH="src:$PHYLAX_SOURCE/src" \
"$C6_VENV/bin/python" scripts/benchmark_revocation_availability.py \
  --events 16 --senders 2 --sends 3 --send-interval 0 \
  --refresh-interval 0 --refresher separate --retries 2 \
  --label "agent inert smoke; not target-filesystem qualification"
```

Operator environment, before controls A/B and every candidate run.
Do not run as activation. Do not point `PY` at `C6_VENV` unless that
venv is the runtime already selected for the baseline and controls.
Leave `PY` unchanged for the candidate runs.

```bash
: "${PY:?set PY to the selected interpreter before controls}"
: "${EVIDENCE:?set EVIDENCE to an existing protected directory}"
test -d "$EVIDENCE" && test -w "$EVIDENCE"
export PYTHONPATH="src:${PHYLAX_SOURCE}/src"
```

Candidate command, three times, distinct files. Uses the same `PY`:

```bash
set -o noclobber
"$PY" scripts/benchmark_revocation_availability.py \
  --events 256 --senders 8 --sends 300 --send-interval 0.2 \
  --refresh-interval 15 --refresher separate --retries 2 \
  --samples-jsonl "$EVIDENCE/run-N.jsonl" \
  --label "Mac APFS candidate run N" \
  > "$EVIDENCE/run-N.stdout.json" \
  2> "$EVIDENCE/run-N.stderr.txt"
```

---

## 4. Explicit non-goals

- Setting `ORAMA_GRANT_SERVING` or claiming serving activation.
- Treating CI or agent smoke as C6, R6, or dual-platform qualification.
- Re-opening merged phylax `#32` / oramasys `#98` / lockstep `#481/#484`.
- Concurrent Ollama + LM Studio heavy load on this Mac.
- Whole-file rewrites of shared LAN trackers (append-and-merge only).
