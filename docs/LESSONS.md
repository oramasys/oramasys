# Lessons — orama-system

> **Cross-repo companion:** Perpetua-Tools `docs/LESSONS.md` — read both at session start for joint context.
> **Architecture authority:** `docs/2026-05-14--UNIFIED-ABSORPTION-PLAN.md`

---

## 2026-07-10 — Phase 0 checkpoint review + cross-repo grounding | Claude Code

**Session:** Phase 0 blocker fixes + multi-agent orchestration (Codex + Cline + Sonnet-5)
**Repos affected:** PT (specs fixed), orama-system (alexandria ADR created)
**Outcome:** Cross-reference catalogue created; alexandria repository policy approved

### Critical lessons

1. **Two-repo invariant FIRST** — Before editing architectural specs, ALWAYS run git verification to confirm repo locations. This session edited specs from cache (`~/.gstack/projects/`) instead of canonical PT `docs/phase-0-specifications/`. User had to prompt correction. Apply two-repo check as FIRST step before multi-repo work. Pattern: `cd $(git rev-parse --show-toplevel) && git status` confirms canonical location.

2. **Orama monorepo structure** — `~/code/oramasys` is a container; the actual orama-system repo is at `~/code/oramasys/oramasys/`. Non-obvious. Document in checklist: `cd ../../oramasys/oramasys/` for orama-system canonical work, NOT `cd ../../oramasys/` alone.

3. **Cross-repository navigation solved by catalogue** — Created `REPO-CROSS-REFERENCE.md` in PT mapping all plans/specs/ADRs across PT (L2) and orama-system (L3). Maintenance pattern: maintain cross-reference FIRST when adding new plans; use relative paths only (no `/Users/<name>/` paths in tracked files). Golden rule: verify both repos FIRST before editing.

4. **Alexandria repository policy APPROVED** — Decision: create `oramasys/alexandria` as a documentation-only, zero-code repository for centralized specs, threat models, ADRs, and team review checklists. Benefits: single source of truth (not scattered across PT + gstack cache), no code = no build burden, stable URL anchors for cross-project references, clear L2/L3 delineation. ADR #41 created in orama-system/docs/v2/41-alexandria-repository.md. One-way import: PT and orama-system import FROM alexandria, never reverse (prevents circular dependency).

5. **Phase 0 Fix #3 formalized** — StateTransitionManager model reconciliation resolved: adopt asymmetric hysteresis (D2 model—quick to suspect, slow to recover). Three tasks documented: D1 schema rename, D2 pseudocode detail, D4 matrix reference. Estimated 2–3 hours to execute. PHASE-0-FIX-3-AND-MEDIUM-ITEMS-DECISION-BRIEF.md created in PT for manual review.

6. **Medium items (M1–M7) deferred to Phase 1b** — Discovery strategy, cache eviction, rate limit adaptation, checkpoint gates, sequence bit-width, replay dedup, STM validation pattern. Each documented with decision options + recommendations. Do NOT block Phase 1 start; track in backlog.

---

