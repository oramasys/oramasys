# ADR 41: Alexandria Repository — Centralized Documentation Hub

**Date:** 2026-07-10  
**Status:** APPROVED  
**Authors:** Team (user decision)  

---

## Problem

Phase 0 specifications, threat models, ADRs, and design decisions are scattered across three locations:

1. **Perpetua-Tools** (L2 — runtime authority) — lives in `docs/phase-0-specifications/` (correct, runtime-adjacent)
2. **orama-system** (L3 — architectural planning) — should live in `docs/v2/` (not yet migrated, ADRs sparse)
3. **gstack cache** (`~/.gstack/projects/diazMelgarejo-orama-system/`) — stale copies (2–6 hours behind disk)

Result: Navigation confusion. Editors don't know canonical location. Specs get edited in wrong place (gstack cache instead of canonical PT). Cross-references break when repos move.

---

## Solution: Create `oramasys/alexandria`

A **documentation-only, zero-code** repository as the single source of truth for all specifications, threat models, ADRs, and architectural decisions.

### Repository Governance

| Repository | Layer | Purpose | Owns |
|---|---|---|---|
| **Perpetua-Tools** | L2 (Runtime) | Implementation + orchestration | Code, config, test suites, packages, state machines |
| **alexandria** | Documentation | Architectural specs + decisions | Specs (D1–D4+), threat models (T1–T7+), ADRs (D0–D17+), team reviews, lessons, design rationale |
| **orama-system** | L3 (Methodology) | Stateless planning framework | Skills, gate criteria, methodology, standards, policies |

### Directory Structure

```
alexandria/
├── docs/
│   ├── adr/                     # ADRs D0–D17+ (migrated from orama-system/docs/v2/)
│   ├── phase-0/                 # Phase 0 deliverables
│   │   ├── D1-peer-observation-model.md
│   │   ├── D2-heartbeat-liveness.md
│   │   ├── D4-threat-model.md
│   │   ├── task-list.md
│   │   └── team-review-checklist.md
│   ├── specifications/          # General specs and architectural designs
│   ├── threat-models/           # T1–T7 and beyond
│   ├── team-reviews/            # Checkpoint checklists, gate criteria
│   └── lessons/                 # Cross-repo learning logs (synced from PT + orama LESSONS.md)
├── README.md                    # Navigation guide for all users
└── .gitignore                   # Never: binaries, build artifacts, venv, node_modules
```

### Key Constraints

1. **Zero code.** No implementation, no build artifacts, no binaries. Pure documentation.
2. **Portable paths.** All paths use relative refs or environment variables; never `/Users/<name>/` or hard-coded workstation paths.
3. **Append-only LESSONS.md.** New session learnings always append; never delete or rewrite.
4. **One-way import.** orama-system and Perpetua-Tools IMPORT from alexandria; never the reverse (no circular dependency).
5. **Sync policy.** When alexandria is updated, both PT and orama-system pull + commit the changes; no merge conflicts (append-only, one-way).

---

## Benefits

1. **Single source of truth.** All specs live in one repo. No stale copies in gstack cache.
2. **No build burden.** Documentation-only means no CI, no tests, no deployments. Always readable.
3. **Stable URL anchors.** Cross-project references point to `alexandria/docs/phase-0/D1.md`, not scattered across PT + gstack.
4. **Clear delineation.** Specs are architecture (L3 domain); implementation is runtime (L2 domain); methodology is standard (L3 domain).
5. **Prevents confusion.** Next time a developer wonders "where do I edit the threat model?", answer is unambiguous: alexandria.

---

## Implementation Plan

### Phase 1: Repository Creation (Day 1)
- [ ] Create `oramasys/alexandria` as a new repo in the orama GitHub org
- [ ] Initialize with README.md + .gitignore
- [ ] Create `docs/v2/` directory structure
- [ ] Copy this ADR to `docs/v2/41-alexandria-repository.md`

### Phase 2: Content Migration (Days 2–7)
- [ ] Migrate Phase 0 specs (D1, D2, D4, task list, team review checklist) from PT `docs/phase-0-specifications/` to alexandria `docs/phase-0/`
- [ ] Migrate ADRs (D0–D17+) from orama-system `docs/v2/` to alexandria `docs/v2/`
- [ ] Consolidate LESSONS.md from both PT and orama-system into alexandria `docs/lessons/LESSONS.md`
- [ ] Update PT + orama-system to reference alexandria docs via `git submodule add` or direct URLs

### Phase 3: Cross-Reference Updates (Days 8–14)
- [ ] Update all cross-references in PT + orama-system to point to alexandria URLs
- [ ] Update CLAUDE.md files in both repos to document the new canonical location
- [ ] Update REPO-CROSS-REFERENCE.md in PT to list alexandria as primary source

### Phase 4: Sync Policy Implementation (Ongoing)
- [ ] Create `scripts/sync-alexandria.sh` in PT + orama-system to pull alexandria changes
- [ ] Wire script into CI/CD pre-commit hooks
- [ ] Document in both repos' CLAUDE.md: "Before editing architectural specs, check alexandria first; sync locally via `../alexandria/scripts/sync.sh`"

---

## Decision Rationale

### Why a separate repo (not a monorepo)?
- **Build isolation:** Documentation never breaks CI.
- **Clear ownership:** Alexandria maintainer role is separate from L2 (runtime) and L3 (methodology) roles.
- **Low friction:** Documentation contributors don't need to understand complex build systems.

### Why not store specs in PT or orama-system directly?
- **L2 burden:** PT is production code; adds test/build complexity if specs live there.
- **L3 bloat:** orama-system is methodology/standards; specs are too domain-specific.
- **Navigation:** Developers don't know whether to look in PT or orama first.

### Why one-way import (not circular)?
- **Prevents merge loops:** If both directions reference each other, conflict resolution becomes circular.
- **Clear authority:** alexandria is the source; PT and orama-system consume.

---

## Acceptance Criteria

- [ ] Repository created and initialized
- [ ] Phase 0 specs migrated (all 5 files + cross-reference catalogue)
- [ ] ADRs 0–17+ present in alexandria/docs/v2/
- [ ] LESSONS.md consolidated from both repos
- [ ] Both PT and orama-system CLAUDE.md updated to reference alexandria
- [ ] Sync scripts working (dry-run verified)
- [ ] No broken links in documentation
- [ ] All 3 repos commit to sync policy in their next session

---

## Alternative Considered

### Option A: Keep specs in Perpetua-Tools
- Pros: Simpler (one fewer repo)
- Cons: L2 (runtime) becomes heavy with L3 (architectural) documentation; CI/test burden grows

### Option B: Monorepo with three subdirectories
- Pros: Single git history
- Cons: Huge footprint; all three projects must coordinate on all pulls; increased merge conflicts

### Option C (CHOSEN): Separate alexandria repository with one-way import
- Pros: Clean separation; documentation never breaks CI; clear navigation
- Cons: One more repo to track; sync policy must be maintained

---

## Related Decisions

- ADR-27 (Git Governance): Zero-fragmentation doctrine; all canonical files have single source of truth
- ADR-19 (Worktree Parallel Agents): Concurrent writes to multi-repo system; this ADR prevents conflicts by centralizing read-only specs

---

## Follow-Up

- Establish release schedule: when should alexandria be tagged/released?
- Define archive policy: what happens to Phase 0 docs after Phase 1 ships?
- Consider: should alexandria have a CI gate (check for broken links, validate YAML frontmatter)?

