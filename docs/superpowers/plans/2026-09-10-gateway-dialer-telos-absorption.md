# Gateway Dialer → Telos Absorption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Completely absorb Oramasys Gateway endpoint-security mechanics into Telos while preserving Gateway compatibility names as thin wrappers/pointers.

**Architecture:** Telos gains the reusable secure-dial primitive and owns DNS/address policy, endpoint authorization, pinning and peer verification. Oramasys retains only provider/port capability policy, lifecycle orchestration, compatibility dataclasses/reason aliases, and translation into the Telos secure-dial API. There is no silent non-Telos fallback.

**Tech Stack:** Python 3.11+, asyncio, Pydantic 2, pytest/pytest-asyncio, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-10-gateway-dialer-telos-absorption-design.md`

## Global Constraints

- `oramasys/telos` is the sole reusable v2 endpoint-security authority.
- Preserve useful Gateway behavior/tests additively; do not erase history or compatibility names.
- Remove caller-trusted `EndpointRef.is_public` usage from Oramasys.
- No silent fallback around Telos denial/unavailability.
- Maintain at least 80% project test coverage; higher existing thresholds MUST NOT be lowered.
- Do not merge any PR without explicit owner authorization.

---

### Task 1: Add Telos secure-dial contracts and fail-closed peer verification

**Files:**
- Create: `oramasys/telos/src/telos/dialer.py`
- Modify: `oramasys/telos/src/telos/__init__.py`
- Create: `oramasys/telos/tests/test_dialer.py`

**Interfaces:**
- Consumes: `EndpointAuthorizer`, `EndpointRef`, `EndpointIdentity`, `EndpointPurpose`, `EndpointUseDecision`, `resolve_endpoint`, `parse_ip`.
- Produces: `ConnectedPeer`, `SecureDialRequest`, `SecureDialResult`, `SecureDialConnector`, `SecureDialer`.

- [ ] **Step 1: Add RED tests for mixed DNS, mapped IPv6, metadata/transition networks, public opt-in, peer mismatch, connector error, timeout.**
- [ ] **Step 2: Run `pytest tests/test_dialer.py -q`; expect failures because `telos.dialer` does not exist.**
- [ ] **Step 3: Implement `SecureDialer` using Telos resolver/address/authorizer primitives and verify returned peer equals the selected vetted pin after `parse_ip()` normalization.**
- [ ] **Step 4: Export the new contracts from `telos.__init__`.**
- [ ] **Step 5: Run `pytest -q` and coverage; require >=80%.**
- [ ] **Step 6: Commit to the existing Telos PR #1 branch.**

### Task 2: Convert Oramasys `gateway.dialer` to a thin Telos adapter

**Files:**
- Modify: `src/orama/gateway/dialer.py`
- Modify: `src/tests/test_model_server_dialer.py`

**Interfaces:**
- Consumes: Telos `SecureDialer`, `SecureDialRequest`, `SecureDialResult`, `ConnectedPeer`, `SecureDialConnector`.
- Produces: compatibility `ModelServerDialRequest`, `ModelServerDialResult`, `ModelServerDialer`, stable reason aliases.

- [ ] **Step 1: Rewrite tests so DNS/address/pinning behavior is asserted through an injected Telos secure dialer rather than independent Oramasys classifiers.**
- [ ] **Step 2: Add a conformance test that fails if `orama.gateway.dialer` imports `ipaddress` or defines address-classification network tables.**
- [ ] **Step 3: Preserve only Gate-4 purpose/provider/port application policy in Oramasys.**
- [ ] **Step 4: Translate compatibility request to `SecureDialRequest` and Telos result back to `ModelServerDialResult`; no direct authorization or DNS logic.**
- [ ] **Step 5: Keep legacy connector name as an alias/pointer to Telos `SecureDialConnector`; update fake connectors to return `ConnectedPeer`.**
- [ ] **Step 6: Run targeted dialer tests.**

### Task 3: Remove duplicate lifecycle authorization and optional security bypass

**Files:**
- Modify: `src/orama/gateway/lifecycle.py`
- Modify: `src/orama/gateway/contracts.py`
- Modify: `src/tests/test_gateway_lifecycle.py`
- Modify: `src/tests/test_gateway_claim_cancellation.py` as required by constructor changes.

**Interfaces:**
- Consumes: `ModelServerDialer.dial()` results carrying Telos decision/policy metadata.
- Produces: unchanged `GatewayLifecycleResult`/`RoutingState` public semantics with policy versions derived from actual secure dials.

- [ ] **Step 1: Add tests proving lifecycle cannot run endpoint phases without a Telos-backed dialer and does not call a separate semantic-only `authorize()` path.**
- [ ] **Step 2: Make the dialer a required constructor dependency (or construct a Telos-backed default only when all Telos I/O dependencies are available); never silently skip dialing.**
- [ ] **Step 3: Use config/health dial results for `endpoints_authorized`, `endpoints_dialed`, and routing-state Telos policy versions.**
- [ ] **Step 4: Preserve idempotency/cancellation/progress behavior.**
- [ ] **Step 5: Run all Gateway tests.**

### Task 4: Migrate Oramasys to restored Telos contracts

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/orama/gateway/contracts.py`
- Modify: Gateway tests/fixtures using `EndpointRef(..., is_public=...)`.

**Interfaces:**
- Consumes: restored Telos `EndpointRef(scheme, host, port)` and secure-dial API.
- Produces: Oramasys request/routing types free of caller-trusted endpoint classification.

- [ ] **Step 1: Replace every Oramasys `EndpointRef.is_public` construction/read.**
- [ ] **Step 2: Model public permission only as `GatewayLifecycleRequest.allow_public_model_servers` → Telos secure-dial policy.**
- [ ] **Step 3: Pin `oramasys-telos` to the exact green Telos absorption head.**
- [ ] **Step 4: Run `python -m compileall -q src/orama` and the full `pytest src/tests -q` suite.**
- [ ] **Step 5: Require project coverage >=80%.**

### Task 5: Publish migration evidence and compatibility pointers

**Files:**
- Create: `docs/architecture/gateway-telos-endpoint-security-migration.md`
- Update: `docs/superpowers/specs/2026-09-10-gateway-dialer-telos-absorption-design.md` only if implementation exposed a necessary clarification.

**Interfaces:**
- Produces: durable explanation that old Gateway dialer behavior was absorbed, not deleted; points to Telos API and Git history for provenance.

- [ ] **Step 1: Record before/after ownership matrix and exact Telos/Oramasys heads.**
- [ ] **Step 2: List every preserved security vector and its new Telos test location.**
- [ ] **Step 3: State that `orama.gateway.dialer` is compatibility-only and contains no security implementation.**
- [ ] **Step 4: Commit and push once on the Oramasys branch, then open the single Oramasys PR.**

### Task 6: Exact-head verification and cross-repo closure

**Files:**
- Update Orama PR #351 handoff/ADR status.
- Update PT PR #382 semantic/working memory only after verified v2 heads.

- [ ] **Step 1: Verify Telos exact-head CI and fresh review threads.**
- [ ] **Step 2: Verify Oramasys exact-head CI and fresh review threads.**
- [ ] **Step 3: Change PR #351 wording from Gateway migration pending to complete, preserving ownership-versus-enforcement distinctions for unrelated outbound paths.**
- [ ] **Step 4: Record final Telos/Oramasys heads in PT `.agent` memory/coordination evidence without hand-editing rendered `LESSONS.md`.**
- [ ] **Step 5: Re-run PT exact-head CI/review and close any restoration-specific findings.**
- [ ] **Step 6: Produce final handoff showing completed deliverables and any unrelated pre-existing debt separately.**
