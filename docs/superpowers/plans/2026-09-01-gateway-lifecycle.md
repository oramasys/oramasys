# Gateway Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an idempotent, owner-separated Gateway Lifecycle capability.

**Architecture:** A pure orchestration state machine consumes injected Telos,
Phylax, Agate, Claude-Desktop-LLM, event-sink, and state-store ports. Oramasys
persists only the resulting routing state; PT remains a delegating façade.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-09-01-gateway-lifecycle-design.md`

## Global Constraints

- Never execute a package manager or persist credentials.
- Require an exact artifact version and `sha256:<64 lowercase hex>` digest.
- Require consent scoped to the artifact and version.
- Route every configuration and health endpoint through Telos.
- Use Phylax for provenance, integrity, redaction, and runtime admission.
- Do not duplicate Agate placement or Claude provider-operation semantics.
- Do not provide a legacy PT fallback.

---

### Task 1: Define lifecycle contracts

**Files:**

- Create: `src/orama/gateway/contracts.py`
- Create: `src/orama/gateway/__init__.py`
- Test: `src/tests/test_gateway_lifecycle.py`

**Interfaces:**

- Produces: immutable request, decision, event, routing-state, result models,
  and an atomic `claim`/`complete`/`abort` state-store port.

- [ ] Write contract and validation tests for consent, versions, and digests.
- [ ] Run the targeted test and confirm it fails because the module is absent.
- [ ] Implement the minimal Pydantic contracts and protocol definitions.
- [ ] Run the targeted tests and confirm they pass.

### Task 2: Implement the owner-separated lifecycle

**Files:**

- Create: `src/orama/gateway/lifecycle.py`
- Test: `src/tests/test_gateway_lifecycle.py`

**Interfaces:**

- Consumes: owner ports and request contracts from Task 1.
- Produces: `GatewayLifecycle.run(request) -> GatewayLifecycleResult`.

- [ ] Write failing success, denial, timeout, event-redaction, and owner-order tests.
- [ ] Implement the smallest fail-closed state machine that passes them.
- [ ] Write and verify sequential and concurrent repeat-run tests that prove
  owner calls are not repeated.

### Task 3: Add the PT transitional façade and documentation

**Files:**

- Create: `src/orama/gateway/compat.py`
- Modify: `README.md`
- Test: `src/tests/test_gateway_lifecycle.py`

**Interfaces:**

- Produces: `PerpetuaToolsGatewayFacade.run(request)` as a direct delegate.

- [ ] Write a failing façade test proving failures propagate without fallback.
- [ ] Implement the one-way delegate.
- [ ] Document ownership, security constraints, and integration boundaries.
- [ ] Run targeted and complete repository tests.
