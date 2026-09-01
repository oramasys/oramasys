# Gateway Lifecycle Design

**Status:** Approved for implementation

## Purpose

Add a Gateway Lifecycle capability to `oramasys/oramasys` without moving
semantic authority into the orchestration layer. Oramasys owns the idempotent
workflow, routing-state materialization, structured progress, and transitional
Perpetua-Tools façade.

## Ownership

- Telos authorizes every configuration and health endpoint before use.
- Phylax verifies artifact provenance and integrity, redacts event details, and
  decides runtime admission.
- Agate resolves hardware placement.
- Claude-Desktop-LLM operates Ollama and LM Studio and reports readiness.
- Perpetua-Tools exposes only a temporary delegating façade. It has no legacy
  fallback and never becomes a second route-selection authority.

## Workflow

`GatewayLifecycle.run()` validates explicit operator consent and an immutable
artifact version plus SHA-256 digest. It derives an idempotency fingerprint and
returns the stored routing state without repeating side effects when that exact
request has already completed.

The state-store port atomically claims an idempotency key. A contender waits
for and returns the completed state rather than repeating semantic-owner
operations; failures abort the claim so a later attempt may retry.

For a newly claimed request the lifecycle authorizes both endpoints through
Telos, verifies the
artifact and runtime admission through Phylax, asks Agate for placement, asks
Claude-Desktop-LLM to make the provider ready within the declared timeout, and
then persists one routing state. No package manager, credential store, or raw
endpoint client is implemented here.

## Contracts

Owner integrations are dependency-injected protocols. Their results carry
opaque references and policy versions rather than implementation details.
Progress events contain phase, status, sequence, and Phylax-redacted details.

Terminal lifecycle statuses are `ready`, `already_ready`, `denied`,
`timed_out`, and `error`. Any denial, malformed owner result, or timeout stops
the workflow. Nothing silently selects another provider or invokes legacy PT
logic.

Oramasys enforces the readiness deadline even when a provider adapter hangs.
After routing state is durably committed, progress-delivery failure cannot
reverse the business result; the result remains `ready` with an explicit event
delivery reason code.

## Acceptance Criteria

- `latest`, ranges, tags, and missing or malformed SHA-256 digests are rejected.
- Consent is scoped to the exact artifact and version.
- Telos sees both configuration and health endpoints before provider operation.
- Phylax owns provenance, integrity, redaction, and admission decisions.
- Agate and Claude receive only the inputs needed for their owned decisions.
- A successful repeat run emits `already_ready` and performs no owner calls.
- Timeout and denial produce explicit terminal results and no routing-state write.
- The PT façade delegates once and propagates the lifecycle result unchanged.
