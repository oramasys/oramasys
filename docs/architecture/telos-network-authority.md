# Telos Network Authority

## Decision

`oramasys/telos` is the sole reusable v2 authority for endpoint-specific
security and secure outbound transport. Oramasys owns application/workflow and
provider-purpose semantics; it does not own a second HTTP/socket security
stack.

## Current state

| Path | Status |
| --- | --- |
| Gateway config/health secure dial | Telos-backed compatibility façade |
| Perpetua Core discovery health probe | pinned to Telos-backed Core revision |
| FastAPI server | inbound only |
| graph dispatch | backend selection/application orchestration |
| provider invocation | contract/injection seam; real transport must be Telos-backed |

## Telos owns

- endpoint URL/URI canonical identity;
- DNS resolution and every-answer admission;
- SSRF/address classification;
- metadata, loopback/private/link-local/special-use and transition-network policy;
- semantic endpoint-use authorization;
- vetted connection pin selection;
- connected-peer pin verification;
- redirect safety;
- proxy isolation;
- HTTP Host/TLS SNI destination identity;
- endpoint-specific timeout/security failure semantics.

## Oramasys retains

- route/budget/effect policy;
- workflow and lifecycle sequencing;
- provider/purpose/port capability policy;
- operator consent semantics;
- compatibility names and reason translation;
- routing-state construction;
- application-facing provider invocation contracts.

## Forbidden production shapes

Production source under `src/orama/` must not establish independent outbound
network authority through `httpx`, `requests`, `aiohttp`, `urllib.request`,
`http.client`, raw sockets, SSH clients, or subprocess network tools such as
`curl`/`wget`/`nc`.

There is no approved fallback of the form:

```text
try Telos
if unavailable/denied:
    use raw HTTP/socket client
```

Telos denial or unavailability fails closed.

## Compatibility doctrine

Moving authority does not require deleting stable compatibility APIs. Keep thin
wrappers/pointers when callers benefit from source compatibility. Such wrappers
may translate application-level request/result types and reason codes; they may
not reacquire DNS, SSRF, pinning, redirect, proxy, TLS, or endpoint-use policy.

## Enforcement

`scripts/check_telos_network_authority.py` scans `src/orama/**/*.py` and fails CI
when a production module imports a banned raw network stack or shells out to an
obvious network client.

The gate intentionally scans production source rather than the test tree, so
FastAPI/http test clients and deterministic test doubles remain available.

## Cross-repo boundary

Perpetua Core may express discovery/execution intent but does not become a
second endpoint-security authority. Its health-probe convergence uses Telos for
semantic exact-candidate authorization and transport safety.

Phylax remains the generic security/safety/runtime-admission and monitorability
owner, excluding endpoint-specific security.

Provider repositories retain provider protocol/lifecycle semantics and consume
Telos for endpoint security.

## Coverage and verification

Every change touching this boundary must preserve at least 80% project test
coverage, or any stricter configured threshold. Exact-head Python 3.11/3.12 CI
and a fresh review-thread sweep are required before readiness is claimed.

No successful check or review authorizes merging without explicit owner
instruction.
