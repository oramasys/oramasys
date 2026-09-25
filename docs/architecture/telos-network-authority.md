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
| Oramasys discovery health probe | Telos-backed composition (`orama.discovery`) |
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

The import guard evaluates both the imported module and each qualified symbol
from `from ... import ...` statements. Alias spelling therefore cannot turn a
forbidden `urllib.request` or `http.client` dependency into an allowed import.
Subprocess aliases are likewise resolved to canonical call targets before
network-command checks run.

The gate intentionally scans production source rather than the test tree, so
FastAPI/http test clients and deterministic test doubles remain available.

Cross-repository conformance tests must prove more than symbol presence. For
security-sensitive consumers such as Oramasys discovery composition, the test
parses the consumer AST and verifies the actual outbound call chain: the probe
must dispatch through `telos.request`, use exact-candidate Telos authorization,
carry `EndpointPurpose.HEALTH_PROBE`, and bind the required `TransportPolicy`
access flags. A decoy Telos import, disconnected policy object, or raw fallback
must fail the conformance test.

## Cross-repo boundary

Perpetua Core retains pure backend data types and selection logic only. Oramasys
owns discovery probe/registry I/O and uses Telos for semantic exact-candidate
authorization and transport safety. Core must not depend on Telos.

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
