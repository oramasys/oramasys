# Gateway Dialer → Telos Absorption Design

## Status

Approved architecture for the 2026-09-10 restoration saga.

## Goal

Completely migrate endpoint-security authority and mechanics out of the Oramasys Gateway dedicated dialer into `oramasys/telos`, while preserving Oramasys compatibility names and historical behavior as thin adapters/pointers rather than deleting them.

## Canonical ownership

`oramasys/telos` is the sole reusable v2 endpoint-security authority. Telos owns endpoint identity, DNS resolution, all-answer validation, SSRF/address classification, IPv4-mapped IPv6 normalization, transition-network denial, rebinding/TOCTOU resistance, connection-time pinning, connected-peer verification, redirect revalidation, proxy isolation, TLS destination identity/Host/SNI, timeout/cancellation boundaries, and purpose-scoped endpoint authorization.

Oramasys owns only application/workflow concerns above that boundary: provider-kind selection, the current narrow provider/port capability matrix, lifecycle sequencing, progress events, routing-state construction, and compatibility types.

## Migration shape

1. **Absorb, do not delete.** Existing Gateway security vectors and tests are retained as provenance/conformance evidence. Equivalent logic moves into Telos tests and reusable Telos APIs.
2. **Thin Gateway façade.** `orama.gateway.dialer` remains import-compatible for `ModelServerDialRequest`, `ModelServerDialResult`, `ModelServerDialer`, stable reason-code aliases, and documented provider capability checks. It contains no IP/DNS/security implementation.
3. **Telos-native secure dial contract.** Telos exposes a reusable async secure-dial primitive. DNS/address policy and peer-pin verification occur inside Telos. The connector boundary reports the actual peer address so Telos can reject a connector that did not connect to the vetted pin.
4. **No caller-trusted public/private endpoint bit.** Oramasys migrates to restored Telos `EndpointRef(scheme, host, port)`. Public/local intent is supplied through Telos transport policy, never embedded as trusted endpoint evidence.
5. **No silent fallback.** Gateway lifecycle cannot bypass Telos if the compatibility dialer is absent or Telos fails. A default Telos-backed dialer is required or explicitly injected for tests.
6. **Application policy stays above Telos.** The current `ollama`, `lm_studio`, and `openclaw_gateway` port matrix remains an Oramasys workflow capability restriction. It is evaluated before the Telos secure dial, but does not perform destination-security classification.
7. **Authorization is not duplicated.** The actual endpoint-use authorization used for a dial is performed by the Telos secure-dial operation. Gateway consumes the returned Telos decision metadata for routing state/progress rather than maintaining a second preauthorization path.

## Telos secure-dial API

Telos adds focused contracts in `src/telos/dialer.py`:

```python
@dataclass(frozen=True, slots=True)
class SecureDialRequest:
    endpoint: EndpointRef
    purpose: EndpointPurpose
    actor_id: str
    workflow_id: str
    run_id: str
    allow_public: bool = False
    allow_private: bool = True
    allow_loopback: bool = True
    require_https_for_public: bool = True
    timeout_seconds: float = 10.0

@dataclass(frozen=True, slots=True)
class ConnectedPeer:
    provider_ref: str
    peer_address: str

class SecureDialConnector(Protocol):
    async def connect(
        self, *, endpoint: EndpointRef, pinned_address: str,
        purpose: EndpointPurpose, timeout_seconds: float
    ) -> ConnectedPeer: ...

@dataclass(frozen=True, slots=True)
class SecureDialResult:
    allowed: bool
    reason_code: str
    endpoint_identity: EndpointIdentity | None = None
    decision: EndpointUseDecision | None = None
    provider_ref: str | None = None
```

`SecureDialer.dial()` resolves and validates every answer through Telos, semantically authorizes the resulting `EndpointIdentity`, selects a vetted pin, invokes the connector with that pin, then verifies `ConnectedPeer.peer_address` equals the vetted pin after IPv4-mapped IPv6 normalization. Connector errors and timeouts become stable fail-closed Telos reason codes.

## Gateway compatibility façade

`src/orama/gateway/dialer.py` becomes a narrow adapter:

- validates Gate-4 scope and provider/port capability only;
- converts `ModelServerDialRequest` to Telos `SecureDialRequest`;
- delegates to Telos `SecureDialer`;
- translates Telos result/reason metadata back to `ModelServerDialResult`;
- re-exports stable aliases needed by existing callers/tests;
- contains no `ipaddress`, DNS classification, transition-network tables, rebinding logic, pin verification, redirect/proxy/TLS logic, or endpoint-use authorization implementation.

The legacy connector name remains as a compatibility alias to Telos `SecureDialConnector`; implementers must return `ConnectedPeer`, because a provider-ref-only connector cannot prove connection-time pinning.

## Gateway lifecycle

`GatewayLifecycle` must not keep a separate semantic-only authorization path for the same dial. For config and health endpoints it calls the Telos-backed compatibility dialer, consumes policy-version/decision metadata from those results, emits `endpoints_authorized`/`endpoints_dialed`, and fails closed on any Telos denial or transport failure. The dialer is no longer optional security.

## Compatibility and migration

Historical Oramasys dialer code remains recoverable in Git history and is summarized in migration documentation. No security vector is discarded: CGNAT, 6to4 relay anycast, Teredo, 6to4, metadata, mixed-answer denial, invalid answers, public opt-in, provider/port scope, timeout, expired decision, and peer mismatch are represented in Telos or compatibility conformance tests.

## Testing

Telos tests must prove:

- IPv4-mapped IPv6 cannot bypass IPv4 policy;
- mixed DNS answers fail closed before connector invocation;
- metadata, CGNAT, 192.88.99.0/24, Teredo and 6to4 are denied;
- public endpoints require explicit public intent and HTTPS when configured;
- connector gets only a vetted pin;
- a mismatched returned peer is denied;
- authorization is for the resolved `EndpointIdentity`;
- timeout/cancellation fail closed.

Oramasys tests must prove:

- `orama.gateway.dialer` contains no independent address-classification behavior;
- provider/port matrix remains enforced;
- compatibility request/result names still work;
- Telos denial/reason metadata is translated stably;
- lifecycle has no optional/no-dialer fallback and persists Telos policy metadata from actual secure dials;
- no direct dependency remains on caller-supplied `EndpointRef.is_public`.

## Dependency and versioning

Oramasys must pin the verified Telos restoration/absorption head, replacing the old semantic-only Telos pin. The pin is updated only after Telos exact-head CI is green.

## Completion gate

The migration is complete only when:

1. Telos exact-head CI is green with project coverage >=80%;
2. Oramasys exact-head CI is green with project coverage >=80% or its stricter existing threshold;
3. fresh review-thread sweeps show no unresolved restoration findings;
4. Orama PR #351 ADR/handoff states Gateway migration is complete rather than pending;
5. PT `.agent` memory/coordination board is updated through canonical tooling/records after those v2 heads are verified;
6. no PR is merged without explicit owner merge authorization.
