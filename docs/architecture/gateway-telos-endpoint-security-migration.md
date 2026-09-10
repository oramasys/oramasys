# Gateway endpoint security → Telos migration

## Status

The Oramasys Gateway dedicated dialer has been absorbed into `oramasys/telos`.
The Gateway module remains as a compatibility/application-policy façade; it is
not a second endpoint-security authority.

## Ownership after migration

| Concern | Owner after migration |
| --- | --- |
| endpoint canonical identity / IDNA | Telos |
| DNS resolution and every-answer validation | Telos |
| SSRF/address classification | Telos |
| IPv4-mapped IPv6 normalization | Telos |
| metadata/special-use/transition-network denial | Telos |
| public/private/loopback transport admission | Telos |
| endpoint-use authorization | Telos |
| connection-time vetted pin selection | Telos |
| connected-peer pin verification | Telos |
| HTTP redirect/proxy/TLS destination safety | Telos |
| Gateway provider/purpose/port capability matrix | Oramasys |
| lifecycle sequencing/progress/routing state | Oramasys |
| compatibility request/result names and stable reason aliases | Oramasys |

## Compatibility surface retained

`orama.gateway.dialer` intentionally remains importable. It retains:

- `ModelServerDialRequest`;
- `ModelServerDialResult`;
- `ModelServerDialer`;
- `DialConnector` as a compatibility pointer to Telos `SecureDialConnector`;
- stable Gateway reason aliases;
- the Gate-4 provider/purpose/port capability matrix.

The compatibility connector contract is strengthened: implementations return
Telos `ConnectedPeer(provider_ref, peer_address)` rather than only an opaque
provider reference. This is necessary for Telos to verify that the connection
actually terminated at the vetted pin.

## Security vectors absorbed rather than removed

| Historical Gateway vector | Telos destination |
| --- | --- |
| reject all DNS answers if one is unsafe | `SecureDialer._resolve()` + Telos address policy tests |
| cloud metadata `169.254.169.254` | `telos.address` + `src/tests/test_dialer.py` |
| IPv4-mapped IPv6 bypass | `telos.parse_ip()` + secure-dial regression |
| CGNAT `100.64.0.0/10` | Telos special-use classification |
| 6to4 relay anycast `192.88.99.0/24` | Telos transition-network policy |
| Teredo `2001::/32` | Telos transition-network policy |
| 6to4 `2002::/16` | Telos transition-network policy |
| public endpoint opt-in | `SecureDialRequest.allow_public` transport policy |
| fresh exact endpoint-use decision | Telos secure-dial authorization |
| endpoint-decision mismatch rejection | Telos `authorization_endpoint_mismatch` |
| expired decision rejection | Telos `authorization_expired` |
| bounded DNS/connector work | Telos secure-dial timeout |
| connection pinning | Telos-selected `pinned_address` |
| post-connect rebinding/connector mismatch | `ConnectedPeer.peer_address` recheck |

HTTP-specific redirect, credential, proxy and TLS identity protections are
implemented in Telos `transport.py`; the Gateway compatibility dial is for
bounded provider connectivity and delegates endpoint security to the same Telos
authority.

## No silent fallback

`GatewayLifecycle` requires a `ModelServerDialer`. The compatibility dialer is
Telos-backed and the lifecycle no longer performs a separate semantic-only
preauthorization against a raw `EndpointRef`. Config and health secure-dial
results are the source of Telos policy metadata written into routing state.

A Telos denial, missing decision metadata, timeout, connector failure, or peer
pin mismatch terminates the lifecycle fail-closed. There is no path that skips
the Telos secure dial because the dialer is absent.

## Endpoint classification input

Restored Telos `EndpointRef` contains only `(scheme, host, port)`. Oramasys does
not provide a trusted `is_public` classification bit. Operator/application
intent to permit public model-server access remains separate as
`allow_public_model_servers` and is passed to Telos as transport policy.

## Production-network conformance gate

The Gateway migration is not only a one-time refactor. Oramasys CI rejects new
production imports of raw outbound transports and obvious network CLI
subprocesses under `src/orama/`.

The gate enforces the steady-state architecture:

- Oramasys owns application/provider/workflow semantics;
- Telos owns endpoint-specific security and secure outbound transport;
- a future provider integration must consume/extend Telos rather than importing
  a second HTTP/socket implementation into Oramasys;
- test-only clients remain permitted outside the production source tree.

The executable gate is `scripts/check_telos_network_authority.py`. It is wired
into both the Makefile and GitHub Actions.

## Perpetua Core discovery convergence

Perpetua Core's historical `health_probe()` was a distinct raw `httpx` path and
therefore a separate endpoint-security exception. The convergence work routes
that discovery probe through Telos while keeping Core's public discovery/result
semantics intact.

The required authority split is:

- Core expresses explicit discovery intent and maps transport outcomes into
  `ProbeResult` / `BackendHealth`;
- Telos performs endpoint normalization, DNS/address admission, exact
  endpoint-use authorization, secure transport, pinning/peer verification,
  redirect/proxy/TLS destination safety;
- Core must not introduce a permanent always-allow `HEALTH_PROBE` semantic
  authorizer.

Oramasys pins the exact verified Core revision once that Core PR is green and
review-clean. A cross-repo conformance test then proves the installed Core probe
no longer creates a raw `httpx.AsyncClient` path.

## Phase-3 provider invocation boundary

Actual model invocation is intentionally introduced through an application port
rather than by adding a raw HTTP client to `perpetua_graph.py`.

`orama.providers` defines immutable request/result contracts and a
`ProviderInvoker` protocol. `build_graph(..., provider_invoker=None)` preserves
the existing no-network Phase-2 behavior. When an invoker is explicitly
supplied, Oramasys passes resolved backend/application intent through that port
and records the returned provider/Telos evidence.

A future concrete network provider implementation must be Telos-backed. The
source/CI network-authority gate prevents a direct `httpx`, `requests`,
`urllib`, socket, or `curl` implementation from landing under `src/orama/`.

## Dependency pin and immutable migration evidence

Dependency pins are immutable commit SHAs rather than moving branches. Update
this document and the dependency pins together when a newly verified Telos or
Core implementation is adopted.

Historical Gateway absorption evidence:

- Telos dependency/evidence head used by the merged Gateway migration:
  `19810d0493344aa507c29c462f68afbc1b98ecf8`.
- Oramasys PR #5 merge commit:
  `539e112948a9a13d12d648464084bb0cf3c01f2a`.

The outbound-convergence PR's own exact pins, verified directly against
`pyproject.toml` and a real local test run, not merely asserted:

- Telos pin: `b2143083044496d93be3ca2dc88c28135e034d9f`.
- Perpetua Core pin: `1021367aed03872a2fcfb0c5d30229e241e06dc5`
  (the Core health-probe PR #3 head, green on Python 3.11 and 3.12).
- Full local suite: 72/72 passed.
- Coverage: 94% (`src/orama`), above the required 80% floor.
- Production-network authority scanner against `src/orama`: exit 0, zero
  violations.

## Verification requirements

The convergence is complete only when:

- the production-network authority scanner passes;
- Gateway conformance tests prove no second transport-security stack exists;
- the pinned Core health probe is Telos-backed;
- provider invocation remains a contract/injection boundary with no raw network
  client in Oramasys production code;
- Oramasys exact-head CI is green on Python 3.11 and 3.12;
- project coverage is at least 80%, with stricter configured thresholds never
  lowered;
- fresh review-thread sweeps contain no unresolved actionable findings;
- coordination/handoff records are synchronized to exact heads.

No verification status authorizes merging; owner merge authorization remains
separate.
