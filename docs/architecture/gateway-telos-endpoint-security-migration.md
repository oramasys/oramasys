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
already implemented in Telos `transport.py`; the Gateway compatibility dial is
for bounded provider connectivity and delegates endpoint security to the same
Telos authority.

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

## Dependency pin and immutable migration evidence

Oramasys pins Telos to the exact verified restoration/secure-dial head rather
than the superseded semantic-only Telos scaffold. Update this document and the
pin together if subsequent remediation changes the verified Telos head.

- Telos verified head and dependency pin: `19810d0493344aa507c29c462f68afbc1b98ecf8`.
- Oramasys verified implementation/remediation head: `0639578fe63c9681b4ee35b6e4abab69483a5d64`.

The Oramasys value identifies the immutable implementation state immediately
before this evidence-only documentation update. A later PR tip may therefore
advance for documentation or review bookkeeping without changing the recorded
implementation evidence; any implementation change requires refreshing this
record after re-verification.

## Verification requirements

The migration is complete only when both Telos and Oramasys exact-head CI are
green on Python 3.11 and 3.12 with at least 80% project coverage, fresh review
thread sweeps contain no unresolved migration findings, and Orama/PT handoff
records are synchronized to those exact heads.

No verification status authorizes merging; owner merge authorization remains
separate.
