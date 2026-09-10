# oramasys

Hardware-aware multi-agent **orchestration system** — the graph DSL + FastAPI
surface layered on top of the `perpetua-core` kernel. Imports `perpetua-core`;
the kernel never imports `oramasys` (one-way boundary).

## Layout

```
bin/            # thin executables (bin/serve → uvicorn orama.api.server:app)
src/
  orama/        # the package (import orama)
    api/        # FastAPI surface (server.py: app)
    gateway/    # Gateway Lifecycle orchestration + owner ports
    graph/      # orchestration graph + perpetua dispatch bridge
    providers/  # application-facing provider invocation contracts
  tests/        # test suite (pytest)
Makefile        # dev-install / test
LICENSE
pyproject.toml  # build (hatchling, src-layout) + pytest config
```

Source lives under `src/` (PyPA src-layout); imports stay `import orama` via
`tool.hatch.build.targets.wheel.packages = ["src/orama"]` and pytest
`pythonpath = ["src"]`.

## Develop

```bash
make dev-install                    # venv + editable installs
make check-telos-network-authority  # reject raw production network paths
make test                           # authority gate + pytest src/tests
bin/serve                           # run the API
```

Requires Python ≥ 3.11. `make dev-install`/`make test` still support a sibling
`../perpetua-core` checkout for fast local iteration. `pyproject.toml` also pins
Core and Telos by immutable Git commit so clean CI installs are reproducible.

## Network-security architecture

Oramasys is an application/workflow orchestrator, not an endpoint-security
stack. `oramasys/telos` owns endpoint identity, DNS/address admission, SSRF
policy, semantic endpoint-use authorization, connection pinning/peer
verification, redirects, proxy isolation, and TLS destination identity.

The repository enforces that boundary with
`scripts/check_telos_network_authority.py`, which rejects new raw outbound
network imports/commands under `src/orama/`. Provider and Gateway compatibility
surfaces remain thin application adapters over Telos rather than independent
secure connectors.

See:

- `docs/architecture/telos-network-authority.md`
- `docs/architecture/gateway-telos-endpoint-security-migration.md`

## Gateway Lifecycle

`orama.gateway.GatewayLifecycle` owns the idempotent user workflow,
structured progress, and routing-state materialization for local model
gateways. It deliberately does not install packages, store credentials, probe
raw endpoints, choose hardware, or operate model providers itself.

The caller injects semantic-owner adapters:

- Telos authorizes every configuration and health endpoint;
- Phylax verifies pinned artifact provenance and integrity, redacts event
  details, and decides runtime admission;
- Agate resolves hardware placement;
- Claude-Desktop-LLM operates Ollama or LM Studio and reports readiness.

Requests require explicit operator consent scoped to the artifact id, exact
version, and `sha256:<64 lowercase hex>` digest. Mutable versions such as
`latest` are rejected. Successful routing state is keyed by the complete
immutable request, so an identical repeat run returns `already_ready` without
repeating owner operations.

`PerpetuaToolsGatewayFacade` is a temporary one-way compatibility entry point.
It delegates to Gateway Lifecycle and propagates denial, timeout, and error
results unchanged. It contains no inline legacy implementation and no silent
fallback.

## Provider invocation boundary

`orama.providers` defines immutable application-facing provider invocation
contracts. `build_graph(..., provider_invoker=None)` preserves the current
Phase-2 no-network behavior. A future concrete provider invoker must use Telos
for outbound transport rather than importing a raw HTTP/socket client into
Oramasys production code.
