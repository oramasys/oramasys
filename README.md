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
make dev-install      # venv + editable install of perpetua-core and oramasys
make test             # pytest src/tests
bin/serve             # run the API (uvicorn, reads from src/)
```

Requires Python ≥ 3.11. `make dev-install`/`make test` still use a sibling
`../perpetua-core` checkout (pre-release, unpublished) for fast local
iteration. `telos` is now published at
[`oramasys/telos`](https://github.com/oramasys/telos) — `pyproject.toml` pins
`oramasys-telos` to a reviewed Telos commit, so the entry is
independently resolvable by a clean `pip install`/wheel build without a
sibling checkout, so `make dev-install` no longer installs it from `../telos`
by default; override `TELOS` in the `make` invocation if you need to develop
against a local telos checkout instead.

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
