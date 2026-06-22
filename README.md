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

Requires Python ≥ 3.11 and a sibling `../perpetua-core` checkout.
