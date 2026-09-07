# oramasys dev Makefile
# Portable interpreter: prefer python3.13 on PATH, fall back to python3; override with `make PYTHON=...`
PYTHON ?= $(shell command -v python3.13 || command -v python3)
PERPETUA_CORE := ../perpetua-core
# telos is now published (github.com/oramasys/telos) and resolves via
# pyproject.toml's own git dependency during `pip install -e ".[dev]"` below
# -- no forced sibling-checkout install needed by default. Override TELOS to
# a local path (e.g. `make dev-install TELOS=../telos`) to develop against a
# local telos checkout instead of the published git ref.
TELOS ?=

.PHONY: install test dev-install

dev-install:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -e $(PERPETUA_CORE)
	.venv/bin/pip install -e ".[dev]"
	$(if $(TELOS),.venv/bin/pip install -e $(TELOS),)

install: dev-install

test:
	.venv/bin/pip install -e $(PERPETUA_CORE) -q
	.venv/bin/pip install -e ".[dev]" -q
	$(if $(TELOS),.venv/bin/pip install -e $(TELOS) -q,)
	.venv/bin/python -m pytest src/tests/ -v
