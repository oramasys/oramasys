# oramasys dev Makefile
# Portable interpreter: prefer python3.13 on PATH, fall back to python3; override with `make PYTHON=...`
PYTHON ?= $(shell command -v python3.13 || command -v python3)
PERPETUA_CORE := ../perpetua-core

.PHONY: install test dev-install

dev-install:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -e $(PERPETUA_CORE)
	.venv/bin/pip install -e ".[dev]"

install: dev-install

test:
	.venv/bin/pip install -e $(PERPETUA_CORE) -q
	.venv/bin/python -m pytest src/tests/ -v
