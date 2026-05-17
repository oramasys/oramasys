# oramasys dev Makefile
PYTHON := /opt/homebrew/bin/python3.13
PERPETUA_CORE := ../perpetua-core

.PHONY: install test dev-install

dev-install:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -e $(PERPETUA_CORE)
	.venv/bin/pip install -e ".[dev]"

install: dev-install

test:
	.venv/bin/pip install -e $(PERPETUA_CORE) -q
	.venv/bin/python3.13 -m pytest tests/ -v
