"""v2 Orchestrator Controller: the single authority for job claims (doc 68).

This package is the internal module home recorded in doc 68 section 2. It holds the
authoritative claim store, the opt-in expiry worker, the Telos/Phylax ports and the
transactional outbox. See ``docs/architecture/orchestrator-controller-claim-contract.md``.

Importing this package has no side effects: it opens no database, starts no thread or
timer and touches no network. Every runtime object is constructed explicitly by the
composing application. Job-claim leases here are distinct from the execution run leases
in ``orama.graph.execution_guard``.
"""
from __future__ import annotations
