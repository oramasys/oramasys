# Outbound Consumer Authority Ledger

Status: current static inventory. This document records authority boundaries;
it is not a runtime dispatch or financial ledger.

| Consumer path | Direct network client | Security authority | Evidence | Status |
| --- | --- | --- | --- | --- |
| `src/orama/gateway/dialer.py` | No | `telos.SecureDialer` via `ModelServerDialer` | `src/tests/test_model_server_dialer.py`, `src/tests/test_gateway_telos_conformance.py` | Enforced |
| Core discovery probe | No Oramasys-owned client | Perpetua Core discovery delegates endpoint handling to Telos | `src/tests/test_core_telos_discovery_contract.py` | Dependency-pinned and tested |
| `src/orama/graph/perpetua_graph.py` provider dispatch | No | Injected `ProviderInvoker` contract; result requires opaque provider and decision references | `src/tests/test_provider_transport_contract.py` | Delegated boundary |
| Production-source scan | N/A | `scripts/check_telos_network_authority.py` rejects independent HTTP, socket, and network-command paths | `src/tests/test_telos_network_authority.py` | Enforced |

## Explicit Gap

No concrete `ProviderInvoker` implementation or durable per-run dispatch record
exists in this repository. The injected seam prevents a hidden raw-network
client, but it cannot by itself prove that an eventual invoker is Telos-backed
or persist an auditable dispatch outcome. Introduce that durable ledger only
with an owner-defined persistence and retention authority; do not replace it
with an in-memory list or unredacted endpoint log.
