# Foreign-provider transport (T4) contract

`orama.providers.foreign_transport.GuardedForeignInvoker` implements `ProviderInvoker` and ships **dark**:
the default `TransportConfig()` refuses every call.

## Gates, in order
1. `mode == "disabled"` (default) → `transport.disabled`.
2. Default-deny `(backend, model)` allowlist → `transport.not_allowlisted`.
3. `dry_run` mode records the target and returns without dialing.
4. `live` requires a prior recorded dry run for the same target → `transport.dry_run_required`.
5. Durable SQLite holds under `BEGIN IMMEDIATE`: call cap and cost cap, shared across instances/processes.
6. The injected `DialPort` (Telos-backed) performs the call. Any `Exception` is `transport.dial_failed` and the
   hold **stays charged** (unknown outcome is never refunded). Cancellation and other control-flow
   exceptions propagate unchanged, and the hold stays charged. All store work runs off the event loop
   (`asyncio.to_thread`) and every connection is closed after use.
7. A caller cancelled while its reservation is still waiting on the store never dials, so the hold
   that reservation places is released when it lands (repeated timeouts cannot drain the caps).
8. If settlement fails after a successful dial, the provider result is still returned; the hold stays
   charged, is listed in `unsettled_holds` and is logged for the operator.

## Out of scope by design
No network client, DNS, SSRF, redirect or TLS logic exists here (AST-enforced); those belong to Telos.
Redirects and non-2xx handling are the `DialPort`'s responsibility and must surface as exceptions.
Live use needs operator config, a real Telos dial port and durable admission; none are enabled by this change.
