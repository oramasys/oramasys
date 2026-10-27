# Release 1–2 inert process-crash evidence

Status: draft candidate evidence; serving and production T3 remain unqualified.

This extends PR #77's inert-driver tests on baseline
`8a68cc386299ead2f6c8e665a7fb4ea0cc33508a`. It changes test support only;
the production authorization, wire, schema, send marker and outcome rules stay
those of the candidate. Tests use synthetic signatures and gate ports. They do
not establish trusted effect-grant provenance or deployed isolation.

## Process matrix

`src/tests/test_inert_effect_process_crashes.py` launches a fresh interpreter
and terminates it with `os._exit(73)`. No connection close, exception unwinding,
or explicit rollback runs in the killed interpreter. The parent opens a new
SQLite connection and checks durable state.

| Crash boundary | Required durable result |
| --- | --- |
| Before authorization | No intent, grant use, outbox or consumed reservation |
| Authorization writes executed, before COMMIT | All authorization writes roll back together |
| After authorization commit | Complete intent and grant use; send marker still clear |
| Send-marker write executed, before COMMIT | Marker rolls back; one inert send remains possible |
| After send-marker commit, before settlement | UNKNOWN persists and replay refuses |
| Settlement write executed, before COMMIT | UNKNOWN persists and replay refuses |
| After settlement commit | Confirmed inert evidence persists and replay refuses |

The write-before-commit cases use SQLite trace callbacks: a target write arms
the crash, and the following COMMIT triggers process death before it executes.
An eighth test starts two independent sender processes against one authorized
attempt. Exactly one reports a send, the other refuses, and one confirmed
simulation receipt remains durable.

## Reproduction

```bash
python -m pytest -q src/tests/test_inert_effect_process_crashes.py
python -m pytest -q src/tests
python scripts/check_telos_network_authority.py src/orama
```

Fresh non-editable installs on Python 3.11 and 3.12 also passed the existing
`scripts/verify_production_install.py` check from outside the checkout with
isolated interpreter mode. Core's PEP 610 identity was the declared pin
`6d75cfe08af95992dddffab13ae3019aa9c41350`; the declared Telos and Agate pins
were installed without alteration. The full source test suite passed on each
interpreter: 2,001 passed and 3 skipped. Pytest uses the repository's source-path
configuration; this is developer candidate evidence, not a sealed installed
producer/consumer release matrix. No Phylax effect-verifier qualification is
claimed by the clean-install check.

## Remaining release gates

1. **Trusted consumer effect-grant adapter.** The optional grant-serving pin is
   Phylax `0c3e860749b3ff8f62e102679f1f415f8acf0a61`, the recovery-grant
   verifier. A recovery verifier cannot authenticate effect authority. The
   consumer's `VerifiedDispatchGrant` is explicitly a value object whose
   provenance belongs to the composition root. Constructing it from request
   fields would bypass that boundary. Phylax's `DispatchIssuerSigner` at inspected
   head `31afe7f485bec9d305531d9edc3460ab066dc8c5` covers issuer signing only.
   These facts do not supply a consumer v2 effect-grant verification adapter.
2. **Final execution composition.** Connect verified effect facts, authenticated
   scoped approval, trusted issuer events, the existing atomic Step 4.3
   transaction, and the driver at the reviewed execution boundary. The fake
   ports in this matrix do not qualify that connection. Preserve the ratified
   ordering for revocation and finalization rather than adding an independent
   authority check with different semantics.
3. **Real isolation evidence.** Run seed-access denial and issuer-write denial
   from the actual serving identity with the deployment's configuration. Local
   test subprocesses run as the developer and do not prove account isolation.
4. **Release qualification.** Record source, wheel, registry, manifest, policy
   and configuration digests, qualify the complete pinned set, obtain independent
   reviews, then rerun after any producer merge and repin. Actual deployment
   checks and a separate operator activation record remain required.

This matrix closes a bounded inert process/restart evidence gap. It does not
qualify arbitrary effects, a provider transport, durable graph continuation,
signer isolation, autonomous recovery or production activation. No effect route
is exposed by this extension.
