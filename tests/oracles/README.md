# Offline compatibility oracle cells

This directory runs real upstream packages; supported cells do not use
importorskip. The ordinary src/tests suite needs no framework installation.
Normal stack dependencies and extras contain no LC/LG/Pydantic AI dependency.

The requirements snapshot pins LC 1.0.7, LG 1.0.3 and pydantic-ai-slim 1.0.18
plus their transitive environment. It was exercised on Linux/Python 3.12.14;
CI also checks 3.11. It is not a hash-verified universal lock for all platforms.
The workflow selects an explicit immutable Core revision for every lane:
production uses the promoted R3 commit, while the policy-R3 and core-R3 lanes
retain their original historical qualification revisions.  Candidate evidence
is never used as the production-install proof.

## Reproduce

In a fresh environment, install requirements/compatibility-oracles-py312.txt,
then install the exact candidate Core checkout and this checkout with --no-deps
--no-build-isolation. Run pip check, then pytest -q src/tests tests/oracles.
Do not ask pip to resolve a candidate source alongside Oramasys's production
Core direct reference: install production dependencies first or use this full
oracle snapshot, then overlay the candidate explicitly.

Socket connection attempts fail each oracle. Pydantic AI model requests are
disabled, with exact TestModel/FunctionModel fixtures. The guard is test scope,
not an adversarial sandbox for caller-supplied Python tools.

## Cells and limits

Ten cells cover text, structured output, local tools, usage-limit exhaustion,
pending deferred approval, FunctionModel, model mutation/global gate refusal,
LCEL composition through an explicit RunnableLambda wrapper, real LG conditional
target export/execution, and real Agent graph-tool schema registration.

No evidence here proves automatic Runnable class identity, full unchanged-caller
replacement, both implicit pipe directions, callbacks, streaming cancellation,
reducers/joins, dynamic sends, checkpoint wire formats, durable effect recovery,
real provider egress or full public API coverage. The exporter uses LG's scheduler;
it does not preserve Core nodes_visited/max_steps/interrupt behavior.

For v0.x and further v1.x lines, create one isolated pinned environment per
matrix row, inventory supported symbols, then compare outputs/errors/config,
public event schemas and causal partial order. Record exact source/version,
fixture digest, interpreter, lock and candidate. Policy refusals are enforcement
outcomes, never ordinary upstream-parity passes.
