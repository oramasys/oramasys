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

In a fresh environment, install requirements/compatibility-oracles-py312.txt. Then
check out one lane's exact Core revision, install it and this checkout with --no-deps
--no-build-isolation, and run pip check and pytest with that lane's registry profile.
The profile defaults to production when unset, so every command below sets it
explicitly. The Core revision and profile must be a matching pair; a mismatched pair
reports a result for a lane that was not installed. The CI guard test checks that each
command here agrees with the lane files and the registry profiles.

Set ORAMA_DOCS_V2_REGISTRY to the ownership-registry.json of an Orama checkout at the
revision pinned in the workflows, otherwise the byte-parity check is skipped.

Production lane (Core 4d217f6b9e94e36554a9427198b8c2c4b7febc47):

```bash
git -C core-candidate checkout 4d217f6b9e94e36554a9427198b8c2c4b7febc47
python -m pip install --no-deps --no-build-isolation -e ./core-candidate -e .
python -m pip check
ORAMA_REGISTRY_PROFILE=production pytest -q src/tests tests/oracles
```

Policy-R3 lane (Core 04759a50c748444ff97136ea95c1e1289eac3a1a):

```bash
git -C core-candidate checkout 04759a50c748444ff97136ea95c1e1289eac3a1a
python -m pip install --no-deps --no-build-isolation -e ./core-candidate -e .
python -m pip check
ORAMA_REGISTRY_PROFILE=policy-r3 pytest -q src/tests tests/oracles
```

Core-R3 lane (Core 34e4a8d22212d38d6ab100c1ad7fb2b19f56cb68):

```bash
git -C core-candidate checkout 34e4a8d22212d38d6ab100c1ad7fb2b19f56cb68
python -m pip install --no-deps --no-build-isolation -e ./core-candidate -e .
python -m pip check
ORAMA_REGISTRY_PROFILE=core-r3 pytest -q src/tests tests/oracles
```

Do not ask pip to resolve a candidate source alongside Oramasys's production
Core direct reference: install the full oracle snapshot first, then overlay the lane's
Core explicitly as above. Editable overlays are for oracle reproduction only; they are
never the production-install proof.

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
