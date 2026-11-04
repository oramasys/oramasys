# Next-slice CI baseline audit

Observed 2026-11-03 22:14 UTC (2026-11-04 in Asia/Manila, the plan's date). Consumer main `98b7568fa4bedbf59be788b62d2c7333f10535f4`; producer main `a7211df7d58695f35f5afee9b6b50af6a3f96139`. These are merged baseline evidence only: any later producer fix produces a distinct candidate and is not covered by these checks or by the earlier green PR #92 cells.

Consumer [PR #92](https://github.com/oramasys/oramasys/pull/92), head `9ca04b3fd7176a83403dffe8ec158c84ae794949`, already changes the R3 checkout from the old source-test candidate to merged producer `a7211df7d58695f35f5afee9b6b50af6a3f96139`. It is the sole open consumer PR and overlaps the workflow and revocation tests; no producer PR was open at observation. Its 19 Actions checks passed; CodeRabbit was skipped. The two exact R3 cells are below. Both ran on the pull_request event and the workflow checks out without `ref`, so they tested the synthetic merge commit `576454759cc044677a8f031a7d4f8915e69dbb61` (`refs/pull/92/merge`, logged as "Merge 9ca04b3fd7176a83403dffe8ec158c84ae794949 into 98b7568fa4bedbf59be788b62d2c7333f10535f4"), not the PR head alone; the base SHA at that time was `98b7568fa4bedbf59be788b62d2c7333f10535f4` and the head SHA is retained above:

| Check | Result | URL |
| --- | --- | --- |
| r3-composition (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41726657841/job/126233094832 |
| r3-composition (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41726657841/job/126233095263 |

## Consumer main jobs

| Check | Result | URL |
| --- | --- | --- |
| final-producers | skipped | https://github.com/oramasys/oramasys/actions/runs/41647597581/job/125956997328 |
| effect-candidate | skipped | https://github.com/oramasys/oramasys/actions/runs/41647597581/job/125956936088 |
| manifest-schema3 (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41647597876/job/125956935621 |
| permit-interop | success | https://github.com/oramasys/oramasys/actions/runs/41647597931/job/125956934914 |
| manifest-schema3 (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41647597876/job/125956934785 |
| test (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41647597815/job/125956934586 |
| test (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41647597815/job/125956934386 |
| grant-composition-interop (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41647597780/job/125956934165 |
| offline-oracles (3.12, production, requirements/compatibility-core-production.txt, 1) | success | https://github.com/oramasys/oramasys/actions/runs/41647597390/job/125956933730 |
| core-gate (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41647597629/job/125956933694 |
| grant-composition-interop (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41647597780/job/125956933672 |
| effect-grant-composition (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41647597518/job/125956933630 |
| core-gate (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41647597629/job/125956933532 |
| offline-oracles (3.11, production, requirements/compatibility-core-production.txt, 1) | success | https://github.com/oramasys/oramasys/actions/runs/41647597390/job/125956933460 |
| r3-composition (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41647597560/job/125956933457 |
| offline-oracles (3.11, core-r3, requirements/compatibility-core-candidate.txt, 1) | success | https://github.com/oramasys/oramasys/actions/runs/41647597390/job/125956933373 |
| offline-oracles (3.11, policy-r3, requirements/compatibility-core-policy-r3.txt, 0) | success | https://github.com/oramasys/oramasys/actions/runs/41647597390/job/125956933337 |
| offline-oracles (3.12, core-r3, requirements/compatibility-core-candidate.txt, 1) | success | https://github.com/oramasys/oramasys/actions/runs/41647597390/job/125956933260 |
| r3-composition (3.12) | success | https://github.com/oramasys/oramasys/actions/runs/41647597560/job/125956933222 |
| effect-grant-composition (3.11) | success | https://github.com/oramasys/oramasys/actions/runs/41647597518/job/125956933166 |
| freeze-gate | success | https://github.com/oramasys/oramasys/actions/runs/41647597581/job/125956933117 |
| offline-oracles (3.12, policy-r3, requirements/compatibility-core-policy-r3.txt, 0) | success | https://github.com/oramasys/oramasys/actions/runs/41647597390/job/125956932930 |

## Producer main jobs

| Check | Result | URL |
| --- | --- | --- |
| test (3.11) | success | https://github.com/oramasys/phylax/actions/runs/41643481866/job/125942631481 |
| permit-interop | success | https://github.com/oramasys/phylax/actions/runs/41643481866/job/125942631468 |
| windows-platform (3.12) | success | https://github.com/oramasys/phylax/actions/runs/41643481866/job/125942631463 |
| windows-platform (3.11) | success | https://github.com/oramasys/phylax/actions/runs/41643481866/job/125942631405 |
| test (3.12) | success | https://github.com/oramasys/phylax/actions/runs/41643481866/job/125942631008 |

Windows jobs run `src/tests/test_platform_fs.py` only, not the full producer suite. Required branch protection check lists were unavailable (HTTP 403 for both repositories). No failing check runs were observed; the two skipped consumer jobs and skipped PR CodeRabbit are not passes. Legacy combined status returns pending with zero legacy statuses; this is absent legacy status data, not a failed Actions job.

## Pins and bounded producer delta

Consumer main R3 tests use producer `7cac74e240de5830cef82c3d46921d00c21786df`; PR #92 uses `a7211df7d58695f35f5afee9b6b50af6a3f96139`. The source-only lane runs Ubuntu Python 3.11/3.12 with both interop-required flags set, installs `.[dev]` and `PyNaCl==1.6.2`, and runs `pip check`. Checkout action is `34e114876b0b11c390a56381ad16ebd13914f8d5`, setup-python `a26af69be951a213d495a4c3e4e4022e16d87065`. Consumer optional production grant-serving pin and verify-only compatibility pin both remain `0c3e860749b3ff8f62e102679f1f415f8acf0a61`. Producer declares `PyNaCl>=1.5`, `pywin32` on Windows and dev `pytest>=8.0`, `pytest-cov>=5.0`; these declarations do not establish exact resolved CI versions.

[Producer comparison](https://github.com/oramasys/phylax/compare/7cac74e240de5830cef82c3d46921d00c21786df...a7211df7d58695f35f5afee9b6b50af6a3f96139) is ahead six commits, behind zero, with three net changed paths: `src/phylax/operator_assertion.py`, `src/tests/test_operator_assertion.py`, `src/tests/test_revocation_publication.py`. The operator assertion change uses an older-SQLite-compatible seed query, samples the clock under the write lock and refuses rollback between validation and commit or below the durable clock. Tests cover concurrent valid calls and within-call rollback; other net test edits are docstrings.
