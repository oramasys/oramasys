# compatibility-manifest.v3.json: notes

Status: exploratory (no digest has been frozen; no Linux run). The coordinator records the frozen digest.

## Digest binding
The digest is NOT stored inside the manifest (that would be circular, and the validator rejects
unknown top-level keys). `canonical_digest` = sha256 of canonical JSON (UTF-8, sorted keys, compact).
The frozen value is supplied externally as `expected_digest` (validator) or
`scripts/compat_manifest_digest.py <file> --expected-digest <hex>`. Only schema 3 may be digest-bound.
Digest of the file as committed in this lane: recorded in the lane report, not here (any edit changes it).

## Verified inputs (from the lane brief)
Consumer, three producer candidates, phylax candidate (composition only, no production pin,
`declared_dependency` false), three production pins, registry ref, historical cells (copied from schema 2).

## PROVISIONAL fields (shape required by the validator; values not verifiable from the repo)
- `cells[final-producers].min_passed` = 360: copied from the historical floor; the real floor needs a run.
- `cells[final-producers].require_r3` = true: assumed for candidate producers; confirm.
- `artifacts`, `environments`, `required_capabilities`, `source_contracts`: the validator only requires
  non-empty containers; contents transcribe boundary doc sections 2.3-2.5 and are not machine-checked.
  `source_contracts.test_count` (4) is taken from the boundary doc, unverified here.
- `disabled_capabilities` wording is a transcription of boundary section 2.9.
- Workflow matrix: not updated (out of scope); `validate_workflow` would fail against the current workflow.
