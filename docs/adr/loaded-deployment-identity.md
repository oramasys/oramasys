# Loaded deployment identity

**Status:** reviewed design with a bounded loader-only implementation; actual
host qualification, binding to later service consumption, and activation remain open.
See the [qualification handoff](../release12-postmerge-qualification-2026-11-04.md).

**Baseline:** consumer `9ca04b3fd7176a83403dffe8ec158c84ae794949`.

**Scope:** loader-bound evidence for R5, not a serving permission or approval.

## Decision and boundaries

Propose capturing a versioned, immutable snapshot inside the actual configuration loading operation, after validation and effective override resolution, and deriving a strictly allowlisted public projection and a restricted private evidence record from that snapshot. An evidence generation links these records to independently obtained installed-set and policy evidence. After design review, a bounded loader-only implementation and synthetic tests can proceed without a host choice. The integration point and complete loader chain must also be verified against the chosen deployment before claiming deployment coverage. A synthetic run demonstrates software behavior only; R5 remains open until evidence is collected and reviewed on the actual installed deployment.

Alternatives considered: (1) hash arbitrary files after startup: rejected because a later read does not establish what was loaded, misses environment and fallbacks, and a public hash may enable secret guessing; (2) serialize the existing `EffectiveNode` directly: rejected because it is mutable and contains paths, accounts, endpoints, raw hash and free-text notes; (3) the proposed loader-bound snapshot: captures the selected effective values and outcome, at the cost of integrating and reviewing every actual loader and managing private evidence. This is a recommendation for review, not an approved host or implementation decision.

## Observed baseline

`src/orama/deploy/profile.py` reads at most `MAX_PROFILE_BYTES + 1` bytes once, decodes UTF-8, rejects duplicate YAML keys and validates a version-1 `ServingProfile`. `resolve_node` selects `ORAMA_NODE_ID` or hostname, checks the node OS, and applies `ORAMA_NODE_ROLE` as a downgrade-only override. Missing or unreadable files fall back to client; no matching node does likewise after a successful parse. Invalid UTF-8, excessive size, malformed/duplicate YAML, validation errors, OS mismatch and invalid role override raise `ProfileError`. The returned `EffectiveNode` is mutable and includes a SHA-256 of the raw bytes when successfully parsed, plus path, endpoint, accounts and notes. It does not contain every profile field (for example `serves` or `expected_principal`). The profile is topology, not approval; `serving_permitted` also checks the flag and matcher, and `check_startup` can refuse. No conclusion follows that this CLI loader is the actual service's complete configuration chain: establish that on the chosen host.

`scripts/verify_installed_identity.py` requires Python to run in isolation outside a checkout, verifies the consumer wheel digest and source provenance against a plan, checks producer VCS metadata, and checks imported module ownership and location. `scripts/verify_phylax_pin.py` checks installed Phylax VCS URL/commit and import location against a pin. `scripts/operator_serving_checks.sh` invokes those and the service-identity check, preserving an unset serving flag. These checks are separate observations, not a loaded-configuration or policy verifier, nor proof of all installed file contents at runtime. The R5 requirements document explicitly says no configuration/policy identity script exists yet. Other policy digests in the code have their own narrower purposes and cannot be substituted without tracing the deployed policy loader.

## Capture and interfaces (proposed, not existing API)

1. A capture-capable loader reads the same bounded byte buffer it parses, snapshots the relevant environment inputs once, validates and resolves the profile, and constructs the effective result and immutable evidence snapshot in the same operation. Do not reopen a supplied path to reconstruct a load. Deep-copy/freeze nested values before returning; subsequent mutation of `EffectiveNode`, input mappings, or parsed objects must not alter evidence. Preserve existing loader and refusal semantics.
2. A typed result such as `LoadedIdentityCapture(effective, public_projection, private_capture)` is an illustrative interface, not a mandated signature. Successful fallback carries its actual fallback source and effective client/off role. Refusals produce a separate classified failure record, never a successful identity or an invented effective configuration. Capture failure must not silently create qualified evidence; the design review must decide whether it also blocks startup in the actual integration.
3. `project_public(snapshot) -> PublicProjectionV1` accepts only captured, validated closed types. `assemble_private(generation_context, snapshot, verifier_results, policy_capture) -> PrivateEvidenceV1` binds independently verified inputs with explicit status and provenance. Unknown schema versions, unknown keys, missing required inputs, invalid enums, mismatched generations or verifier failure refuse qualification. These names are interface sketches; precise serialization and integration require review.
4. Every actual configuration and policy source, defaults, environment input, override, reload path, and policy loader must be inventoried. Add loader-owned capture for each input that affects the claimed identity, or mark coverage incomplete and refuse an R5-complete claim. Record capture at process startup or actual reload, not in a separate process pretending to observe that service. A restart or reload creates a new generation; associate any old record only with its original process instance and interval. No record establishes continued current state after an unobserved reload or process replacement.

## Public projection v1: closed schema

Canonical JSON is proposed: UTF-8, sorted keys, compact separators, no non-finite numbers, no duplicate or unknown fields. A schema version defines exact types and enum values. All keys below are required; null has only the meaning stated. No generic metadata, diagnostics or passthrough fields are allowed.

| Key | Type and permitted values | Meaning |
| --- | --- | --- |
| `schema` | integer `1` | Public schema version |
| `outcome` | `loaded`, `fallback` or `refused` | Loader outcome; refusal has null effective fields |
| `source` | `profile`, `no-profile`, `unreadable-profile`, `no-matching-node`, `refused` | Fixed classification, not a path or error string |
| `role` | `primary-server`, `secondary-server`, `client`, `off`, or null on refusal | Effective role after override |
| `serving_applicability` | `applicable`, `not-applicable`, or null on refusal | Topology applicability only, never authorization |
| `public_state` | `local`, `signed-publication`, or null when no selected node or refused | Effective profile setting |
| `role_override` | `absent`, `same`, `downgraded`, `ignored`, `unknown`, or `invalid` | Classified effect; unknown means refusal occurred before evaluation could be established |
| `refusal` | null or fixed code `load-refused`; future reviewed integrations may distinguish `profile-invalid`, `os-mismatch`, `role-override-invalid`, `startup-refused`, `capture-failed` | Coarse outcome only; no exception text; the initial wrapper cannot distinguish existing ProfileError origins |

Public output excludes node/installation names, hostnames, OS/account identifiers, endpoints, paths, principal/SID, environment values, raw YAML, notes, credentials, raw profile/policy hashes and hashes or commitments of low-entropy secrets. The public projection contains no generation identifier by default: even a random identifier can correlate deployments. A digest of these canonical *public bytes* may be used as a projection fingerprint; it establishes equality of projections only, not equality of private configuration or authenticity. The coarse refused codes require mapping at their origin, never parsing exception messages. `startup-refused` applies only when the same process actually performs that check; a loader result alone cannot claim it. No public record implies current approval, successful startup, policy completeness or permission to serve.

## Private evidence v1

Restricted to the operator and authorized reviewers, encrypted and access-controlled using the eventual host's selected mechanism. Do not store credentials, secret values, or raw secret-bearing configuration merely because the record is private. Define retention and deletion with the operator before collection. A record contains:

- schema and a fresh opaque generation ID; capture time in UTC, process-instance/restart or reload association, and explicit capture coverage and status;
- exact canonical public projection bytes and their SHA-256, plus a binding between the generation and the actual loader invocation;
- the loader/schema implementation identity and source revision, effective role and source, classified override including the validated requested role when safe, selected non-secret effective values required for review, and explicit absent/fallback/refusal states. Store sensitive paths, endpoints, node and service identifiers only if necessary and under restricted access; never copy exception text. Record only safe classifications or protected references for secret-bearing inputs, never bare low-entropy secret hashes;
- installed artifact observations and verifier version, invocation context, status and complete restricted outputs or authenticated references: consumer wheel digest and provenance/source revision, producer distribution/source revisions and Phylax pin outcome, along with actual service interpreter/import identity. Compare observed values against the expected deployment set; a mismatch or unverifiable binding fails qualification;
- policy loader/schema/version and revision or digest of **validated non-secret policy content**, captured by the actual policy loader. For secret-bearing policy, use a reviewed protected reference or keyed commitment with managed key and domain separation, only if needed; never publish it or use an ordinary hash as a secret fingerprint. Mark absent, not applicable, failed and unknown distinctly; no policy coverage is assumed until its actual inputs are inventoried;
- observed service identity and OS, evidence collection method and operator-controlled provenance, capture scope, timestamps, and any supported filesystem proof and its limits. Bind the independently run verifier results to the same installed environment and process generation through a reviewed mechanism; merely putting outputs in one JSON object is not proof of simultaneity or common origin.

Record generation is not authentication. The host owner must choose secure collection, integrity protection, transport and publication, and establish how a reviewer verifies the binding between service process, capture, installed verifiers and policy. Until then, the record is an unverified assertion. Public publication must only emit the public schema, never the private record or verifier stderr. No public fingerprint or generation implies installed identity was verified.

## Filesystem and platform proof

The baseline `Path.open` and buffer hash identify bytes read, not stable pathname, ownership, ACL, symlink safety, or the file later at that path. A loader-bound snapshot can claim those bytes were parsed by that invocation, subject to trusted process and capture code. It cannot alone prove the process was installed from the expected artifact, or that the named host actually ran it.

If the eventual claim includes filesystem identity, specify and test per supported OS before implementation: trusted root and each parent, relative handle-based traversal without following unwanted links/reparse points, leaf opened once with appropriate no-follow semantics, type and ownership/permissions or effective-access checks on handles, reading and hashing from that same handle, and race detection/defined behavior under renames or replacement. Specify the platform's actual APIs, filesystem and mount assumptions, privileges, and what those checks cannot prove. POSIX descriptor techniques are not a Windows ACL/reparse-point proof; Windows requires its own handle, sharing, reparse and security-descriptor design and real host tests. Unsupported platform, filesystem, primitive or ambiguous race yields `unsupported`/unqualified, never a portable proof claim. Handle-based identity can describe the object read even if a path changes, but does not by itself prove a stable path throughout service life.

## Acceptance and verification after design review

- Trace the real entrypoint and all configuration/policy loaders; confirm capture and service consume the same snapshot, including defaults, node selection, role override and any reload. A substituted loader, different process, missing input, unobserved reload, stale generation, or mismatch between capture and installed verifier fails qualification.
- Exercise bounded reads and replacement before, during and after capture; symlink/parent replacement and unsupported platform cases must either preserve a truthful handle-bound claim or explicitly refuse the requested filesystem proof. No later path read may change the captured values.
- Exercise malformed and duplicate YAML, invalid UTF-8, oversize input, OS mismatch, invalid override, missing/unreadable profile, no matching node, downgrade, equal role and ignored promotion. Assert successful fallbacks, classified refusals, and existing fail-closed behavior separately.
- Change environment values before and after capture, mutate all returned and input objects, restart and reload. Each generation reflects only values consumed in its own operation; prior evidence remains immutable, and no stale capture represents the new process.
- Put recognizable secrets in every possible raw input, diagnostics, paths, account names, endpoint, policy and environment. Inspect the new capture/publication pipeline's public bytes, errors and logs for raw values, low-entropy hashes and arbitrary fields; reject unknown keys and schema versions. Existing profile CLI diagnostics are a separate surface and must not be forwarded into evidence. Verify deterministic canonical public encoding and fingerprint without treating it as private identity.
- Mismatch consumer wheel/provenance, producer or Phylax pin, interpreter/import origin, policy revision, service identity and generation linkage individually; each yields an explicit failed or incomplete qualification. Verify no secret is included in private evidence by default and access/retention match the chosen host's controls.
- Run supported platform-specific tests on the actual OS/filesystem, then collect installed evidence outside the checkout as the actual service identity, with `ORAMA_GRANT_SERVING` unset. Review complete evidence and independent R4/R6 requirements separately. Test results or a public projection alone do not close R5.

## Unresolved deployment and review decisions

The operator must identify the host/OS/filesystem, service manager and actual service identity; exact installed artifact set and source/pin expectations; service entrypoint and complete configuration/policy loader chain; policy inputs and secret classification; public-state topology; publication/transport owner; private storage, integrity, key management and retention; reload lifecycle and process-to-verifier binding; and whether filesystem identity is required. Choose supported platform proof and its failure behavior, capture failure's effect on startup, exact public release approval and any authenticated binding format during design review. These are not inferred here. Review this design before implementation; preserve existing production pins and accepted generation bytes, keep live effects disabled, and leave R5 open pending actual deployment evidence.

## Initial software subset after same-session design review

`orama.deploy.identity.load_with_identity` snapshots the three relevant profile environment
inputs and invokes the existing loader once. Its frozen `projection` observes safe topology
fields at the instant loading returns; it does not bind future service consumption. The returned
`effective` object preserves the existing mutable API: later mutation can change operational
configuration and requires a separate new observation/binding. Serialize only `projection`;
the enclosing result's `effective` field is private and may contain identifying configuration.

This subset adds no collector, public endpoint, private evidence assembler, canonical wire
parser, signature, startup integration, policy capture, filesystem proof or R5 completion.
The dataclass is an in-process observation, not a validator for caller-supplied evidence.
Existing loader exceptions become the generic `load-refused` without their messages.
The larger capture/consumption, schema-ingestion and host-binding requirements above remain
design work. Same-session Terra review is not independent R6 evidence.
