# Local workspace proof of concept

- [x] Inspect architecture PR heads and owner boundaries.
- [x] Write product plan including both prior recommendations.
- [x] Implement offline artifact, privacy contract, and independent verifier.
- [x] Verify contracts, negative cases, and run instructions (API-only slice).
- [ ] Browser workspace UI (not shipped; the slice exposes JSON endpoints only).

## Follow-up: Release 1–2 R3 synthesis

1. [x] Reconcile bundle patches, historical candidate branches, and the live
   merged Oramasys/Phylax mains with a path-level three-way matrix.
2. [x] Preserve only behavior that is absent from live main and safe under the
   frozen, dark-by-default authority contract.
3. [x] Add the retained-authority regression first, then implement the smallest
   atomic persistence and read-only recovery surface that satisfies it.
4. [x] Run the focused dispatch, composition, revocation, and lifecycle suites.
   Host-bound qualification remains explicitly delegated in the handoff.
5. [ ] Commit the harmonized delta, push once, and open one draft Oramasys PR.
   No Phylax delta remains after the three-way synthesis.
