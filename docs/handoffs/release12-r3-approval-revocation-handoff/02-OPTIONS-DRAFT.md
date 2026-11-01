# Draft: what verifies approvals in production

**Status: proposal.** Not ratified, not implemented, and it enables nothing. Choosing production
authority is the operator's decision. Reference IDs such as `S3` are in
[`01-REFERENCE-INDEX.md`](01-REFERENCE-INDEX.md).

## Recommendation

1. **Approval:** let the signed chain be the proof (option A). The human approves once, at grant
   issuance through P5. Serving then checks signatures with public keys and never holds a secret.
2. **Revocation:** combine local signed events with a Phylax read, and refuse when the data is not
   known to be current (the **Combined** option).
3. **Human evidence:** extend the GitHub device ceremony to effect grants for now. Passkey stays
   deferred.
4. **Scope:** keep R3 as tests with real ports. Do not reopen the Release 0 to 2 freeze just to make
   the `effects` bit live.

Option A has one real weakness: the human approves an operation, not a specific attempt. Decision
D1 below is the one that matters most.

## Findings that shape the options

Each finding was read in code or a document at the pinned commit. Re-verify before relying on it.

1. **Serving cannot use P5 receipts directly.** [`P5ApprovalAuthority`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/p5_approval.py#L523)
   needs a `signing_key` and checks receipts with [HMAC](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/p5_approval.py#L637),
   a shared secret. Consuming a receipt also writes to the store. E1 separation rule 1 (S2) says the
   serving process never loads signing material.
2. **The human decision already reaches a public-key signature.** [`EffectGrantAuthority.issue`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/effect_grant.py#L308)
   runs preview, approve and consume, then signs the grant. It only accepts the class
   `inert.simulation` with no second approval, which matches the T3 gate of one driver and one
   effect class (S4).
3. **Evidence at issuance is weaker than it looks.** The issuer passes `operator_evidence_ref`
   straight to P5. The lines read show no evidence verifier for effect grants. The model-launch path
   has one, and [its document](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/model-launch-approval.md) says an arbitrary reference
   string alone establishes nothing.
4. **The local revocation view can look clean because it is empty.** [`refusal_reason`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_revocations.py#L69)
   covers issuer, grant, approval chain and cascade, but only for events already recorded. A search
   of `src/orama` and `scripts` at the pinned commit found no caller of [`ingest_events`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_attempts.py#L933).
   With no feed, "nothing revoked" means "nothing heard". The final boundary also already calls this
   check, so a port that only repeats it adds no protection.
5. **The Phylax read can report old data as fresh.** [`revocation_freshness`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/verifier_surface.py#L271)
   stamps the time it read, not the time the issuer wrote. If serving reads a copy of issuer state,
   a fresh read of an old copy passes. R4 names separate issuer and public state, and ADR 71 (O3)
   wants "signed public state publication with a revocation-freshness proof" before Level 1.
6. **The Phylax read cannot satisfy the port alone.** [`RevocationObservation`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/adjustment_grant.py#L120)
   has one grant and one boolean. The [port contract](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/dispatch_attempts.py#L154)
   requires approval-chain and issuer coverage too (L1).
7. **The verify-only object has no revocation method.** The opened effect verifier exposes `verify`
   and `close` only. A revocation read needs [`open_verifier_surface`](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/verifier_surface.py#L318)
   or a new public method.
8. **There is a third missing port, and the freeze blocks it.** No sender is wired until the
   `effects` bit is effective, which needs [`OperatorSignatureVerifier`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/api/capabilities.py#L68).
   S3 says no signing path exists in Releases 0 to 2, and [Phylax refuses enablement too](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/src/phylax/capability_record.py#L165).
   Real approval and revocation ports therefore cannot produce a live sender in R0-2, by design.
9. **The chain is not finished.** [The composition boundary document (F10)](https://github.com/oramasys/phylax/blob/cf3a300c6d39092ab64df54f0d1ab3fea3db3c38/docs/trusted-composition-boundary.md) lists as unbuilt:
   authenticated `GrantFacts` from a signed dispatch grant, and the operator-authority adapters.
   Consumer key composition is owned by Oramasys.

## Approval options

The port takes only a `FinalBoundaryBinding`, so every option needs read access to stored attempt
facts. The attempt table holds permit and finalization **digests**. Whether the signed bodies are
kept is an open question below.

| Option | How it works | Fits verify-only | Human per attempt | New wire format | Verdict |
| --- | --- | --- | --- | --- | --- |
| **A. Signed chain** | Check grant, permit and finalization signatures with public keys; compare with the stored attempt | Yes | No: per operation, issuer binds the attempt | No | **Recommended** |
| **B. Attempt receipt** | After authorization, a human approves that attempt; a separate process signs with a public-key signature | Yes | Yes | Yes | Upgrade path |
| **C. Local authority call** | Serving asks a separate process that holds the P5 secret | Yes | Possible | Yes | Not recommended |
| **D. P5 in serving** | Serving holds the HMAC key and consumes receipts | **No**: breaks S2 rule 1, R2 and R4 | Yes | No | Ruled out |
| **E. GitHub check at send time** | Serving reads the approval comment | Yes | Possible | No | Ruled out as a verifier |
| **F. Bearer credential** | A valid operator token counts as approval | Yes | No | No | Ruled out by L2 and S1 |

**Why A.** It uses ratified, frozen wire formats, keeps secrets out of serving, and needs the least
new authority. Its gap: S4 asks for approval of "the concrete attempt identity", while a grant exists
before any attempt does. The attempt is bound by the issuer through the permit and finalization, not
by the human.

**Why B is the upgrade.** It meets S4 literally. Its cost is a new frozen wire format with a
ratification round, and the human has to approve after authorization, because the fencing epoch and
expiry only exist then. That wait must fit inside the reservation lifetime. Keep the receipt lifetime
separate from the authority lifetime (L4).

**Why not C.** It puts a signing process in the live send path. It would fail closed, but every send
would depend on it, and S5 keeps issuer calls out of the consumer's dispatch transaction.

**E is still useful as evidence.** The ceremony can feed `operator_evidence_ref` at issuance. It proves
the procedure, not an attested human (L5).

## Revocation options

| Option | How it works | Approval chain and issuer | Detects a stale view | Verdict |
| --- | --- | --- | --- | --- |
| **Events** (local + feed) | Build the feed; the port reads acknowledged events | Yes | Only if feed age is enforced | Not enough alone |
| **Read** (Phylax) | The port calls the read-only surface | **No** (finding 6) | **No** for a copy (finding 5) | Not enough alone |
| **Combined** | Return `True` if either says revoked; **raise** if the feed is stale or never ran | Yes | Yes | **Recommended** |

The port must raise, not return `False`, when it cannot vouch for currency.
[`authorize_final_boundary`](https://github.com/oramasys/oramasys/blob/40a6248fdf7ccc9f21fcfba9d8a2025c3281f53d/src/orama/graph/final_boundary.py#L168)
turns a raised error into a terminal refusal.

**Idea to verify first.** The finalization records the issuer counter `R_f`, and S5 says it orders
issuer revocation against dispatch. A revocation after finalization is "post-authorization" there.
So the unexpired finalization may already bound staleness at send time, which would shrink the
Combined option. This is unproven.

## Decisions for the operator

| ID | Decision | Recommended | Why it is yours |
| --- | --- | --- | --- |
| D1 | Is one human approval of an operation enough, with the issuer binding the attempt? | Yes for the single inert class; B before any real effect | Interprets S4 |
| D2 | Which human evidence? | GitHub device ceremony, with an effect-grant verifier added | Sets the trust level (L5). Passkey is deferred (S15) |
| D3 | How does serving get issuer state: a shared read, a copy, or signed publication? | Signed publication | ADR 71 gate, depends on the R4 deployment |
| D4 | Keep the R0-2 freeze, so real ports are qualified by tests only? | Yes | Changing it amends a frozen contract |

## Work plan for agents

**Without decisions:** only WP0. **After D1 to D4 are recorded:** the rest, in order.

| WP | Repo | Work | Depends on |
| --- | --- | --- | --- |
| WP0 | All | Re-verify every finding and answer the open questions; report only | None |
| WP1 | Phylax | Evidence verifier for effect grants, mirroring the model-launch one | D2 |
| WP2 | Phylax | Public read for revocation and, if chosen, signed publication | D3 |
| WP3 | Oramasys | Event feed calling `ingest_events`, with a recorded last-success time | D3 |
| WP4 | Oramasys | Revocation adapter (Combined) | WP2, WP3 |
| WP5 | Oramasys | Approval adapter (A), with Phylax kept out of `src/orama` | D1, WP1 |
| WP6 | Oramasys | Startup matrix for requirement R3, with real ports | WP4, WP5, D4 |
| WP7 | Independent reviewer | Review against the R6 scope (O1) by someone who wrote none of it | WP6 |

### Open questions for WP0

1. Are signed permit and finalization bodies stored, or only their digests? If only digests, what
   does option A re-verify at the boundary?
2. Does the inert effect path go through permits and finalizations at all, or does it reach the
   boundary another way? Option A depends on this.
3. Does `request_digest` in the grant equal `operation_digest` in the binding?
4. Is there any production client for permit requests, finalization and event catch-up?
5. With separate identities, does the private-state check force serving to read a copy?
6. Does `R_f` bound staleness as suggested above?

### Tests to write first

Each must fail before the code exists.

- Changed payload, principal, target, epoch or expiry refuses.
- Replay after restart refuses. A second dispatch for one attempt refuses.
- A feed that never ran refuses. A feed that stopped refuses.
- Revoked grant, approval chain, issuer and cascade each refuse.
- A stale copy of public state refuses.
- A verifier that raises, or returns a non-boolean, refuses.
- A rotated or unknown key refuses.
- A backward clock jump refuses (S1 section 5).
- Serving still cannot reach a seed, signer or P5 secret (R2).

## Risks

- **Same-user limits remain.** Until R4 is proven, another process under the same identity could read
  state (O4).
- **Option A is issuer-trusting.** A compromised issuer can sign a permit no human saw.
- **The verify-only test allowlist.** An unmerged patch pins each composition root to two Phylax
  names. Adding `open_verifier_surface` means changing that list on purpose, with review.
- **A green suite proves little.** Fixtures do not qualify a deployment (O1, L8).
