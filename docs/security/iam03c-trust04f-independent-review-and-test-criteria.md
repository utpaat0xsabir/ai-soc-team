# TRUST-04F independent review and corrective TEST acceptance

2026-11-16. TRUST-04F documentation-only review. Existing frozen proposals are unchanged; no implementation or independent cryptographic sign-off is claimed. All D04F decisions are PROPOSED — NOT APPROVED.

## Independent reviewer and required artifacts

Review must be performed by a named cryptographic engineer/researcher competent in
Ed25519 encodings, cofactor/subgroups, scalar malleability, implementation/FFI review
and adversarial vector semantics. Reviewer must not author the proposed correction
or its sole oracle; disclose employment, financial and implementation dependencies.
Separate reviewer verifies golden derivation and source provenance. The project owner
accepts the named reviewers and scope; this document nominates no person and claims
no independent sign-off. Codex analysis/self-review is not independent crypto review.

Required signed/datable review artifacts (not keys/signatures generated here):
exact reviewed document/source/dependency revisions, conflicts disclosure, requirement
matrix F-A01–F-E03, predicate-to-API map, equation/equivalence argument, A/R asymmetry,
feature/build/backend assumptions, parsing/diagnostic/call-order map, attack classes,
unresolved findings with severity, and approve/reject/revise verdict for TEST scope.
A subsequent review must inspect actual code and environment, not only this design.
Owner acceptance and independent technical review are distinct records. Any source,
backend or acceptance change invalidates the relevant sign-off pending re-review.

## Future tests — proposal only

| Group | Exact acceptance objective | PASS | FAIL / REVIEW_REQUIRED |
| --- | --- | --- | --- |
| P-A | 31/32/33-byte inputs; undecodable/noncanonical y/sign; identity, all pure torsion and mixed-order classes; independently admissible pins | Strict boundary rejects forbidden classes, accepts admissible A only with separate enrollment | Any forbidden acceptance FAIL; unreviewed class/oracle REVIEW_REQUIRED |
| P-R | Exact first signature half; canonical/decompression/H; torsion/mixed order; equation-valid R=O fixture | Reject forbidden points; identity alone never rejects otherwise-valid fixture | Blanket R-identity rejection FAIL; absent independent R=O positive REVIEW_REQUIRED |
| P-S | Exact second half LE, 0/1/L-1/L/L+1, high bits, S+nL, signature length/aliases | Range precheck matches interval; equation decides in-range cases | Reduction/clamping/out-of-range acceptance FAIL; missing independent valid edge asset REVIEW_REQUIRED |
| P-E | Pure exact M, E1 reference/E8 equivalence, equation-invalid subgroup inputs, wrong message/key/frame, ph/ctx | Full frozen acceptance, no fallback or hidden normalization | Undocumented equation/mode REVIEW_REQUIRED; unexpected accept/reject FAIL |
| P-152 | Exact retained tcId/key/message/signature through old backend and proposed full boundary | Record native acceptable and historical ACCEPT; authorized reproduction; corrected strict result REJECT/no vote | Changed original inputs/verdict or corrected acceptance FAIL |
| P-RFC | Three acquired RFC known-answer vectors and selected independent positives | Original exact public input accepted; keep raw algorithm vectors separate from project frames | Any unexpected rejection FAIL |
| P-CORPUS | All 210 source IDs; original native labels, raw backend behavior, strict result and reason separately | Every applicable frozen expectation satisfied after independent classification | Blind acceptable acceptance FAIL; semantics/oracle disagreement REVIEW_REQUIRED |
| P-POLICY | Invalid source/anchor, unknown/revoked/wrong key, duplicates, insufficient quorum, invalid third, bindings and permutations | Earliest frozen code, no partial evidence, fixed source/crypto counts | Miscount, fallback, provider/synthetic promotion or precedence drift FAIL |
| P-GOLDEN | All 26 literal project cases, independent bytes/preimages/digests/TEST signatures | Two independently reviewed derivations agree; pinned assets/review outside verifier | UUT-only oracle FAIL; any missing literal/review NOT_READY |

S=0 and S=L-1 are in-range, not necessarily valid signatures for a selected R/A/M.
Do not require acceptance merely because a scalar is in range. R=O positive must be
equation-valid under a permitted A, sourced or independently derived in a later
explicit TEST signing milestone; no fabricated oracle. Require both forbidden
acceptance and over-rejection tests. Differential agreement alone is not a standard
or independent proof; investigate disagreements against frozen predicates.

### Corpus inventory and resumption gates

Recorded evidence remains 3 RFC passes, 152 corpus cases (88 valid accept, 63 invalid
reject, one acceptable accept). Full source totals: 117 valid, 64 invalid, 29 acceptable.
Remaining IDs: 153–159 seven acceptable SmallOrderPublicKey; 160–180 twenty-one
acceptable MixedOrderPublicKey; 181–209 twenty-nine valid; 210 one invalid mixed-order.
All 58 are NOT_RUN. Use exact raw bytes; no normalization or native-verdict rewrite.
Each forbidden A case must reject regardless of acceptable. Review R/S admissibility
of nominally valid vectors; a source label is not full project conformance proof.
The [04E per-case inventory](iam03c-trust04e-corrective-test-and-vector-plan.md)
lists every remaining ID and exact gap. No new coverage is asserted.

Before execution: independent design/source review and explicit D04F-06 scope.
First reproduce/resolve case 152, prove full predicate coverage and preserve RFC
positives. A complete-corpus discrepancy-collection run needs explicit permission
rather than assuming prior stop-on-first-failure rules are waived. Any confirmed
profile incompatibility blocks acceptance even if collection is separately allowed.
Only after strict compatibility and owner permission may independent project signing
and golden derivation resume. TEST compatibility approval does not grant TRUST-05.

### All project cases — inventory and readiness

Existing expected outcomes remain those of the frozen matrix. Status is NOT_READY
for every complete case; RFC or partial corpus results are component evidence only.
Each future case needs exact inputs, result/code, side-effect counters, independent
oracle, review and pinned revision. No tests execute under this document.

| Case | Objective | Existing coverage | Future acceptance | Readiness |
| --- | --- | --- | --- | --- |
| V04-01 | RFC 8032 positive message/key/signatures | RFC3 pass; frame not run | Exact published algorithm success, separate from project frame acceptance | NOT_READY |
| V04-02 | Frozen canonical body, key-set, manifest and full frame | Specification only; no completed golden validation | Exact independently pinned bytes, byte counts and all five digest boundaries; no self-reference | NOT_READY |
| V04-03 | Two distinct eligible TEST customer signatures | Specification only; no completed golden validation | SignatureEvidence with exactly two sorted signer pairs, non-operational fixed status; one source read/two crypto checks | NOT_READY |
| V04-04 | Three valid entries, all six input permutations | Specification only; no completed golden validation | Same frame digest and three sorted pairs; three crypto checks; no third ignored | NOT_READY |
| V04-05 | Zero/one otherwise eligible signature | Specification only; no completed golden validation | QUORUM_INSUFFICIENT, zero crypto; one-unknown or revoked variants follow earlier codes | NOT_READY |
| V04-06 | Flip one bit of otherwise well-shaped signature | Specification only; no completed golden validation | SIGNATURE_INVALID, zero evidence; fixed sorted check order | NOT_READY |
| V04-07 | Duplicate custodian/key entries; manifest duplicate key/material; source duplicate map | Specification only; no completed golden validation | Candidate SIGNER_DUPLICATE before lookup; malformed independent source ANCHOR_UNAVAILABLE after one attempted read | NOT_READY |
| V04-08 | Well-typed wrong tenant in expected versus proof; nested payload/manifest mismatch | Specification only; no completed golden validation | BINDING_MISMATCH, zero lookup/crypto; no foreign IDs in diagnostic | NOT_READY |
| V04-09 | Wrong deployment UUID/kind/customer/domain with otherwise valid bytes | Specification only; no completed golden validation | BINDING_MISMATCH; same identifiers do not erase enterprise/SaaS boundary | NOT_READY |
| V04-10 | Wrong environment UUID; environment_kind=PRODUCTION | Specification only; no completed golden validation | UUID mismatch BINDING_MISMATCH; otherwise valid PRODUCTION input DOMAIN_MISMATCH, no production lookup | NOT_READY |
| V04-11 | Ed25519ph/ctx/P-256 or mixed signature profiles | Specification only; no completed golden validation | ALGORITHM_UNSUPPORTED after earlier shape/domain/canonical checks; no fallback | NOT_READY |
| V04-12 | Whitespace, escaped alias, unsorted object/set, time/UUID spelling alias; bool/float/exponent counter | Specification only; no completed golden validation | CANONICAL_MISMATCH for typed aliases; STRUCTURE_INVALID for bad primitive type; duplicate keys STRUCTURE_INVALID | NOT_READY |
| V04-13 | Unknown field in body/manifest/context/signature, including trusted flag or key URL | Specification only; no completed golden validation | STRUCTURE_INVALID before lookup, no ignored extension | NOT_READY |
| V04-14 | Wrong computed root-set/manifest/payload digest, internally consistent outer claims | Specification only; no completed golden validation | CANONICAL_MISMATCH; separately coherent different pinned manifest/set POLICY_STALE | NOT_READY |
| V04-15 | Two valid plus invalid third signature | Specification only; no completed golden validation | SIGNATURE_INVALID, no partial evidence; include each failing sorted position | NOT_READY |
| V04-16 | Unknown custodian/key pair, wrong key signature under known pair | Specification only; no completed golden validation | SIGNER_UNKNOWN before crypto; known pair with signature from other key SIGNATURE_INVALID | NOT_READY |
| V04-17 | Revoked root/key, expired source/body/key, or future test_time | Specification only; no completed golden validation | KEY_REVOKED before TIME_INVALID/threshold; no history-to-current claim | NOT_READY |
| V04-18 | Missing, self-selected, corrupt or non-TEST anchor source/pin | Specification only; no completed golden validation | ANCHOR_UNAVAILABLE; missing authenticated production source never synthesized | NOT_READY |
| V04-19 | Older/newer policy/version/generation, wrong independent pin reference | Specification only; no completed golden validation | POLICY_STALE; neither old nor unapproved next can self-activate | NOT_READY |
| V04-20 | Synthetic IAM provenance or production request classification | Specification only; no completed golden validation | SYNTHETIC_SOURCE; protected fixture channel distinction, zero operational imports | NOT_READY |
| V04-21 | Malformed/noncanonical point/scalar, torsion/mixed-order keys, scalar >= L, corpus edge vectors | Partial corpus; tcId152 incompatible; strict suite incomplete | Frozen strict acceptance; no library-specific permissive success. Length/hex shape STRUCTURE_INVALID; mathematical invalidity SIGNATURE_INVALID; unusable fixture pin blocks registration | NOT_READY |
| V04-22 | Wrong label/NUL/length/purpose/trailing bytes; future purpose | Specification only; no completed golden validation | DOMAIN_MISMATCH once bounded readable; cap+1 declared length LIMIT_EXCEEDED | NOT_READY |
| V04-23 | Body/payload/frame/combined/depth/entry limit cap and cap+1 | Specification only; no completed golden validation | At cap proceed to ordinary validation, not necessarily success; cap+1 LIMIT_EXCEEDED before expensive work, per budget definition | NOT_READY |
| V04-24 | Multi-fault fixtures from section 2 and permutations | Specification only; no completed golden validation | Exact earliest code, source-read/crypto-call counters; no raw input or inventory | NOT_READY |
| V04-25 | SaaS provider-recovery custodian/delegation or platform key as signer | Specification only; no completed golden validation | Unsupported domain -> DOMAIN_MISMATCH; ordinary unknown platform signer -> SIGNER_UNKNOWN; no provider authority | NOT_READY |
| V04-26 | Erroring backend/source or mutated result object/caller success flag | Specification only; no completed golden validation | Fixed rejection; no exception text, no returned partial evidence, immutable TEST output and no IAM consumer | NOT_READY |

## Proposed isolated TEST scope and evidence gates

A future owner grant must name paths, Python/runtime exception, exact reviewed application interfaces,
artifacts/dependency pins, optional official acquisition permission, offline network
isolation, allowed public/TEST signing material, fixture/output locations and limits.
No system/project venv modification, app imports, DB/services, production keys,
trust enrollment, policy changes, operational outputs or TRUST-05 implementation.
No tests or installations are approved here. Existing 04D approval does not authorize
new corrective files/dependencies or continuation under altered stop rules.

PASS for the complete TEST boundary requires all frozen predicates, reviewed code,
reproducible environment, reviewed independent oracles, full corpus disposition,
all 26 project cases, unchanged diagnostics and immutable non-authorizing evidence.
FAIL blocks G1 on any forbidden accept, valid-profile over-reject, fallback, wrong
binding/quorum or source mutation. REVIEW_REQUIRED keeps G1 blocked when policy
mapping, backend provenance, independent expected values or reviewer findings remain
unresolved. No majority-of-libraries or passing-test-count override is permitted.

Capture exact commands, versions/build/features, source identities, original and
strict results, exceptions sanitized to fixed diagnostics, counters and reviewer
assessment; original assets remain immutable. New hashes/signatures may only be
computed later under explicit TEST authorization. Recovery from a failed corrective
experiment is to stop and retain evidence; no edits to operational code or old fixtures.
