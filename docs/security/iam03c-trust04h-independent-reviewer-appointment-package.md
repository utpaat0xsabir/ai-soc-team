# TRUST-04H independent reviewer appointment package

2026-11-16. TRUST-04H documentation-only proposal. No code, crypto execution, new dependency, trust enrollment, reviewer appointment or approval. All owner decisions remain PROPOSED — NOT APPROVED.

## Appointment specification — owner action required

**INDEPENDENT REVIEWER: NOT_APPOINTED.** No identity, CV, contract, external findings
or authentic sign-off was supplied. The owner must appoint/contract a named reviewer;
preparing this packet does not authorize contacting anyone. Codex source research
and self-review are not independent cryptographic review.

Require demonstrated work in Ed25519/ECC verification, canonical encodings,
subgroup/cofactor semantics and source implementation security; owner checks relevant
public work/references and review competence. Reviewer must not author the proposed
prototype or its sole expected-value oracle. Disclose financial/employment/library
maintenance relationships and other conflicts; conflicted input may inform but not
serve as the sole independent verdict. The reviewer gets exact source/spec/evidence,
may reject freely, and records written findings, reproducible references, scope and
limitations. Separate independent golden review must not merely repeat the UUT.

Appointment record to be supplied by owner, not populated here: reviewer identity and
qualifications verified by owner, conflicts and independence statement, agreed exact
scope/revisions, access to complete packet, deliverables/timeframe, explicit review
outcome, conditions and owner receipt. Use public/non-secret materials; no credentials,
customer keys or production access are needed. Unknown credentials remain unknown.

## Review packet index

| Packet item | Exact repository source / review task |
| --- | --- |
| Frozen A/R/S and pure profile | [anchor section4](iam03c-trust04-anchor-and-verifier-contract.md), [04F requirements F-A01–F-E03](iam03c-trust04f-strict-ed25519-normative-profile.md) |
| Frame/body/canonical/pins/quorum | [wire](iam03c-trust04-root-policy-wire-spec.md), anchor sections2–6; distinguish structural bytes from crypto validity |
| Confirmed discrepancy | [04E reconstruction](iam03c-trust04e-case152-evidence-reconstruction.md), source152 exact bytes and native acceptable |
| Actual run/versions/source inputs | [04D results](../../tests/iam/fixtures/trust04d_offline_validation/results.json), [harness read-only](../../tests/iam/fixtures/trust04d_offline_validation/compatibility.py), [runtime](iam03c-trust04d-runtime-and-dependency-evidence.md), [original manifest](../../tests/iam/fixtures/trust04c_public_vectors/manifest.json) |
| Root-cause boundary | [04E boundary review](iam03c-trust04e-strict-ed25519-verification-boundary.md); internal OpenSSL equation unresolved |
| Prior candidates/source evidence | [04G assessment](iam03c-trust04g-candidate-implementation-assessment.md), [source ledger](iam03c-trust04g-source-level-verification-evidence.md) |
| Exact proposed composition and R issue | [H-COMP-1](iam03c-trust04h-exact-verification-composition.md), [R/risk review](iam03c-trust04h-r-identity-and-backend-risk-review.md) |
| Independent oracle/test design | [04F tests](iam03c-trust04f-independent-review-and-test-criteria.md), [04G full review packet](iam03c-trust04g-independent-security-review-package.md) |
| Threat20 / cases26 / diagnostics15 | Inventory below, frozen matrix and original [TRUST-03 threats](iam03c-trust03-threat-model.md); do not rely on summaries alone |
| Decisions and missing approval | [04H owner package](iam03c-trust04h-owner-decisions-and-g1-status.md); all six proposed |

Reviewer can follow source URLs, inspect exact inputs and independently derive the
reasoning without trusting Codex conclusions. Reproduction using cryptography would
require separately authorized TEST scope; this appointment package grants none.

## Explicit reviewer questions and sign-off criteria

1. Do canonical decompression plus exact re-encoding and subgroup predicates enforce
   every frozen A/R requirement, including sign-bit/y aliases and identity distinction?
2. Does ordinary equation verification preserve exact A/R/S/M and accept a genuinely
   valid R=O case without accepting forbidden A or mixed-order points?
3. Are S bounds, zero handling, challenge reduction and E1 semantics exact under all
   resolved features? Are compatibility/prehash/batch paths excluded by construction?
4. Does E1/E8 equivalence rely only on proven frozen predicates? Could either chosen
   implementation impose extra exclusions or wrong transcript behavior?
5. Are tag/commit/artifact and runtime/backend/feature assumptions sufficiently
   authenticated, supported and reproducible? What review is missing below API calls?
6. Are input copies, failures, source provenance, prior-stage codes/counters, every
   supplied signature and threshold precheck safe without changing frozen priorities?
7. Are valid and invalid edges, all210 original verdicts, RFC3 and all26 project cases
   covered with independent expected values? What precise evidence would close gaps?
8. Does the boundary stay TEST-only and non-authorizing, with no provider/custodian
   self-trust, operational IAM consumer or unsupported recovery authority?

Require a dated written report tied to exact document and source revisions, artifact/
feature graph when available, conflicts statement, reasoning/proof assumptions,
severity-ranked findings, evidence/reproduction references, limitations, conditions
and explicit verdict. Later actual prototype code/build/test results need another
review; design sign-off is not binary conformance or production approval. Reviewer
cannot grant owner execution scope or waive frozen requirements by a favorable label.

| Permitted reviewer outcome | Meaning only if genuine external evidence is supplied |
| --- | --- |
| APPROVED_FOR_TEST_PROTOTYPE | Design sufficiently justified for narrow prototype; owner still must authorize exact work |
| APPROVED_WITH_CONDITIONS | Conditions must close and be verified before implementation; not a provisional permission |
| REJECTED | Composition unsuitable; record reasons, retain NO-GO, no fallback |
| MORE_EVIDENCE_REQUIRED | Suitability cannot be established; missing evidence remains blocking |

**Actual reviewer outcome: NONE RECORDED. INDEPENDENT SIGN-OFF: PENDING.**
No reviewer name, approval or external report is invented.

## Threat coverage — original model unchanged

C=historical confirmed152; H=hypothetical conditional attack; O=outside this boundary.

| Threat | Review focus / evidence | Residual or required case |
| --- | --- | --- |
| T03-01 forgery | C identity-A admitted; review full predicate+equation | V04-21; backend/host compromise |
| T03-02 one stolen key | H forbidden second anchor undermines votes | V04-03/17; custody external |
| T03-03 two colluding custodians | O no cryptographic honest-intent test | V04-03/26; independent custody |
| T03-04 duplicate voting | H aliases or repeated keys/IDs | V04-07; person independence not proven |
| T03-05 stale policy | O signature not current policy | V04-19; independent pin/high-water trust |
| T03-06 revoked key | O admissibility not eligibility | V04-17; propagation external |
| T03-07 cross-tenant replay | H context/pin substitution | V04-08; authenticated expected tenant |
| T03-08 cross-deployment replay | H wrong site/environment | V04-09/10/22; migration fencing outside |
| T03-09 algorithm confusion | H ordinary API called wrong mode/feature | V04-11/21; fixed pure/no fallback |
| T03-10 canonical mismatch | H aliases or rewritten hash input | V04-02/12/21; original-byte equality |
| T03-11 unknown fields | O primitive does not enforce envelope | V04-13; closed schema |
| T03-12 DB rollback | O ROOT_POLICY no latest-state proof | Future independent checkpoints; not solved |
| T03-13 checkpoint rollback | O unsupported CHECKPOINT purpose | Future current independent head/fork checks |
| T03-14 recovery tampering | O recovery excluded | V04-22; separate ceremony |
| T03-15 lost keys | O no recovery/threshold reduction | V04-05; availability loss |
| T03-16 malicious recovery | H forged root enrollment pressure | V04-18/22; display/customer process |
| T03-17 SaaS escalation | H provider source impersonates customer | V04-25; infra admin access remains |
| T03-18 verifier compromise | O local results can be fabricated | V04-26; artifact/build/host controls |
| T03-19 time manipulation | O crypto not trusted clock | V04-17; operational time separate |
| T03-20 revocation race | O signature not execution gate | Future freshness/serialization; no TOCTOU claim |

## All project cases and golden readiness

The frozen [matrix](iam03c-trust04-vector-and-error-matrix.md) is authoritative for
exact expected codes/counters. Every complete project case remains NOT_READY;
component-only execution evidence does not materialize a full project golden.

| Case | Required review objective | Existing evidence / missing evidence | Readiness |
| --- | --- | --- | --- |
| V04-01 | RFC 8032 positive message/key/signatures | RFC3 pass historical; project frame assets/review absent | NOT_READY |
| V04-02 | Frozen canonical body, key-set, manifest and full frame | Specified only; independent literal golden validation absent | NOT_READY |
| V04-03 | Two distinct eligible TEST customer signatures | Specified only; independent literal golden validation absent | NOT_READY |
| V04-04 | Three valid entries, all six input permutations | Specified only; independent literal golden validation absent | NOT_READY |
| V04-05 | Zero/one otherwise eligible signature | Specified only; independent literal golden validation absent | NOT_READY |
| V04-06 | Flip one bit of otherwise well-shaped signature | Specified only; independent literal golden validation absent | NOT_READY |
| V04-07 | Duplicate custodian/key entries; manifest duplicate key/material; source duplicate map | Specified only; independent literal golden validation absent | NOT_READY |
| V04-08 | Well-typed wrong tenant in expected versus proof; nested payload/manifest mismatch | Specified only; independent literal golden validation absent | NOT_READY |
| V04-09 | Wrong deployment UUID/kind/customer/domain with otherwise valid bytes | Specified only; independent literal golden validation absent | NOT_READY |
| V04-10 | Wrong environment UUID; environment_kind=PRODUCTION | Specified only; independent literal golden validation absent | NOT_READY |
| V04-11 | Ed25519ph/ctx/P-256 or mixed signature profiles | Specified only; independent literal golden validation absent | NOT_READY |
| V04-12 | Whitespace, escaped alias, unsorted object/set, time/UUID spelling alias; bool/float/exponent counter | Specified only; independent literal golden validation absent | NOT_READY |
| V04-13 | Unknown field in body/manifest/context/signature, including trusted flag or key URL | Specified only; independent literal golden validation absent | NOT_READY |
| V04-14 | Wrong computed root-set/manifest/payload digest, internally consistent outer claims | Specified only; independent literal golden validation absent | NOT_READY |
| V04-15 | Two valid plus invalid third signature | Specified only; independent literal golden validation absent | NOT_READY |
| V04-16 | Unknown custodian/key pair, wrong key signature under known pair | Specified only; independent literal golden validation absent | NOT_READY |
| V04-17 | Revoked root/key, expired source/body/key, or future test_time | Specified only; independent literal golden validation absent | NOT_READY |
| V04-18 | Missing, self-selected, corrupt or non-TEST anchor source/pin | Specified only; independent literal golden validation absent | NOT_READY |
| V04-19 | Older/newer policy/version/generation, wrong independent pin reference | Specified only; independent literal golden validation absent | NOT_READY |
| V04-20 | Synthetic IAM provenance or production request classification | Specified only; independent literal golden validation absent | NOT_READY |
| V04-21 | Malformed/noncanonical point/scalar, torsion/mixed-order keys, scalar >= L, corpus edge vectors | Partial152 cases; confirmed mismatch;58 unexecuted; full boundary absent | NOT_READY |
| V04-22 | Wrong label/NUL/length/purpose/trailing bytes; future purpose | Specified only; independent literal golden validation absent | NOT_READY |
| V04-23 | Body/payload/frame/combined/depth/entry limit cap and cap+1 | Specified only; independent literal golden validation absent | NOT_READY |
| V04-24 | Multi-fault fixtures from section 2 and permutations | Specified only; independent literal golden validation absent | NOT_READY |
| V04-25 | SaaS provider-recovery custodian/delegation or platform key as signer | Specified only; independent literal golden validation absent | NOT_READY |
| V04-26 | Erroring backend/source or mutated result object/caller success flag | Specified only; independent literal golden validation absent | NOT_READY |

## Original corpus and diagnostics

Original210 Wycheproof IDs and verdicts preserved. Historical152 executed:88 valid
accepted,63 invalid rejected,1 acceptable accepted. Remaining58 NOT_RUN:153–159 seven
acceptable small-order,160–180 twenty-one acceptable mixed-order,181–209 twenty-nine
valid,210 one invalid mixed-order. Source117valid/64invalid/29acceptable remains
unchanged. RFC8032-7.1-TEST-1/2/3 retain historical PASS, raw algorithm messages,
not project frames. Require future full210 results with native/backend/strict verdicts
separate. Acceptable does not override project A/R predicates.

| Order | Diagnostic | Reviewer obligation |
| --- | --- | --- |
| 00 | LIMIT_EXCEEDED | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 01 | SYNTHETIC_SOURCE | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 02 | STRUCTURE_INVALID | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 03 | BINDING_MISMATCH | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 04 | SIGNER_DUPLICATE | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 05 | CANONICAL_MISMATCH | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 06 | DOMAIN_MISMATCH | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 07 | ALGORITHM_UNSUPPORTED | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 08 | ANCHOR_UNAVAILABLE | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 09 | POLICY_STALE | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 10 | SIGNER_UNKNOWN | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 11 | KEY_REVOKED | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 12 | TIME_INVALID | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 13 | QUORUM_INSUFFICIENT | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |
| 14 | SIGNATURE_INVALID | Preserve exact frozen trigger/order and source/crypto counts; no later-stage override |

Require independent golden derivation outside the future verifier: exact policy/body/
frame/preimages/digests, separately reviewed TEST signatures, second method/reviewer,
source/runtime pins and literal expected outcomes. Different wrappers sharing one
crypto backend do not establish independent verification. Missing R=O positive or
any other literal/review remains NOT_READY, never auto-generated oracle success.
