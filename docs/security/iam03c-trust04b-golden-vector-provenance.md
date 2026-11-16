# TRUST-04B independent golden-vector provenance readiness

2026-11-16. **GOLDEN VECTORS: NOT_READY. No cryptographic asset created.**
[Dependency](iam03c-trust04b-dependency-assessment.md),
[compatibility](iam03c-trust04b-ed25519-compatibility-matrix.md),
[G1/owner decisions](iam03c-trust04b-g1-evidence-and-owner-decisions.md).
Authoritative project requirements remain the unchanged
[26-case TRUST-04 matrix](iam03c-trust04-vector-and-error-matrix.md).

## 1. Current evidence and source register

The repository has structural fixtures and proposed vector recipes, not an approved
cryptographic golden bundle. Targeted inventory found no approved RFC 8032/Wycheproof
artifact manifest, independent project golden bytes/digests/signatures or reviewer
acceptance record. Existing 98 structural tests and prior selected regressions do
not establish these assets. No vector was fetched, generated or executed here.

| Ref | Source classification and required source/derivation | Present readiness / provenance |
| --- | --- | --- |
| RFC | PUBLISHED_ALGORITHM_VECTOR: [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1), exact published pure-Ed25519 message/key/signature cases | Source identified; exact local approved bytes/license/provenance not acquired. EXTERNAL_VERIFICATION_REQUIRED |
| ADV | PUBLISHED_ALGORITHM_VECTOR: [Wycheproof Ed25519 corpus](https://github.com/C2SP/wycheproof), exact reviewed release/commit/file/digest/license and acceptance labels | Corpus location candidate only; current contents/authenticity not fetched. EXTERNAL_VERIFICATION_REQUIRED; strict mapping UNVERIFIED |
| FRAME | INDEPENDENT_PROJECT_VECTOR: exact frozen TRUST-04 schemas and separately approved TEST key/context/pin fixtures, two independent reference derivations of full byte preimages/hash constants and independent project-frame signatures | Recipe specified; literals/signatures/review absent. DERIVATION_REQUIRED |
| PARSE | ADVERSARIAL_PARSING_VECTOR: deterministic byte/field/framing/limit mutations of an approved FRAME input, independently reviewed earliest code/counters | Recipe/result requirements specified; exact mutation assets/review absent. DERIVATION_REQUIRED |
| BIND | QUORUM_BINDING_FIXTURE: independently registered TEST context/source/key map, exact FRAME and immutable expected sorted signer outputs or staged rejections | No approved complete fixture/signature assets. DERIVATION_REQUIRED |
| NEG | NEGATIVE_SECURITY_VECTOR: independent fixed fault/multi-fault/provider/synthetic/lifecycle recipe against approved FRAME/source fixture | Expected diagnostic vocabulary specified, not independently reviewed exact assets. DERIVATION_REQUIRED |

No source link was accessed. A source name/hash supplied by a fixture author is
not proof of authenticity or independent review. Published algorithm vectors must
retain their original messages; an RFC signature cannot be relabelled as signing
the project's domain-separated frame. Different TEST key labels are not evidence
of three independently controlled real custodians.

## 2. Formats, reviewer roles and readiness notation

Required input formats:

- A: published exact raw public key, original message and 64-byte signature plus
  published vector identifier/classification. Optional published private seeds stay
  out of this report and verifier; future reference signing needs separate approval.
- F: exact canonical transport/frame/body/inner-policy bytes and manifest/key-set
  preimages, separate immutable ExpectedTestContext/TestAnchorSnapshot, signature
  entries and full provenance. Never build F expectations with the verifier under test.
- M(F): exact deterministic byte/field/source mutation of a pinned F fixture; record
  the preimage, changed bytes/fields and intended earlier-stage failures.

Required output formats:

- A-result: published algorithm VALID/INVALID plus explicit reconciliation of
  ambiguous corpus labels. These are test assertions, not new verifier/IAM outcomes.
- E: exact frozen TEST SignatureEvidence, digest/context/pin/sorted-signer fields
  and independently expected source-read/crypto-call counts.
- R(code): SignatureRejection with the exact frozen code and separate test-only
  call-count/absence-of-evidence assertions; no new wire fields or raw errors.
- B: full literal expected byte sequences and SHA-256 values for all preimages,
  lengths and frame/payload/key-set/manifest bindings, independently reviewed.

Reviewer roles are unassigned requirements, not claimed approvals: RA = independent
cryptographic vector/profile reviewer; RP = independent reference-byte/hash reviewer;
RS = independent parsing/stage/security reviewer. At least one named reviewer must
be independent of the asset producer and implementation under test; project crypto
assets need both byte and cryptographic review. Owner assigns actual reviewers later.

Every row below is **NOT_READY**. Published expected values exist in their external
sources but are not locally acquired/approved. For project/negative cases, a result
requirement exists in TRUST-04, while exact input/output literals/digests/signatures
and independent review are absent. Provenance is specifiable but **not verified**;
absence of local assets is an unmet prerequisite, not permission for synthetic success.

## 3. All 26 cases — exact provenance/readiness inventory

Class names are the requested five categories; source refs/formats/roles above are
part of each row's definition. “Spec only” means no approved literal golden asset.

| Vector ID | Security objective | Classification | Source / derivation | Expected input | Expected output | Reviewer | Values / provenance / readiness |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V04-01 | Pure Ed25519 known answers | PUBLISHED_ALGORITHM_VECTOR | RFC original cases, separate from project frames | A | A-result matching exact published bytes | RA | Published externally, local absent; unverified; NOT_READY |
| V04-02 | Exact canonical/frame/digest meaning | INDEPENDENT_PROJECT_VECTOR | FRAME independent encoders and separate hash tool | F plus all preimages | B, all exact lengths/digests | RP+RA | Spec only; derivation/review missing; NOT_READY |
| V04-03 | Two valid eligible votes | QUORUM_BINDING_FIXTURE | BIND and independently checked project signatures | F, two entries | E, two sorted pairs, one source/two crypto calls | RA+RP | Spec only; signatures/pins unapproved; NOT_READY |
| V04-04 | Three votes/order independence | QUORUM_BINDING_FIXTURE | BIND with three independent signatures and six permutations | F variants | E, same frame, three sorted pairs/three checks | RA+RS | Spec only; assets/review missing; NOT_READY |
| V04-05 | No quorum downgrade | QUORUM_BINDING_FIXTURE | BIND zero/one eligible vote | M(F) | R(QUORUM_INSUFFICIENT), zero math | RS | Code specified; exact fixture/review missing; NOT_READY |
| V04-06 | Invalid signature fails | NEGATIVE_SECURITY_VECTOR | NEG fixed well-shaped mutation, independently checked | M(F) | R(SIGNATURE_INVALID), no partial E | RA | Code specified; mutation/verdict missing; NOT_READY |
| V04-07 | Duplicate identity/material cannot vote twice | QUORUM_BINDING_FIXTURE | BIND duplicates and independent bad-source-map variant | M(F/source) | R(SIGNER_DUPLICATE); bad source R(ANCHOR_UNAVAILABLE) | RS+RA | Spec only; assets/review missing; NOT_READY |
| V04-08 | Tenant isolation | QUORUM_BINDING_FIXTURE | BIND independent expected tenant versus nested claim | M(F/context) | R(BINDING_MISMATCH), no source/crypto | RS | Code specified; exact assets/review missing; NOT_READY |
| V04-09 | Deployment/domain/customer isolation | QUORUM_BINDING_FIXTURE | BIND deployment-kind/UUID/customer/domain mutations | M(F/context) | R(BINDING_MISMATCH) | RS | Code specified; exact assets/review missing; NOT_READY |
| V04-10 | Environment isolation | QUORUM_BINDING_FIXTURE | BIND wrong environment UUID and separate PRODUCTION-kind case | M(F/context) | R(BINDING_MISMATCH) or R(DOMAIN_MISMATCH), per recipe | RS | Codes specified; exact assets/review missing; NOT_READY |
| V04-11 | No algorithm negotiation | NEGATIVE_SECURITY_VECTOR | NEG declared ph/ctx/P-256/mixed profile | M(F) | R(ALGORITHM_UNSUPPORTED), no math/fallback | RA+RS | Code specified; exact assets/review missing; NOT_READY |
| V04-12 | Canonical/primitive ambiguity rejection | ADVERSARIAL_PARSING_VECTOR | PARSE aliases, numeric/time/UUID variants, decoded duplicates | M(F) | R(CANONICAL_MISMATCH) or R(STRUCTURE_INVALID), frozen earliest stage | RP+RS | Codes specified; exact bytes/review missing; NOT_READY |
| V04-13 | Closed signed/unsigned schemas | ADVERSARIAL_PARSING_VECTOR | PARSE extra fields/URL/trusted flag | M(F) | R(STRUCTURE_INVALID) before source | RS | Code specified; exact bytes/review missing; NOT_READY |
| V04-14 | Derived digests versus independent pins | INDEPENDENT_PROJECT_VECTOR | FRAME independently computed preimages, then controlled wrong-derived/coherent-wrong-pin variants | F/M(F/source) | B plus R(CANONICAL_MISMATCH) or R(POLICY_STALE) | RP+RA | Hash constants/literals absent; unverified; NOT_READY |
| V04-15 | Invalid third vote defeats two valid | NEGATIVE_SECURITY_VECTOR | NEG approved two valid plus invalid third in every sorted position | M(F) | R(SIGNATURE_INVALID), never partial E | RA+RS | Signatures/mutations absent; unverified; NOT_READY |
| V04-16 | No alternate key search | NEGATIVE_SECURITY_VECTOR | NEG unknown pair and known-pair/wrong-key signature | M(F/source) | R(SIGNER_UNKNOWN) or R(SIGNATURE_INVALID) | RA+RS | Exact assets/verdicts absent; NOT_READY |
| V04-17 | TEST lifecycle/time constraints | NEGATIVE_SECURITY_VECTOR | NEG revoked root/key and explicit interval/source cases | M(F/source/context) | R(KEY_REVOKED) before time/quorum; R(TIME_INVALID) otherwise | RS | Code/window spec only; review absent; NOT_READY |
| V04-18 | No self-selected trust bootstrap | NEGATIVE_SECURITY_VECTOR | NEG missing/corrupt/self-selected/non-TEST source | M(F/source) | R(ANCHOR_UNAVAILABLE), no E | RS | Source assumptions specified, assets/review absent; NOT_READY |
| V04-19 | Reject stale/unapproved policy | NEGATIVE_SECURITY_VECTOR | NEG old/new policy/generation/pin variants | M(F/source) | R(POLICY_STALE) | RS+RP | Spec only; exact consistent variants absent; NOT_READY |
| V04-20 | No synthetic/production promotion | NEGATIVE_SECURITY_VECTOR | NEG protected input-class variants, not operational imports | F with independent context variant | R(SYNTHETIC_SOURCE), zero math/source | RS | Code specified; exact fixture/review absent; NOT_READY |
| V04-21 | Strict point/scalar acceptance | PUBLISHED_ALGORITHM_VECTOR | ADV plus independently checked fixture-key registration cases | A and selected F adaptations | A-result mapped to strict profile; malformed shape R(STRUCTURE_INVALID), math R(SIGNATURE_INVALID) | RA | Corpus exists externally, local absent; strict verdicts unverified; NOT_READY |
| V04-22 | Exact domain/frame boundaries | ADVERSARIAL_PARSING_VECTOR | PARSE label/NUL/length/trailing/future-purpose mutations | M(F) | R(DOMAIN_MISMATCH), cap exceptions per frozen stage | RP+RS | Recipes only; exact bytes/review absent; NOT_READY |
| V04-23 | Bounded parsing/work | ADVERSARIAL_PARSING_VECTOR | PARSE independently counted cap/cap+1 raw/decoded/depth/entry cases | M(F/source/context) with exact lengths | R(LIMIT_EXCEEDED) at cap+1; at cap proceed to normal validation | RP+RS | Counts required; actual assets/review absent; NOT_READY |
| V04-24 | Stable multi-fault precedence | NEGATIVE_SECURITY_VECTOR | NEG frozen multi-fault/permutation recipes | M(F) | Exact earliest R(code)/source and crypto counters | RS | Stage table specified; exact fixtures/review absent; NOT_READY |
| V04-25 | No SaaS-provider customer authority | QUORUM_BINDING_FIXTURE | BIND provider-recovery and unknown-platform signer variants | M(F/source) | R(DOMAIN_MISMATCH) or R(SIGNER_UNKNOWN), no provider vote | RS+RA | Spec only; exact fixtures/review absent; NOT_READY |
| V04-26 | Fail closed/no forged evidence | NEGATIVE_SECURITY_VECTOR | NEG backend/source faults and immutable TEST output checks | Approved F and controlled harness faults | Fixed R(code), no raw errors/partial E or operational consumer | RS+RA | Contracts specified; fault assets/review absent; NOT_READY |

## 4. Golden asset acceptance criteria

An accepted asset needs all ten items; none is waived by being publicly available:

1. Stable vector/suite ID and TEST-only classification.
2. Original source, exact revision/commit/release/file and license/authenticity record,
   or an independently reviewed project derivation record.
3. Complete exact input bytes and independent context/pin/source fixtures, not just
   a JSON sketch or a successful sample assertion.
4. Exact expected byte/digest/result/counter literals and mutation preimages; code
   requirements alone do not constitute golden outputs.
5. Explicit pure algorithm/profile and distinction between original algorithm
   messages and project domain-separated frames.
6. Accepted protocol/canonicalization/wire-document content revisions, lossless
   integers, complete body/key-set/manifest/frame preimage boundaries.
7. Producer/tool/version/provenance and independent named-review metadata; no
   self-declared reviewed=True or unverifiable fixture registration.
8. Independent byte reconstruction/hash/signature checks by separate reviewed
   tools/implementation and reviewer; no verifier-under-test-only expected values.
9. Isolation from production roots/keys/customers; no private seeds in reports or
   pure verifier, no fixture-to-production conversion.
10. Reproducible later validation instructions with exact artifact hashes/dependencies,
    permitted offline scope, expected verdicts and failure/stop behavior.

Obtain/review source artifacts only after explicit acquisition authorization. Freeze
human-reviewed project inputs first; independent reference encoders reconstruct
literal bytes, a separate standard hash tool derives expected SHA-256 values and
an independently reviewed signer/verifier supplies/checks project signatures only
under separate test-material authorization. Do not compute expectations at test
runtime using the implementation being tested. Pin literal accepted outputs and
review every change rather than regenerate to force a pass.

Preserve exact published byte values in future accepted fixtures. Do not copy an
RFC signature onto a project frame, conflate arbitrary distinct IDs with independent
custody, or treat ambiguous adversarial flags as strict-profile acceptance. If exact
project signatures are unavailable, positive quorum verification remains blocked.
No current asset is approved and no new key/signature/hash golden was created here.

Cap fixtures must not add a new padding field or relax narrower field constraints.
Some maximal resource sizes cannot be semantically valid ROOT_POLICY objects; at
cap a later ordinary rejection is acceptable, while cap+1 must fail the specified
observable guard. Preserve all raw/decoded budget definitions and error order.

**All 26 case provenance records: SPECIFIED, NOT VERIFIED**  
**Golden cryptographic assets: NOT_CREATED / NOT_APPROVED**  
**GOLDEN VECTORS: NOT_READY**
