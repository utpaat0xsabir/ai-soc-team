# TRUST-04F strict Ed25519 normative-profile review

2026-11-16. TRUST-04F documentation-only review. Existing frozen proposals are unchanged; no implementation or independent cryptographic sign-off is claimed. All D04F decisions are PROPOSED — NOT APPROVED.

## Status and meaning of normative

This document extracts the proposed frozen ED25519-PURE-1 acceptance set; it does
not approve that profile for production. Normative here means required by the
existing candidate, not a new grant of authority. Primary frozen source F4 is
[anchor/verifier section 4](iam03c-trust04-anchor-and-verifier-contract.md), lines
120–157; F5 is its section 5, lines 164–198. W is the
[wire specification](iam03c-trust04-root-policy-wire-spec.md), sections 1–6.
E is the [ordered matrix](iam03c-trust04-vector-and-error-matrix.md), section 1.
[TRUST-04E reconstruction](iam03c-trust04e-case152-evidence-reconstruction.md)
confirms the library-only discrepancy without identifying OpenSSL's internal path.

## Exact mathematical acceptance predicates

Notation: E is edwards25519, O its identity, B its standard prime-order base point,
p=2^255-19, L=2^252+27742317777372353535851937790883648493, H=<B> of order L.
These formulas specify review requirements; no arithmetic is implemented/executed.

A must be exactly 32 bytes, canonically encode a decodable on-curve point, lie in H,
and differ from O. Membership can be specified mathematically as [L]A=O with A!=O;
checking only [8]A!=O excludes pure torsion but not mixed-order points. A need not
be trusted merely because these predicates hold: enrollment authenticates the exact
bytes, customer/custodian mapping and independently approved pin separately.

R is the first 32 bytes of the exact 64-byte signature, also canonical, decodable,
on-curve and in H. Unlike A, R may equal O if the equation and all other checks hold.
Other pure torsion and mixed-order R are forbidden. There is no frozen R!=O or S!=0
rule. Adding either would narrow the acceptance set and needs formal change review;
neither is recommended here. Identity R does not imply a malformed signature.

S is the second 32 bytes, interpreted unsigned little-endian with 0<=S<L. Fixed-width
binary permits leading high-order zero octets; JSON's shortest decimal rule does not
apply. Reject S>=L rather than reduce it, clamp it, mask it or accept S+nL. Comparing
an exact public integer against L is a deterministic non-curve precheck; the selected
backend must still verify the equation. No private scalar or signing operation occurs.

Canonical point decoding requires y<p, valid recovery of x and its sign, including
rejection of x=0 with sign bit one. Re-encoding must equal original bytes; reduction
of y modulo p or alias normalization into acceptance is forbidden. Decompression
alone is not a subgroup test. These are predicates for vetted APIs, not directions
to implement field arithmetic in application Python.

## Equation recommendation and proof obligation

Pure mode uses k=SHA-512(encoded R || encoded A || M), interpreted little-endian;
M is the exact frozen full frame, not its SHA-256 digest. Standard scalar reduction
of k modulo L is equivalent on H; reduction of input S is not permitted.

E1: [S]B = R + [k]A.

E8: [8][S]B = [8]R + [8][k]A.

RFC 8032 permits E8 and allows E1 as sufficient. The frozen phrase standard equation
leaves the internal form unspecified. Once A and R are proven in H, the difference
[S]B-R-[k]A also lies in H. Since gcd(8,L)=1, multiplication by 8 is injective on H;
therefore E1 and E8 have the same acceptance set under all frozen predicates.
This is an analytical inference for independent review, not measured backend proof.

Recommend E1 as the explicit reference equation (D04F-03). Permit a documented E8
backend only after independent review establishes the full predicate conjunction,
mode, exact-byte behavior and equivalence; never as a substitute for subgroup checks.
No existing backend is approved by this recommendation. Outside H, equations may
differ; those inputs already fail the frozen profile. No new valid signatures are
excluded by E1 under the frozen assumptions, including permitted R=O. Case 152
satisfies either equation conceptually, so it cannot reveal which OpenSSL used.

## Requirement traceability

Standards IDs S1–S7 are defined below. Existing evidence codes: C152 means confirmed
saved identity-A acceptance; RFC3 means three saved known-answer passes; U means
unverified for full acceptance. Proposed tests P-A/P-R/P-S/P-E are in the
[test criteria](iam03c-trust04f-independent-review-and-test-criteria.md).
No row treats a source/API statement as a passing implementation test.

| ID | Component | Exact requirement | Frozen source | Standards | Layer | Existing evidence | Test | Ambiguity | Owner decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F-A01 | A | Exactly raw 32 bytes, no alternate encoding | F4/W primitives | S1/S2 | Parser | C152 length valid; length matrix U | P-A length | No | D04F-01 reaffirm |
| F-A02 | A | Canonical encoding, valid decompression/on-curve, no alias normalization | F4 | S1 decoding | Vetted validator | C152 canonical identity; other classes U | P-A encoding | No | D04F-01 reaffirm |
| F-A03 | A | Reject O, all other low-order and all mixed-order; require H | F4 | S1 plus stronger project policy; S4/S6 explanatory | Vetted validator | C152 violation; mixed-order U | P-A subgroup | No | D04F-01 reaffirm |
| F-A04 | A | Exact independently enrolled/pinned key; not self-trust | F5/anchor sections 2–3 | S2 not sufficient | Policy/source | No enrolled-root execution | V04-16/18/19 | No | Existing A01/A04 pending |
| F-R01 | R | Exactly signature first 32 of 64 bytes, canonical on-curve point | F4 | S1 | Parser and validator | Full strict coverage U | P-R encoding | No | D04F-02 reaffirm |
| F-R02 | R | Require H; reject nonidentity torsion/mixed order | F4 | S4/S6 explanatory | Vetted validator | U | P-R subgroup | No | D04F-02 reaffirm |
| F-R03 | R | O not rejected solely for identity, provided equation/all checks pass | F4 | S1 has no blanket R!=O | Validator/backend | No independent positive asset | P-R identity positive | No | D04F-02; forbid extra rejection |
| F-S01 | S | Exact 32-byte unsigned little-endian, 0<=S<L | F4 | S1 verify | Parser/scalar check | Some invalid corpus rejected, not exhaustive | P-S boundaries | No | D04F-02 reaffirm |
| F-S02 | S | Reject rather than reduce out-of-range S; do not require S!=0 | F4 interval | S1 malleability | Scalar check/backend | U for exact boundary set | P-S aliases/zero | No | D04F-02 reaffirm |
| F-E01 | Equation | Pure mode on exact M, no ph/ctx/prehash/fallback | F4/W frame | S1/S2 | Mode/parser/backend | RFC3 raw messages; project frames U | P-E mode/frame | No | D04F-03 implementation mapping |
| F-E02 | Equation | Reference E1; E8 only with proven predicate-equivalence | F4 standard-equation phrase | S1/S4 | Backend plus validator | Internal OpenSSL path unknown | P-E differential edges | Internal form unresolved, acceptance equivalent on H | D04F-03 PROPOSED clarification |
| F-E03 | Equation | Failure produces no evidence or partial successful quorum | F4/F5/E | Project policy | Adapter/policy | No root quorum implementation | V04-15/24/26 | No | D04F-04/06 scope |

No security-critical contradiction was found. R identity is explicit, not ambiguous;
choosing a library that rejects it is an integration mismatch. Implementation API
coverage and internal backend equation remain unresolved, not permission to weaken
predicates. Proposed composition/equation choices need owner review and independent
sign-off; extraction of existing requirements does not need a profile amendment.

## Primary standards and research ledger

Read-only retrieval 2026-11-16. URLs below were consulted, not executed. S1 is an
Informational RFC specifying EdDSA, not a statement that our stronger policy is its
only conforming behavior. Versioned implementation sources describe code, not tests
of any installed binary. Current support/advisory status is not certified here.

| ID / title | Exact URL / version | Kind / relevance / disagreement |
| --- | --- | --- |
| S1 Edwards-Curve Digital Signature Algorithm | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), January 2017, sections 5.1.2/3/7 and 8.4 | Algorithm specification: encoding, S bounds and equation alternatives; project adds full subgroup/nonidentity-A restrictions |
| S2 Ed25519 signing | [PyCA docs](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/), 50.0.2 | API documentation, not proof of strict predicates |
| S3 Ed25519 backend source | [PyCA tag 50.0.2](https://raw.githubusercontent.com/pyca/cryptography/50.0.2/src/rust/src/backend/ed25519.rs) | Maintainer source: delegates verification to OpenSSL, not internal equation proof |
| S4 It's 255:19AM. Do you know what your validation criteria are? | [de Valence](https://hdevalence.ca/blog/2020-10-04-its-25519am/), 2020-10-04 | Primary explanatory analysis of encoding/cofactor/interoperability differences; not audit of selected binary |
| S5 Point validation source | [libsodium 1.0.20-RELEASE](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.20-RELEASE/src/libsodium/crypto_core/ed25519/core_ed25519.c), crypto_core_ed25519_is_valid_point | Candidate checks canonicality/curve/main subgroup and small order; no claim its nonidentity predicate is suitable unchanged for R |
| S6 EdwardsPoint | [curve25519-dalek 4.1.3](https://docs.rs/curve25519-dalek/4.1.3/curve25519_dalek/edwards/struct.EdwardsPoint.html) | Documented is_torsion_free versus is_small_order: distinct predicates; full coverage needs review |
| S7 Strict signature source | [ed25519-dalek ed25519-2.2.0](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/verifying.rs), verify_strict | Explicitly rejects small-order A or R, including identity R. This differs from project R allowance; method name cannot resolve mismatch |

Original corpus semantics and pinned provenance are in the
[public catalog](iam03c-trust04c-ed25519-public-vector-catalog.md); local notes retain
acceptable for equation-valid small/mixed-order keys. Do not substitute those labels
for F-A03/F-R02 or infer library insecurity from a policy difference.
