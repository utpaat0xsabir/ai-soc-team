# TRUST-04J — Reviewer engagement and assessment statement of work

**Status:** draft only. No recipient selected, email sent, organization contacted, reviewer appointed, or engagement accepted. Share no material until owner approves disclosure.

## Ready-to-send email draft

**To:** `[Prospective reviewer selected by project owner]`

**Subject:** Independent review request — Ed25519 trust-policy verification design

Hello,

We are preparing an independent cryptographic review for AI SOC Team, a local-first, multi-tenant security operations platform. The review concerns a proposed TEST-only verifier for customer-controlled root-policy signatures. It is not a request to approve production IAM or customer root enrollment.

The proposal, H-COMP-1, uses explicit A/R point and S scalar validation candidates from `curve25519-dalek 4.1.3`, followed by ordinary pure Ed25519 verification proposed from `ed25519-dalek 2.2.0`. The profile requires canonical A and R encodings, prime-order subgroup membership for both, identity rejection for A only, identity R permitted only when the complete signature equation succeeds, and `0 ≤ S < L`. The proposed equation is the non-cofactored Ed25519 equation over the exact domain-separated message frame. These versions and behaviors are research candidates; no reproducible artifact/toolchain lock or runtime verification of H-COMP-1 exists.

A prior isolated test run found that `cryptography==50.0.2`/OpenSSL 4.0.3 accepted Wycheproof tcId 152, whose source verdict is `acceptable` and whose public key is the identity point. This conflicts with our stricter A policy. The run stopped at that discrepancy. It does not establish that H-COMP-1 is affected or that the underlying backend is generally insecure. A central review question is whether the proposed composition can preserve the identity-R allowance without accepting identity A or relying on undocumented behavior.

We are seeking a reviewer with demonstrated Ed25519/ECC, point encoding/subgroup/cofactor, signature equation, Rust cryptographic implementation and source-security-review experience. The proposed scope and decision criteria are attached for discussion: mathematical analysis, versioned source/API and dependency review, composition review, trust-policy boundary review, and assessment of the RFC/Wycheproof/project test plan.

Could you please indicate your availability, relevant qualifications/references, any actual or potential conflicts, estimated timeline, and fee/engagement terms? The owner will review qualifications and independence and approve scope, confidentiality terms, and disclosure before any project materials are shared. This draft does not authorize access to the repository or evidence.

Expected written outcomes are one of `APPROVED_FOR_TEST_PROTOTYPE`, `APPROVED_WITH_CONDITIONS`, `MORE_EVIDENCE_REQUIRED`, or `REJECTED`, with reproducible findings and explicit limitations. Any positive outcome would apply only to consideration of a separately authorized TEST prototype, not production approval.

Regards,

`[Project owner / authorized contact]`

**Draft only — do not send without separate owner authorization.** No recipient address is supplied.

## Reviewer qualification and independence checklist

- [ ] Owner verified demonstrated expertise in Ed25519 and Edwards-curve arithmetic.
- [ ] Owner verified work on canonical encodings, subgroup membership, cofactor semantics, scalar validation and signature equations.
- [ ] Reviewer can assess Rust cryptographic implementations, source-level security and composition.
- [ ] Reviewer can design/review adversarial cryptographic tests.
- [ ] Reviewer is not H-COMP-1 author, future prototype author, or sole golden-oracle author.
- [ ] Employment, financial, authorship, maintenance and other relevant conflicts are disclosed and assessed.
- [ ] Reviewer is free to reject; scope allows access to exact frozen specs and approved evidence.
- [ ] Review method, references, limitations and authenticated written deliverables are agreed.
- [ ] If reviewer authors any expected-value derivation, a separate independent golden reviewer is appointed.

No checklist item is complete absent owner-held evidence. No identity or qualification is fabricated here.

## Assessment statement of work

### 1. Mathematical correctness

Assess exact canonical point decoding and round-trip rules; on-curve and prime-order subgroup membership for A and R; A-only identity rejection; identity-R allowance without bypassing the equation; fixed-width unsigned little-endian S and strict `0 ≤ S < L`; pure Ed25519 transcript; E1 non-cofactored equation; conditions for E1/E8 equivalence; and signature malleability/edge cases. Identify any assumption not entailed by the frozen profile. Do not silently amend acceptance semantics.

### 2. Source-level correctness and dependency evidence

Inspect exact immutable source commits and later approved artifacts for `curve25519-dalek 4.1.3` predicates and `ed25519-dalek 2.2.0` ordinary verification. Assess point decoding, canonicality, subgroup predicate, identity behavior, scalar parser, hash transcript, equation and encoded-R comparison. Review version/feature interactions, prohibition of `legacy_compatibility`, prehash/context/batch/alternate paths, complete transitive dependency resolution, source provenance, compiler/Cargo/toolchain/target constraints, licenses, maintenance and advisories. Treat source claims separately from artifact/runtime behavior.

### 3. Composition correctness

Verify same-original-byte handoffs from parser to A/R/S validators to equation verifier; no point re-encoding substitution in transcript; consistent scalar endian/range; identity-R compatibility; exact equation and mode; error/panic fail-closed behavior; dependency/version drift; duplicate curve implementations; and FFI/ABI/memory boundaries if later introduced. Identify whether correct components compose safely or whether a single coherent implementation is necessary.

### 4. Trust and authorization separation

Review independent TEST anchor pins and context, tenant/deployment/environment/purpose/root-policy binding, customer custodian identity mapping, distinct votes, revocation, threshold, invalid extra signature rejection, fixed 15-diagnostic precedence and bounded inputs. Confirm a crypto pass yields only non-authorizing evidence; no IAM policy, admission, current-authority or execution result follows. Review the prohibition on caller-selected trust, provider authority, synthetic sources and self-signed bootstrap.

### 5. Test acceptance plan

Review all three RFC 8032 vectors, all 210 original Wycheproof records/verdicts, all 26 project cases, and dedicated A/R/S/equation negatives. Include identity A rejection; valid identity R only with an independently derived equation-valid case; invalid identity-R equation rejection; canonical/noncanonical encodings; malformed and subgroup points; scalar values at 0, 1, L−1, L and beyond; wrong keys/messages/frames/modes; two-of-three behavior; duplicate/revoked signer; invalid third signature; tenant/deployment/environment replay; frozen multi-fault precedence and side-effect counts; and independent golden derivation. State which source verdicts differ from the project policy and why. Identify missing tests and exact pass/fail/review criteria.

### 6. Required report and exclusions

The reviewer report must record qualifications, independence/conflict declaration, dates, exact spec revision, full source commit and artifact identities actually reviewed, resolved feature graph and toolchain where applicable, methods and reproducible references, findings/severity, required corrections, test gaps, residual risks, scope exclusions, and one permitted decision. Explicitly state if implementation, runtime, artifacts, custody, operational IAM, database state, or production deployment were not reviewed. The current engagement is design/source evidence assessment; it is not production audit, penetration test, deployment approval, or operational authority review.

## Decision scale

- **APPROVED_FOR_TEST_PROTOTYPE:** design is sufficiently justified for owner consideration of separately authorized TEST implementation.
- **APPROVED_WITH_CONDITIONS:** conditions must close before any prototype grant.
- **MORE_EVIDENCE_REQUIRED:** insufficient evidence to conclude.
- **REJECTED:** composition is unsuitable as reviewed.

No result itself authorizes implementation. Owner approval and a separate exact-scope grant are required.
