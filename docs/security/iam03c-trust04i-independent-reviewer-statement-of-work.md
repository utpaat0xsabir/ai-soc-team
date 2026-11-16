# TRUST-04I — Independent cryptographic reviewer statement of work

**Draft for owner procurement/appointment. Reviewer: NOT APPOINTED.** This document does not contact, appoint, or represent any person as having reviewed the design.

## Required qualifications and independence

The owner should appoint an individual or team able to demonstrate substantive experience in Ed25519 and elliptic-curve cryptography, signature-verification semantics, canonical encodings, subgroup/cofactor behavior, implementation/source security review, Rust cryptographic crates, and adversarial test design. The owner—not this document—verifies qualifications and references.

The reviewer must not author H-COMP-1 or the future corrective implementation, nor be the sole author of the expected-value oracle. Disclose employment, financial, maintenance, authorship, and other relevant conflicts. The reviewer must be free to reject the composition, have access to the exact frozen documents and evidence, and provide reproducible written reasoning. A separate golden-vector reviewer is required if the primary reviewer authors any derivation procedure. Codex review is not independent sign-off.

## Statement of work

### A. Mathematical review

Review the frozen predicates and their conjunction: A canonical/on-curve/in H/nonidentity; R canonical/on-curve/in H with identity permitted; S exact 32-byte unsigned little-endian and `0 ≤ S < L`; pure Ed25519 transcript; proposed E1 non-cofactored equation. Assess the E1/E8 equivalence argument under full subgroup predicates, identity-R semantics, potential malleability, and edge cases. Identify assumptions or changes to the frozen profile; do not silently amend it.

### B. Source and implementation review

For exact source revisions and resolved features, inspect point decoding, recompression/canonicality, subgroup predicate, identity predicate, scalar parsing, ordinary pure verification, hash transcript, encoded-R comparison, error behavior, and strict-entry differences. Determine whether source behavior maps to the proposed predicates. Review exact selected artifacts and runtime separately from source; source-only evidence is insufficient to establish runtime behavior.

### C. Composition review

Assess whether the A/R/S primitives and equation verifier operate on the same original bytes and mathematical interpretation. Examine point/scalar representation boundaries, identity-R compatibility, equation selection, feature interactions, dependency duplication/version drift, error/panic handling, memory/FFI or ABI boundaries if introduced, and the risk that individually reviewed primitives compose unsafely. No FFI or Python binding is in the current H-COMP-1 selection.

### D. Trust and policy boundary review

Verify that crypto input is bound to independently supplied TEST context and pins; provider identity cannot substitute for customer trust; custodian mapping, uniqueness, revocation, environment/root-policy/purpose binding and all-signatures-valid quorum semantics are enforced outside the math primitive; frozen diagnostic precedence remains unchanged; outputs are non-authorizing and no operational IAM path consumes them. Review no self-signed trust bootstrap, request-selected key, algorithm fallback, or synthetic promotion.

### E. Test-plan review

Review the three published RFC 8032 vectors, all 210 original Wycheproof records and verdicts, all 26 project V04 cases, and explicit A/R/S/equation negatives. Required edges include identity A rejection; identity R accepted only for an independently established equation-valid case and rejected for invalid equation; canonicality, invalid-point and subgroup cases; S values around 0 and L; invalid extra third signature; duplicates, revocation, quorum manipulation, wrong tenant/deployment/environment, purpose/frame replay, and independent golden derivation. Identify missing or ambiguous cases. Preserve native Wycheproof verdicts; policy-specific disposition is separately recorded.

## Questions requiring written answers

1. Are the A canonicality, on-curve, prime-order and nonidentity checks sufficient, and are their implementations correct?
2. Are the corresponding R checks sufficient while retaining identity R?
3. Is A-only identity rejection mathematically and operationally justified by the frozen policy?
4. Does identity R create any weakness under the exact equation and all other frozen predicates?
5. Does the exact ordinary `ed25519-dalek` API/build implement E1 and retain identity-R behavior?
6. Can a valid identity-R signature be constructed and independently confirmed without changing the message/profile? If not, explain why; do not replace evidence with an assumption.
7. Are S parsing and bounds consistent across every stage and feature combination?
8. Can noncanonical aliases, mixed-order points, low-order points, or malformed encodings bypass validation?
9. Are there malleability or cross-library interpretation hazards?
10. Does the composition rely on undocumented behavior or source-to-binary assumptions?
11. Are the proposed exact dependency versions and build inputs suitable for a TEST prototype?
12. What exact evidence, corrections, and tests are required before implementation?

Reviewer may add questions and must distinguish proven findings, source-supported findings, hypotheses, and unknowns.

## Deliverables and permitted outcome

The reviewer report should identify reviewer and qualifications; independence/conflict declaration; review date; exact specification revision; exact source commit/artifact/feature/toolchain identities actually reviewed; source references; mathematical and implementation findings; threat and residual-risk assessment; required corrections/tests; scope limitations; and one explicit decision:

- **APPROVED_FOR_TEST_PROTOTYPE** — design is sufficiently justified for a separately authorized, bounded TEST prototype only.
- **APPROVED_WITH_CONDITIONS** — list conditions that must close before prototype authorization.
- **MORE_EVIDENCE_REQUIRED** — evidence is insufficient to decide.
- **REJECTED** — composition is unsuitable as reviewed.

No outcome grants owner authorization, approves production trust or deployment, or proves operational IAM readiness. The decision must be authenticated by the reviewer using an owner-agreed method; no reviewer identity, signature, credential, or result is prefilled here. The owner records receipt and decides independently whether to authorize any next work.

## Review packet

Supply the reviewer with the linked TRUST-04 wire, anchor, diagnostic/vector, 04F profile, 04G evidence and 04H composition/R-identity/owner documents listed in [baseline](iam03c-trust04i-hcomp1-review-baseline-and-artifact-requirements.md), plus read-only TRUST-04D evidence assets. Include all 20 threat mappings, all 26 vector cases, all 15 diagnostics, all original corpus verdicts, and 58 NOT_RUN status. Do not represent the evidence packet as a test correction or a completed audit.

## Owner-controlled appointment

The owner separately chooses the reviewer, verifies competence/conflicts, approves this scope, agrees review access and deliverables, and retains the signed report. No external contact is authorized by TRUST-04I. A later implementation author must not be the sole reviewer of the code or oracle.
