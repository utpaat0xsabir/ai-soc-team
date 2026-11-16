# TRUST-04E strict Ed25519 verification boundary

2026-11-16. Documentation-only TRUST-04E. No cryptographic execution, hashing, signing, installation or profile amendment. All proposed decisions are unapproved.

## Frozen requirements and ownership

Normative repository reference: [anchor contract section 4](iam03c-trust04-anchor-and-verifier-contract.md),
with [wire specification](iam03c-trust04-root-policy-wire-spec.md) and
[ordered errors](iam03c-trust04-vector-and-error-matrix.md). No contradiction requiring
a profile change was found. Existing serializers, schema, digests and fifteen
ordered diagnostics remain unchanged.

| Requirement | Boundary responsible | Acceptance evidence still needed |
| --- | --- | --- |
| Raw A=32 bytes, R||S=64 bytes, exact hex | Signed-message parser plus backend defense | Explicit malformed-length tests and deterministic STRUCTURE_INVALID |
| Canonical, on-curve A; nonidentity; prime-order subgroup | STRICT KEY-VALIDATION BOUNDARY | Vetted full predicate, not length constructor or blacklist |
| Canonical on-curve R in prime-order subgroup; identity R allowed if equation valid | Strict mathematical verifier | Separate R predicate; do not reuse a nonidentity-only A validator blindly |
| Canonical scalar 0<=S<L; exact pure equation | CRYPTOGRAPHIC BACKEND RESPONSIBILITY under strict wrapper | Reviewed scalar/R acceptance and backend exact-frame tests |
| PureEd only, exact frame not its digest; no ph/ctx/fallback | Signed-message boundary and selected backend mode | Profile binding and independent negative vectors |
| ASCII canonical body, exact domain/NUL/U64BE, all 17 fields, hashes, limits | SIGNED-MESSAGE / CANONICALIZATION BOUNDARY | Independent literal assets; unchanged TRUST02 serialization |
| Independently pinned customer keys, exact bindings/policy, unknown/revoked rejection | TRUST-ANCHOR / QUORUM POLICY BOUNDARY | Source authenticity, lifecycle and negative fixtures |
| Three distinct customer custodians; two eligible signatures; every supplied entry valid | TRUST-ANCHOR / QUORUM POLICY BOUNDARY | Duplicate key/material/person mapping, invalid third, permutations |

A 32-byte string need not decode; a decoded point need not be canonical; a canonical
point may be identity; nonidentity does not imply absence of torsion; absence of pure
small order does not exclude a mixed-order point. Even a valid nonidentity subgroup
point is not an enrolled key, and an enrolled key is not automatically an eligible,
unrevoked, authorized signer. A narrow identity blacklist establishes none of the
other properties.

## Primary research ledger

Retrieved read-only on 2026-11-16. These sources specify APIs, mathematics or source
behavior; only saved TRUST-04D evidence records a run of the selected environment.
No executable package was downloaded or source code executed.

| Source / exact version | Relevant evidence and relationship |
| --- | --- |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), January 2017, sections 5.1.2/5.1.3/5.1.7 | Encoding/decoding and S range; cofactored equation and permitted uncofactored check. Does not impose this project's full nonidentity prime-subgroup A requirement. Explains why a policy difference need not violate the RFC |
| [PyCA Ed25519 API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/), 50.0.2 | Documents raw-key constructor and verify failure behavior; no promise of this complete subgroup profile |
| [PyCA implementation](https://raw.githubusercontent.com/pyca/cryptography/50.0.2/src/rust/src/backend/ed25519.rs), tag 50.0.2, Ed25519PublicKey::verify | Delegates exact inputs to no-digest OpenSSL one-shot verification; source evidence supports boundary attribution, not internal backend execution proof |
| [PyCA security policy](https://cryptography.io/en/50.0.2/security/), 50.0.2 | Reporting and vulnerability-review process; not a clean security bill or evidence of a known identity-key advisory |
| [Wycheproof corpus](https://github.com/C2SP/wycheproof/blob/a3d5d1423f2592d6646836a45a21a1b209da9f4d/testvectors_v1/ed25519_test.json), pinned commit | Notes distinguish equation-valid torsion/mixed-order keys from stricter policy. Retained local file provides exact case 152; source expectation is not installed-backend proof |
| [de Valence analysis](https://hdevalence.ca/blog/2020-10-04-its-25519am/), 2020-10-04 | Primary technical analysis of cofactor and implementation acceptance differences; supports separating policies, not an audit of our binary |
| [libsodium predicate source](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.20-RELEASE/src/libsodium/crypto_core/ed25519/core_ed25519.c), 1.0.20-RELEASE, crypto_core_ed25519_is_valid_point | Checks canonical encoding, small-order, decoding, on-curve and main subgroup. Candidate A-validation capability, not selected/pinned Python dependency or tested integration |
| [ed25519-dalek VerifyingKey](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html), 2.2.0 | Explicit weak-key and strict-verification interfaces. A method named strict is not evidence of matching our mixed-order/R-identity acceptance set |

Official libsodium generic point-arithmetic page was accessible, but the attempted
Ed25519-specific documentation URL was unavailable; use the pinned maintainer source
above for that predicate claim. No current maintenance/advisory clearance of an
alternative library, binding or binary is asserted. No OpenSSL internal source path
was verified for the installed build. External release notes were not used to infer
unobserved behavioral changes; existing [dependency evidence](iam03c-trust04c-authoritative-dependency-evidence.md)
remains historical support context, not conformance proof.

## Candidate approaches

| Approach | Advantages | Limitations, risks, tests and disposition |
| --- | --- | --- |
| A: current backend only | Existing pinned environment and simple boundary | CONFIRMED insufficient for A nonidentity on case 152. Cannot resume as profile compliant. Other versions/builds untested; no silent substitution |
| B: vetted pre-verification validation plus existing equation backend | Separates explicit profile predicates; established point API candidate exists | Public-key-only validation is insufficient: also prove R canonical/subgroup (identity exception), S range, exact equation and mode. Two native stacks/bindings increase supply-chain and cross-version risks. No selected Python package/API yet. Recommend further evaluation of this complete boundary, not implementation |
| C: independently reviewed strict verifier | Potential single coherent acceptance set; Rust dalek candidate permits comparative review | Rust/Python FFI, packaging/wheels/toolchain, licenses, support/advisories, exact features and batch semantics require review. Strict may reject permitted identity R or accept mixed-order classes. No candidate declared fully compatible; benchmark only after security acceptance |
| D: formal owner clarification | Makes responsibility, evidence and A/R asymmetry explicit | Cannot fix backend behavior or waive identity/subgroup prohibition. Clarify deployment and diagnostics without changing frozen bytes/acceptance. Proposed review only |

Preferred next evaluation: B with independently reviewed established A and R/scalar
predicates plus equation backend, compared against C as an independent oracle.
Do not use libsodium's nonidentity predicate unchanged for R: frozen R may be identity.
No homemade bad-point table or curve arithmetic is proposed. If established APIs
cannot express the full predicates, STOP for architecture review rather than implement
an approximation. Current evidence supports this review direction, not compatibility
or maintenance approval of a new dependency.

## Root-policy implications and residual risk

Independently authenticated pins prevent a request from simply inserting its own
identity key, but do not prove that enrolled public material is cryptographically
admissible. If a forbidden key were enrolled and counted, one purported vote could
be supplied without its custodian's secret. Combined with another eligible vote,
this could undermine two-of-three integrity. Two distinct forbidden enrolled keys
could be worse, but no such enrollment or quorum exploit was executed or observed.
IDs, distinct byte strings, revocation, root-set digest, tenant/environment binding
and framing are necessary independent checks, not replacements for admissible keys.

The observed forgery uses raw message bytes. Conceptually identity A removes the
message-dependent term from the equation, so domain separation alone cannot repair
weak-key acceptance; this is a mathematical inference, not a tested project-frame
attack. Properly pinned admissible keys and correct every-entry checks restrict the
preconditions. No operational path imports this harness and signature evidence
cannot become IAM ALLOW. Custody, host compromise, stale revocations and two-custodian
collusion remain outside cryptographic conformance.
