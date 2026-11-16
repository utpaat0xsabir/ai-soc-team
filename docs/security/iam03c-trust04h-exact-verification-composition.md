# TRUST-04H exact proposed verification composition

2026-11-16. TRUST-04H documentation-only proposal. No code, crypto execution, new dependency, trust enrollment, reviewer appointment or approval. All owner decisions remain PROPOSED — NOT APPROVED.

## Scope and candidate identity

Proposal ID **H-COMP-1**: a single-family, TEST-only composition using version-specific
curve25519-dalek 4.1.3 point/scalar primitives and ed25519-dalek 2.2.0's ordinary
pure Verifier entry, with explicit full preconditions. These are exact research
versions, not an approved install/build set or maintained-support certification.
Candidate source references C1–C5 below identify the inspected tags; full immutable
commit/artifact authentication, feature lock, runtime and independent review remain
pending. No source archive, executable or package was downloaded or run.

H-COMP-1 deliberately does not choose a Python FFI or operational service. For review,
prefer a standalone native TEST reference before any Python binding decision. This
reduces cross-library encoding/ABI assumptions without removing the need for review.
No reference program is created or authorized. If the reviewer finds these exact
versions unsuitable, revise this proposal under separate authorization; do not silently
substitute releases or enable compatibility flags.

Frozen sources: [TRUST-04 section4](iam03c-trust04-anchor-and-verifier-contract.md),
[wire](iam03c-trust04-root-policy-wire-spec.md),
[errors](iam03c-trust04-vector-and-error-matrix.md). Requirement IDs F-A01–F-E03 come
from [TRUST-04F](iam03c-trust04f-strict-ed25519-normative-profile.md). No new frozen
predicate is introduced. Pure mode, body17 fields, customer3/quorum2, exact domain
frame and all15 diagnostics remain unchanged. ROOT_TRANSITION/ISSUANCE/CHECKPOINT,
production evidence and recovery are still unsupported.

## Exact component/source matrix

Retrieved read-only 2026-11-16. SOURCE_SUPPORTED means source inspection supports
specified semantics; no installed conformance or independent audit is inferred.

| ID/component | Candidate/version and official source | Supported behavior / evidence | Gap / risk / disposition |
| --- | --- | --- | --- |
| C1 A/R points | [edwards.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/edwards.rs), curve25519-4.1.3: CompressedEdwardsY::decompress, EdwardsPoint::compress, is_torsion_free | SOURCE_SUPPORTED decoding, canonical re-encoding and distinct subgroup predicate | Canonicality requires equality to original, not decompression alone; helper/backend correctness and binary tests pending; CANDIDATE |
| C2 A-only identity | [traits.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/traits.rs), same tag: IsIdentity/Identity | SOURCE_SUPPORTED established identity predicate interface | Review exact trait implementation and call site; never apply A exclusion to R; CANDIDATE |
| C3 S | [scalar.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/curve25519-4.1.3/curve25519-dalek/src/scalar.rs), same tag: Scalar::from_canonical_bytes, lines249–252 | SOURCE_SUPPORTED canonical input scalar gate | No modulo reduction/clamping; arithmetic and actual selected binary still need review; CANDIDATE |
| C4 equation/key bytes | [verifying.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/verifying.rs), ed25519-2.2.0: from_bytes154, raw_verify187, RCompute456–521, Verifier::verify530 | SOURCE_SUPPORTED ordinary pure SHA512 path, original key bytes, encoded expected-R comparison | No independent composed test/R=O asset; verify_strict338 is REJECTED for this composition because extra small-order-R exclusion |
| C5 scalar defense | [signature.rs](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/src/signature.rs), same tag: check_scalar84/InternalSignature | SOURCE_SUPPORTED canonical scalar path when legacy_compatibility disabled | Must inspect unified features; legacy path is REJECTED; CANDIDATE defense |
| C6 trust/policy/result | Frozen TRUST-04 wire/anchor/error specs and unchanged TRUST02 records | Proposed exact independent TEST pins, binding, eligibility, duplicates, quorum and evidence | No implementation or authenticated production source; no existing generic IAM object promoted; UNRESOLVED implementation |

Metadata source: [ed255192.2.0 Cargo](https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/ed25519-2.2.0/ed25519-dalek/Cargo.toml)
requires Rust>=1.81 and a curve version4 range; that range is not a lock. Proposed
review requires exact curve4.1.3 resolution shared across point/equation components,
no duplicate arithmetic versions, no legacy_compatibility anywhere, no batch/prehash/
context alternate entry, no request-controlled backend/features. Other transitive
pins, compiler/CPU/backend flags, support/advisory and license clearance are UNRESOLVED.
No claim that minimum Rust1.81 is the approved runtime. Earlier Python3.10.12 TEST
exception does not approve a new Rust toolchain or binding.

## Eight non-executable logical stages

These are a design decomposition, not the observable diagnostic order. Frozen early
binding/duplicate/source/revocation/threshold stages still precede signature math.
See the priority reconciliation below. Each stage requires independent review of
its predicate, data handoff and negative/positive tests before prototype acceptance.

| Stage | Exact input | Required validation / candidate | Failure | Assumptions / future tests / reviewer obligation |
| --- | --- | --- | --- | --- |
| 1 structure | Bounded TEST proof, independently expected context, immutable full frame M, raw A32 and signature64 | Frozen closed schemas/budgets/purpose/profile; split signature first32 R/last32 S; exact frame label+NUL+U64BE+body; pure only | Frozen earliest shape/limit/domain/algorithm code, no normalization/fallback | Original bytes retained across all later calls; V04-02/11/12/13/22/23/24; review parser/counters, not just math |
| 2 A | Exact independently selected raw32 bytes, not a request-selected replacement | C1 decode succeeds; re-encode equals bytes; torsion-free=true; C2 identity=false | Well-shaped math failure SIGNATURE_INVALID; unusable source/registration rejected separately at its frozen stage | Decoded point in H and exact A hash transcript; tcId152, all torsion/mixed/aliases/invalid curve; review no omitted check |
| 3 R | Exact original first32 signature bytes | C1 decode and exact re-encode equality, torsion-free=true; no nonidentity rule | SIGNATURE_INVALID on predicate failure; O alone is not failure or success | R=O only admissible pending equation; independent valid identity-R positive plus invalid cases; review A/R asymmetry |
| 4 S | Exact original last32 bytes | C3 canonical unsigned LE range0<=S<L; C5 independent backend defense, no reduction of input | Out-of-range well-shaped scalar SIGNATURE_INVALID; malformed signature shape earlier | Zero in range but not proof; test0/1/L-1/L/L+1/high bits/aliases with independent equation expectations; review features |
| 5 equation | The same original A, signature64 and immutable M passing stages2–4 | C4 ordinary pure Verifier, exactly E1, no verify_strict/prehash/batch/fallback; normal return is equation evidence only | Any error/panic/backend fault fails closed, fixed code, no partial evidence | Review bytes preserved, hash/mode path and extra exclusions; RFC3,210 cases, R=O positive, wrong key/frame/mode; binary/source mapping pending |
| 6 anchor policy | Authenticated immutable TEST source/context, exact manifest/root-set/policy/pins/custodian map and explicit time | Frozen customer-only trust domain/deployment/tenant/environment/root policy; uniqueness, mapping, lifecycle/revocation; no claim self-establishes trust | Existing source/pin/eligibility/binding code; no foreign inventory or fallback | Actually occurs before math; independent provenance and pin authenticity outside curve APIs; V04-07–10/16–20/25 |
| 7 quorum | Eligible exact map and all supplied signatures, max3 | Two distinct eligible custodian votes minimum, fixed customer3, no duplicate key/material; all supplied eligible signatures pass in sorted order | Frozen threshold precheck before math; any invalid extra entry rejects all evidence | No after-the-fact discard of invalid third; test0/1/2/3, permutations/revoked/duplicates; review independent people assumption |
| 8 result | Only completely successful TEST proof assessment | Immutable non-authorizing SignatureEvidence bound to frame digest, expected context, exact TEST anchor and signer pairs | No evidence on any failure; no caller success flag can bypass stages | Output hash is future operation only; no IAM consumer, no ALLOW/current authority; V04-26; review result origin/isolation |

## Equation and exact handoffs

E1 is [S]B=R+[k]A with k=SHA512(encoded R||encoded A||M), interpreted per pure
Ed25519. C4 uses the same bytes after external checks; no decode/re-encode replacement
is passed to the hash. Equality checks reject aliases, rather than normalize them
into success. Checking S's input range is distinct from reducing challenge k.
Signature construction/parsing must preserve R||S exactly. No rewritten scalar,
cofactor-cleared point or key substitution is permitted between validation and verify.

For H prime order L, residual [S]B-R-[k]A belongs to H. Multiplication by8 is
injective on H; E1 and E8 therefore agree only after the required predicates. This
is the reviewed analytical argument from04F, not an internal OpenSSL assertion or
independent mathematical sign-off. Candidate C4 supplies documented E1 source and
avoids relying on the unresolved OpenSSL path. [RFC8032](https://www.rfc-editor.org/rfc/rfc8032)
provides algorithm context, not this project's full trust-anchor policy.

## Observable priority and implementation blockers

Preserve all15 frozen stages: LIMIT_EXCEEDED, SYNTHETIC_SOURCE, STRUCTURE_INVALID,
BINDING_MISMATCH, SIGNER_DUPLICATE, CANONICAL_MISMATCH, DOMAIN_MISMATCH,
ALGORITHM_UNSUPPORTED, ANCHOR_UNAVAILABLE, POLICY_STALE, SIGNER_UNKNOWN,
KEY_REVOKED, TIME_INVALID, QUORUM_INSUFFICIENT, SIGNATURE_INVALID. Repeated budget
checks follow frozen observable-extent rules. Anchor lookup at most once; candidate
metadata checks and eligibility/threshold precede expensive A/R/S/math. Invalid
independent anchor material must make source unusable/registration fail; no new code
or public diagnostic added. The eight logical stages must not become new priority.

H-COMP-1 is **PROPOSED**, not an approved reproducible dependency set. Blocking
implementation facts: independent appointment/sign-off absent, full commits/artifacts
and dependency/features/toolchain unresolved, Python integration unselected, exact
composed tests and R=O golden absent, remaining58 corpus and all26 project goldens
not completed. No safety conclusion bypasses these gates.
