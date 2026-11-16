# TRUST-04H R-identity compatibility and backend risks

2026-11-16. TRUST-04H documentation-only proposal. No code, crypto execution, new dependency, trust enrollment, reviewer appointment or approval. All owner decisions remain PROPOSED — NOT APPROVED.

## Compatibility finding

H-COMP-1 in the [composition](iam03c-trust04h-exact-verification-composition.md)
can express the required identity-R behavior at source/design level: canonical
point decoding/recompression and torsion-free check admit O, A alone excludes O,
and ordinary pure equation verification still determines validity. No branch treats
identity R as success or skips equation checking. This is SOURCE_SUPPORTED reasoning;
complete runtime conformance remains unverified, and the required independent
identity-R positive asset is missing.

The ordinary verifier source is distinct from the strict entry point. Its use is not
permission to run permissive verification without the full preceding predicates.
No modification or copy of library internals is proposed. Source references and
exact versions are C1–C5 in the composition, with historical candidates/audit/advisory
limits in [04G source evidence](iam03c-trust04g-source-level-verification-evidence.md).

| R input | Required disposition | Why / remaining evidence |
| --- | --- | --- |
| Canonical O with admissible A/S/M and valid equation | Must not fail solely due to O; all policy/quorum checks still required | Decompression and H membership do not exclude O; independent equation-valid positive needed |
| Canonical O with invalid equation or out-of-range S | Reject | Admissibility is not validity; ordinary verifier must not be bypassed |
| Noncanonical O alias, sign/y alias or malformed point | Reject before equation success can matter | Re-encode equality rejects aliases; decompression/subgroup coverage still requires independent review |
| Nonidentity pure torsion or mixed-order R | Reject | H predicate, not only a low-order blacklist or cofactor multiplication |
| Canonical R in H but wrong message/key/frame/mode | Reject unless exact equation genuinely holds | Full frozen transcript, no algorithm/byte normalization fallback |

Do not apply A's nonidentity rule, libsodium's nonidentity point predicate unchanged,
or dalek verify_strict to R. Known entry-point mismatches are excluded alternatives,
not contradictions in the chosen profile. No source finding requires changing the
frozen identity allowance. Actual binary/API composition safety remains UNRESOLVED
pending independent source/code review and authorized positive/negative tests.

## tcId152 contrast

The [saved result](../../tests/iam/fixtures/trust04d_offline_validation/results.json)
is identity A, not identity R: canonical A=O, R=B, S=1 on raw seven-byte message.
Source verdict acceptable stays unchanged; project requires rejection. H-COMP-1's
A-only identity check would reject according to design, without relying on backend
rejection. This has not been executed. An identity-R exception must never become an
identity-A exception. Neither rejecting152 nor passing RFC3 proves all forbidden
subgroup/encoding classes or permitted edges. No claim of general PyCA/OpenSSL
insecurity, production exploit or reconstructed OpenSSL internal path is made.

## Composition safety risk register

| Risk | Required design constraint / future evidence | Disposition |
| --- | --- | --- |
| Different point decoding/canonical policies | Preserve exact bytes, canonical re-encode equality for both A/R; cross-API consistency fixtures | REVIEW_REQUIRED |
| Mixed-order versus small-order confusion | Explicit torsion-free membership plus separate A identity exclusion; mixed-order vectors | REVIEW_REQUIRED |
| Extra identity-R rejection | Ordinary documented equation entry only, independent permitted-R positive; no bypass on backend error | REVIEW_REQUIRED |
| Scalar endian/reduction mismatch | Fixed32 unsigned LE canonical gate; unchanged signature bytes; prohibit compatibility/clamping | REVIEW_REQUIRED |
| Equation/hash/mode mismatch | Document E1 path and original transcript; no ph/ctx/batch/alternate engine | REVIEW_REQUIRED |
| Different curve crates at runtime | Exact shared version/feature resolution; no duplicate incompatible representations | UNRESOLVED lock/artifact |
| Version/backend drift | Resolve tag commits, artifact authentication, compiler/CPU/features and re-review on changes | UNRESOLVED build provenance |
| FFI/ABI/memory safety | Prefer standalone TEST reference for first review; any Python binding separately scoped, bounded copies/lengths/lifetimes, panic/error contract | UNRESOLVED integration |
| Native/multi-library composition | Individually vetted primitives do not audit composition; no raw pointer point/scalar conversion or unchecked shared layout | REVIEW_REQUIRED |
| Supply chain/support/advisories/licenses | Exact transitive lock, current maintenance/security review, reproducible build, no automatic updates; historical audit not certification | UNRESOLVED approval |
| Unsupported versions/features | Research versions not blanket approval; prohibit legacy features through unified graph and default surprise | REVIEW_REQUIRED |
| Error/panic/partial evidence | Fail closed with frozen earliest code; no ignored invalid third, caught error converted to success or raw backend text | REVIEW_REQUIRED |
| Mutation between precheck/verify | Immutable owned copies of exact public inputs, expected context and pins; no re-fetch or substituting alternate key | REVIEW_REQUIRED |
| Shared oracle or host compromise | Independent derivation/reviewer; two wrappers over same arithmetic not independent crypto; local result not attestation | Residual / REVIEW_REQUIRED |

Single-family primitives reduce but do not eliminate composition assumptions.
Combining independently vetted components across libraries is not automatically safe:
representation, mode, scalar and error contracts must be proven at every handoff.
No undocumented behavior is considered established. If a reviewed component cannot
support the full predicates, stop selection instead of writing custom curve arithmetic.

## Evidence gaps and mathematical questions

Independent reviewer must check correctness of canonical round-trip for all y/sign
aliases and invalid decompressions; exact torsion-free predicate semantics at identity
and mixed-order points; A-only exclusion; scalar range including zero; challenge and
message preservation; equivalent E1/E8 assumptions and extra backend exclusions.
Need a valid R=O signature under admissible A sourced independently in later approved
TEST work. No expected output is fabricated here. S=0 or R=O individually does not
imply equation success. Future positive vectors must match the entire conjunction.

No output of H-COMP-1 would establish real custody, customer enrollment, live
revocation/freshness or authority database integrity. The customer3/quorum2 model,
provider separation, independent expected environment/tenant/deployment and exact
root-policy pins remain distinct. Two compromised custodians, malicious display,
verifier host compromise and infrastructure administrator access remain residual risks.
