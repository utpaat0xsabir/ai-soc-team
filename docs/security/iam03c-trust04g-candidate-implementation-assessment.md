# TRUST-04G candidate implementation assessment

2026-11-16. TRUST-04G read-only research and documentation. No cryptographic execution, dependency changes, new trust, owner approval or independent cryptographic sign-off. Existing frozen proposals remain unchanged.

## Decision summary

No drop-in implementation is selected as fully matching the frozen profile.
Recommend **D, a layered boundary, for independent review**, with a specific research
lead: canonical A/R decoding with re-encoding equality and torsion-free checks from
curve25519-dalek, A-only identity exclusion, canonical scalar checks, and documented
pure equation verification. An ed25519-dalek ordinary verifier is a source-supported
candidate equation component after these checks; its verify_strict method is not a
substitute because it excludes identity R. This is a composition to review, not
approved code, a dependency lock, a Python integration selection or a tested oracle.
No unaudited field arithmetic is proposed. Selection remains conditional on exact
API, features, artifact, maintenance, reviewer and runtime evidence.

The complete frozen predicates are F-A01–F-E03 in the
[TRUST-04F profile](iam03c-trust04f-strict-ed25519-normative-profile.md).
See the [source ledger](iam03c-trust04g-source-level-verification-evidence.md) for
exact versions/functions and evidence limits. SOURCE_CONFIRMED means source-level
support, never proof of installed behavior. Current version status is not inferred
from a historical release's existence.

## Candidate identities and classifications

| Candidate | Exact evaluated scope | Classification | Principal disposition |
| --- | --- | --- | --- |
| A PyCA/OpenSSL | cryptography 50.0.2 / recorded OpenSSL 4.0.3, Python 3.10.12 | INSUFFICIENT | Saved identity-A acceptance contradicts profile; internal backend path unresolved |
| B libsodium | Versioned 1.0.20-RELEASE historical sources and 1.0.22-RELEASE current-source review | INSUFFICIENT as detached-verifier drop-in | Point validator is separate; detached verifier excludes permitted identity R. Useful validation component research only |
| C strict verifier | ed25519-dalek 2.2.0 verify_strict, curve25519-dalek 4.1.3 predicates | INSUFFICIENT as unchanged strict entry point | Explicit R small-order rejection conflicts with identity allowance; low-order check alone is not full subgroup check |
| D layered validation + vetted equation backend | Reviewed composition using existing point/scalar APIs and ordinary pure verifier; alternative PyCA equation component conditional | POTENTIALLY_SUITABLE | Source supports expressing required predicates without writing curve arithmetic; complete reviewed composition/runtime still absent |
| E separately maintained reviewed reference | No exact full-profile audited reference established | MORE_EVIDENCE_REQUIRED | Reference may help oracle independence; no need to invent a new curve implementation |

No candidate is production-approved. An unsuitable entry point is rejected for this
profile, not declared an insecure general-purpose library. A later version must be
reviewed separately, not silently substituted.

## Full evaluation matrix

S IDs refer to the companion source ledger. P means proposed composition, U means
unverified. These entries are bounded by inspected source/build features; no new
runtime tests were performed.

| Criterion | A PyCA/OpenSSL | B libsodium | C dalek strict | D layered composition | E independent reference |
| --- | --- | --- | --- | --- | --- |
| Maintenance / supported release | Official security/release sources exist; 50.0.2 environment historical; current support clearance pending | Release page lists 1.0.22; 1.0.21 reports point-validator fix; not blanket security clearance | Active official repository/docs exist; reviewed 2.2.0/4.1.3 support window not established | Inherits component and binding maintenance, U | No selected maintained artifact |
| Provenance | Official PyCA tag; recorded wheel lock | Official release tags/source | Official dalek tags; Cargo metadata | P exact tag/commit/features/artifacts required | U repository/release |
| A canonicality | Not established by API constructor | Validator has explicit check; review helpers/round trip | Decompression alone not canonical acceptance | P decompress+canonical recompression equality | U |
| A on-curve | Complete predicate U | Source validator explicitly checks | Decompression source supports | P vetted decompression | U |
| A nonidentity | Confirmed acceptance gap on tcId152 | Small-order rejection in validator/verifier source | Explicit small-order rejection | P identity check on A after valid decoding | U |
| A subgroup | U | Separate validator main-subgroup check; detached verifier not full proof | No full torsion-free gate in strict entry point | P is_torsion_free, not merely not-small-order | U |
| R canonicality | U complete profile | Detached verifier compares recovered encoding; API composition review needed | Encoded expected-R comparison source | P round-trip equality on exact R bytes | U |
| R on-curve | U complete profile | Successful equation comparison source, not standalone public predicate | strict decompresses R | P explicit decompression | U |
| R subgroup | U | Detached verifier does not establish full standalone subgroup gate | strict small-order test insufficient for full H | P is_torsion_free on R | U |
| R identity allowance | No dedicated independent positive | Detached verifier rejects small-order R: mismatch | verify_strict rejects small-order R: mismatch | P no R-only nonidentity rule; ordinary equation API needs positive proof | U |
| S bounds | Some invalid-vector rejections; full bounds U | Source canonical scalar gate unless ED25519_COMPAT | Canonical check unless legacy_compatibility | P exact public scalar gate plus backend; forbid legacy features | U |
| Equation | PyCA delegates; OpenSSL internal equation U | Reconstructs S B - k A and compares encoded R in inspected source | RCompute reconstruction source | P documented ordinary pure E1 plus all predicates | Must independently establish E1/E8 |
| Python integration | Existing tested isolated environment | Native binding/artifact selected API availability U | Rust library; no selected Python binding/wheel | FFI/subprocess boundary choice requires separate review, not new service now | Independent language acceptable but not operational |
| Security audit | No exact full-profile independent audit acquired | No exact-version/profile audit acquired | Historical 2019 Quarkslab partial library audit, not this composition | No audit of proposed composition | Exact independent review required |
| Test vectors | Saved RFC3 +152/210, not full conformance | Published interoperability context; no local candidate tests | Published library tests; not executed/reconciled here | Need full 210, RFC3, A/R/S edges and26 project cases | Must have independently verified oracle |
| Supply chain | Existing four-wheel lock unchanged | Native build flags/binding and fixed-version provenance pending | Rust compiler/lock/features/architecture and Python packaging pending | Combined dependencies and FFI expand review | Exact artifacts and independent ownership pending |
| Licensing | Prior PyCA provenance; transitive compatibility review pending | ISC LICENSE source; binding/transitives pending | BSD-3-Clause Cargo declarations; full transitive review pending | Combined obligations pending legal/project review | U |
| Remaining gap | Full admissibility and exact backend guarantees | Identity R and full profile composition; old-validator fix | R identity mismatch and subgroup composition | Independent review, reproducible artifacts, tests, support and binding | No vetted complete reference identified |

## Why preprocessing is conditional, not magic

If canonical A and R are independently proven in H=<B>, and S in [0,L), then
D=[S]B-R-[k]A is in H. Because gcd(8,L)=1, [8]D=O iff D=O. E1/E8 equivalence thus
uses assumptions already present in the frozen candidate. It fails as a justification
when decoding/subgroup gates are missing or silently normalize original bytes.
A precheck cannot correct a backend's wrong hash transcript, wrong mode, ignored
message, broken arithmetic, extra acceptance/rejection restrictions or build defects.
No wrapper may bypass an identity-R backend failure and declare the equation valid.
Documented implementation behavior plus independent authorized tests are still needed.

A is an admissible point only after canonical/on-curve/H/nonidentity checks. It is
an admissible trust anchor only after independent exact enrollment and provenance;
then eligibility additionally needs current policy, mapping, revocation and time.
R's H membership permits O; S's range admits zero, but not every in-range tuple
satisfies the equation. No provider/custodian ID, public-key length or crypto PASS
establishes any of those later trust properties.

## Selection blockers and next recommendation

External source review supports continuing D design/source review, not selecting
new packages. Need independently named reviewer, exact source-to-binary mapping,
complete transitive/feature lock, supported runtime/binding, release/advisory review,
R=O positive and adversarial oracles, authorized full compatibility run and golden
review. Reference implementations using the same underlying arithmetic do not
provide independent cross-backend evidence merely through different wrappers.
Do not implement a new curve library or relax frozen requirements to obtain a match.
