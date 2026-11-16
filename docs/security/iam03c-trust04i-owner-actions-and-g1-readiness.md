# TRUST-04I — Owner actions and G1 readiness

**Status as of 2026-11-16:** design packet prepared; owner decisions remain pending; reviewer not appointed. Documentation completion does not authorize implementation.

## Owner actions, in order

1. Confirm/reject D04F-01 through D04F-06 below; each remains **PROPOSED — NOT APPROVED**.
2. Appoint/contract a qualified independent reviewer and approve the [statement of work](iam03c-trust04i-independent-reviewer-statement-of-work.md).
3. Supply the frozen specification, evidence assets, source identities, and exact review scope; do not claim artifact/runtime evidence not present.
4. Receive and authenticate the reviewer report using the [decision record](iam03c-trust04i-review-evidence-and-decision-record.md).
5. Resolve conditions and obtain independent closure evidence. A prototype author may not self-close a cryptographic finding.
6. Only then decide, through a separate explicit authorization, whether a TEST-only prototype may be implemented and executed.

No reviewer is appointed by this package, and preparing it does not authorize contacting candidates. No owner approval is implied by the task.

## D04F decision register

| Decision | Recommendation for owner | Supporting evidence and uncertainty | Independent reviewer input | Owner action / effect if rejected | Status |
|---|---|---|---|---|---|
| D04F-01 A admissibility | Reaffirm exact canonical/on-curve/H/nonidentity A and independent enrollment | Frozen anchor contract and 04F; 04G source offers predicates, not binary proof | Confirm predicate semantics, aliases, mixed-order and identity tests | Explicitly accept or reject; rejection blocks this profile | PROPOSED — NOT APPROVED |
| D04F-02 R/S admissibility | Preserve canonical/on-curve/H R with identity permitted; exact S in `[0,L)` | Dalek strict path rejects small-order R; ordinary-path identity behavior untested; scalar legacy feature risk | Confirm R identity and S edge behavior in exact composition | Explicitly accept or reject; rejection requires a separately reviewed profile decision, not silent change | PROPOSED — NOT APPROVED |
| D04F-03 equation | Use E1 as reference; allow E8 equivalence only with proof under full predicates | 04G source supports candidate E1 path; E1/E8 equivalence is analytical, not independent sign-off | Verify algebra, transcript and exact API behavior | Select/reject only after evidence; unresolved equation blocks prototype | PROPOSED — NOT APPROVED |
| D04F-04 boundary | Evaluate H-COMP-1 layered validation plus ordinary pure verifier; no strict shortcut/custom arithmetic | 04G/H are source/design proposals; R=identity and artifacts untested | Assess composition, APIs, feature graph and backend | Approve for assessment or reject; no automatic package choice | PROPOSED — NOT APPROVED |
| D04F-05 independent review | Require qualified independent cryptographic source/composition review and independent golden review | No reviewer appointed, no sign-off | Reviewer reports scoped findings and conditions | Owner appoints reviewer; without review G1 stays blocked | PROPOSED — NOT APPROVED |
| D04F-06 corrective TEST scope | After reviewer acceptance, issue a separate narrow authorization for exact TEST files, artifacts, toolchain and tests | TRUST-04D authorization does not extend to H-COMP-1 or TRUST-05; 58 cases and all project goldens incomplete | Reviewer evaluates proposed test plan, not grants permission | Owner must explicitly authorize each implementation/execution boundary; rejection leaves NO-GO | PROPOSED — NOT APPROVED |

## Draft future TEST authorization boundary

Not active. A future owner authorization should identify the exact reviewer-approved composition, immutable source commits, checksummed artifacts, complete lock/features, compiler/Cargo/target/build profile, isolated TEST location, allowed files, and acquisition/build permissions. It should explicitly permit or forbid offline implementation and execution; enumerate all 3 RFC vectors, all 210 original Wycheproof records, all 26 V04 cases and independent golden derivation; require A/R/S/equation, identity-R, quorum, revocation, binding and frozen diagnostic tests; and define where outputs may be written.

Require no network during verification; no project/system environment modification; no production/customer keys, databases, services, enrollment, recovery, operational IAM imports, or production trust. Stop on an unexpected dependency/feature, unpinned source/artifact, reviewer rejection/condition not closed, invalid identity-R reasoning, profile mismatch, unexpected vector behavior, environment leak, or need to alter frozen requirements. A future authorization must address whether corpus collection continues after a mismatch; absent explicit collection permission, stop on first blocking discrepancy. No TEST authorization is granted here.

## Readiness gates

| Gate | Current assessment | Why it is not passed |
|---|---|---|
| Design review packet | READY_FOR_INDEPENDENT_REVIEW (packet only) | H-COMP-1 and evidence can be presented; this is not reviewer acceptance |
| Normative profile | Proposed and traceable | D04F-01..03 remain pending owner decision; identity-R conformance unresolved |
| Dependency/artifacts/toolchain | INCOMPLETE | Tags are not commit/artifact pins; full lock, compiler, features, build target and reproducibility absent |
| Runtime composition | NOT VERIFIED | No H-COMP-1 build or runtime tests; ordinary verifier identity-R behavior unknown |
| Independent reviewer | NOT APPOINTED | No authentic review report |
| Vectors | INCOMPLETE | RFC3 historical pass only; 58 Wycheproof NOT_RUN; all 26 project cases NOT_READY as goldens |
| G1 technical readiness | BLOCKED | Reviewer sign-off, exact reproducible artifact, identity-R and full strict tests missing |
| G1 implementation authorization | PENDING | No owner grant for H-COMP-1 implementation; TRUST-04D grant was narrower |
| Operational IAM / production | NO-GO | No production trust, persistence/freshness, admission, or execution verification |

## Recommended next milestone

Owner appoints a qualified independent reviewer and authorizes the actual external assessment against the four TRUST-04I documents and linked evidence. Do not substitute another self-authored design milestone for that review. After receiving the reviewer’s authenticated outcome and closing any conditions, the owner may separately consider a bounded corrective TEST prototype authorization.

## Status

**INDEPENDENT REVIEWER: NOT APPOINTED**

**INDEPENDENT CRYPTOGRAPHIC SIGN-OFF: PENDING**

**G1 TECHNICAL READINESS: BLOCKED**

**G1 IMPLEMENTATION AUTHORIZATION: PENDING**

**D04F-01..06: PROPOSED — NOT APPROVED**
**TRUST-05 / OPERATIONAL IAM / PRODUCTION: NO-GO**
