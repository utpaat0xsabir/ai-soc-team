# TRUST-04E owner decisions and G1 review

2026-11-16. Documentation-only TRUST-04E. No cryptographic execution, hashing, signing, installation or profile amendment. All proposed decisions are unapproved.

## Outcome

Investigation complete; discrepancy confirmed from original and saved evidence.
No cryptographic execution or correction occurred. Root cause is confirmed only at
acceptance-boundary level: the library-only path lacks an effective project-required
nonidentity-key gate on this input. Internal OpenSSL equation/path remains unresolved.
See [evidence](iam03c-trust04e-case152-evidence-reconstruction.md),
[boundary alternatives](iam03c-trust04e-strict-ed25519-verification-boundary.md) and
[all-case plan](iam03c-trust04e-corrective-test-and-vector-plan.md).

## Proposed decisions — no approval granted

| ID | Proposed exact owner decision | Evidence / acceptance / exclusions | Status |
| --- | --- | --- | --- |
| D04E-01 | Reaffirm A canonical/on-curve/nonidentity/prime-order; R canonical/prime-order with specified identity exception; S<L; pure equation | Frozen section 4 and case 152; no acceptance weakening, wire changes or approval of a permissive corpus policy | PROPOSED — NOT APPROVED |
| D04E-02 | Prefer evaluation of vetted full validation boundary B; compare independently reviewed verifier C | Exact APIs for A, R, S, equation and modes; review supply chain, Python integration, licenses/maintenance/advisories; not selecting/installing a package yet | PROPOSED — NOT APPROVED |
| D04E-03 | Require independent cryptographic implementation/composition review before corrective execution | Reviewer competent in Ed25519 subgroup/encoding semantics, independent of correction author; exact acceptance checklist and source pins; no homemade arithmetic | PROPOSED — NOT APPROVED |
| D04E-04 | Separately authorize only a narrow corrective TEST harness after reviewer acceptance | Explicit files, runtime, dependencies/artifacts, offline tests, stop rules and outputs; separate PyPI/install permission if needed; no IAM code, enrollment, production or TRUST-05 | PROPOSED — NOT APPROVED |
| D04E-05 | Resume full corpus and golden derivation only after reviewed strict compatibility and independent-oracle plan | Case 152 rejected by strict boundary, RFC positives preserved, all forbidden/allowed classes covered; explicit complete-corpus and signing authorization; no self-generated oracle or automatic G1 approval | PROPOSED — NOT APPROVED |

These proposals are limited to the next review/TEST milestone, not enduring root trust
or production approval. Customer enrollment, independent custody, optional recovery,
operator identity and operational provenance/freshness remain independently gated.
A01-TEST/A04-TEST are not approved beyond previously authorized TRUST-04D activity.
Production A01/A04 and A02/A03/A05 remain pending. Existing approval records untouched.

## G1 evidence and gates

| Gate | Current evidence | Status / missing acceptance |
| --- | --- | --- |
| Frozen wire/canonical/frame/digests and fifteen-code order | Existing TRUST-04 documents; unchanged | Specification exists, no cryptographic conformance inference |
| Independent TEST expected context/pins and two-of-three | Existing candidate contract | No new enrollment or operational authority; invalid pins must reject |
| Runtime and dependency | Recorded verified wheels and Python TEST exception in TRUST-04D | Historical reproducibility evidence; no blanket future package or runtime approval |
| Strict backend compatibility | Case 152 accepted forbidden identity A | BLOCKED; B/C predicate and equation review plus authorized passing tests required |
| Full adversarial corpus | 152 executed; 58 unexecuted | BLOCKED; preserve native semantics and prove full profile |
| Independent project goldens | None generated; 26 cases inventoried | NOT_READY; independent literals, derivation/review and signatures pending |
| Owner implementation permission | Only historical scoped TEST activity | PENDING; no A01/A04 implementation or TRUST-05 grant |

**G1_TECHNICAL_READINESS: BLOCKED**

**G1_IMPLEMENTATION_AUTHORIZATION: PENDING**

Recommended next milestone: separately authorize TRUST-04F strict-boundary selection
and independent design/source review; include corrective TEST implementation/execution
only after D04E-01–05 scope and reviewer prerequisites are explicitly accepted.
Do not resume TRUST-04D tests or start TRUST-05 from this document.

## Validation and limits

Only evidence reads, primary public-document research, metadata/byte comparison,
inventory, local-link/whitespace checks, git diff --check and byte-for-byte preservation
checks were authorized. No hashing, signing, verifier import/run, test suite, package
installation, database/service access or key generation. Snapshot comparison uses
original bytes, not newly computed digests. Existing files and Git index must match
preflight exactly; four new reports are the only permitted additions. Documentation
completion is separate from validating a future implementation or granting approval.

No claim of production exploit, all-version library vulnerability, full adversarial
conformance, custodian independence, authentic live revocation, database rollback
resistance or operational authorization follows from this evidence.
