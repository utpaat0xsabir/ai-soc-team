# TRUST-04F owner decisions and G1 review

2026-11-16. TRUST-04F documentation-only review. Existing frozen proposals are unchanged; no implementation or independent cryptographic sign-off is claimed. All D04F decisions are PROPOSED — NOT APPROVED.

## Findings and decisions

All sources required for this review were present. Frozen A/R/S predicates are
reviewable without changing wire bytes or diagnostics. Internal equation form is
underspecified but has an equivalent acceptance set on the required prime subgroup;
this is a proposed implementation clarification, not a security-critical contradiction.
No fully selected implementation boundary currently satisfies the evidence gate.

| Decision | Proposed exact scope | Evidence and acceptance conditions | Status |
| --- | --- | --- | --- |
| D04F-01 A admissibility | Reaffirm canonical raw32/on-curve/H/nonidentity A plus independent exact enrollment | F-A01–04 and tcId152; no identity blacklist or weak/mixed-order exception | PROPOSED — NOT APPROVED |
| D04F-02 R/S admissibility | Reaffirm canonical on-curve R in H, allow identity iff all checks/equation pass; exact LE S in [0,L) | F-R01–03/F-S01–02; no S!=0/R!=O addition; independent positive and adversarial assets | PROPOSED — NOT APPROVED |
| D04F-03 equation | E1 reference; E8 backend only after documented full-predicate equivalence and mode review | F-E01–02 proof and reviewed enforcing APIs; never cofactor-only permissiveness; no claim about OpenSSL internals | PROPOSED — NOT APPROVED |
| D04F-04 boundary | Further evaluate vetted predicate+backend composition B in dedicated isolated TEST boundary D; independent comparator if compatible | Full A/R/S API/source map, exact R-identity behavior, maintained artifacts/FFI review; no implementation selected or authorized yet | PROPOSED — NOT APPROVED |
| D04F-05 independent review | Owner appoints qualified non-author crypto reviewer and independent golden reviewer | Qualifications, conflicts, revision-specific findings/verdict and later code review per review criteria; Codex self-review insufficient | PROPOSED — NOT APPROVED |
| D04F-06 corrective TEST authorization | Later explicit scoped grant for approved corrective harness, offline reproduction and full corpus; golden derivation separately conditional | Name files/runtime/pins/network acquisition/outputs/stop rules; review before code; preserve early frozen diagnostics despite conceptual chain; permit remaining58 only after case152 resolution; no automatic signing or TRUST-05 | PROPOSED — NOT APPROVED |

Approval of these document proposals must not be inferred from the request to prepare
them. Reaffirmation decisions do not invent new frozen predicates. No production
A01/A04 approval, broader A01-TEST/A04-TEST approval or approval-record edit occurs.
A02/A03/A05 remain pending. D04E proposals remain historical unapproved proposals.

## Technical versus authorization readiness

| Gate | Current result | Required next evidence |
| --- | --- | --- |
| Frozen wire, canonical bytes, frame, digest construction and 15-code priority | Unchanged documented proposal | Independently reviewed implementation and literal assets later |
| A/R/S acceptance | REVIEWED specification; implementation incomplete | Vetted full predicate map; R=O acceptance preserved |
| Equation | RECOMMENDED_FOR_REVIEW | Independent E1/E8 equivalence/source/mode review; backend provenance |
| Dependency/backend strict compatibility | BLOCKED by recorded identity-A acceptance | Reviewed corrected boundary and separately authorized passing tests |
| Independent anchors and 2-of-3 | Candidate contract unchanged | Invalid-material enrollment rejection plus policy negative tests |
| Adversarial corpus | 58 NOT_RUN | Authorized complete 210-case disposition with original native semantics |
| Project goldens | All26 NOT_READY | Independent literal derivation/review and full frozen outcomes |
| Independent security review | PENDING | Named reviewer(s), source/code-specific approval |
| G1 implementation authorization | PENDING | Explicit separate owner decision; never inferred from TEST results |

G1_TECHNICAL_READINESS: BLOCKED. G1_IMPLEMENTATION_AUTHORIZATION: PENDING.
A complete documentation review is not a compatible cryptographic implementation.
No cryptographic result may become operational IAM authority, role grant, approval
or current freshness. Self-hosted and SaaS customer control, distinct custodians,
independent pins and no provider inheritance remain mandatory.

## Recommended next milestone and stop conditions

Recommend separately authorized TRUST-04G independent cryptographic design/source
review and exact candidate/API selection. Only if that review and D04F-01–06 gates
are explicitly satisfied should a narrowly scoped corrective TEST implementation
and execution milestone be authorized. Do not resume old tests, generate goldens or
begin TRUST-05 now. Review scope can be approved without approving later code/tests.

Stop future work on missing predicate APIs, unsupported/runtime artifacts, undocumented
backend reliance, over-rejection of allowed R, identity-only blacklist, independent
oracle/reviewer absence, changed frozen semantics or any operational integration.
No hand-written curve arithmetic is proposed as production-ready. No packages,
versions, identities or reviewers are silently substituted.

## Validation performed and preservation

Read AGENTS.md and handoff, inspected Git status and both diff whitespace checks.
The handoff's older task scope is historical; this explicit owner milestone supplies
the four-file documentation scope and does not alter the handoff. Existing source,
fixtures, evidence and staged work were inspected read-only. Preservation uses raw
byte snapshots, not hashing. Only the four new TRUST-04F reports may differ from
preflight; Git index must remain byte-identical.

Validate local document links, requirement IDs, all26 project IDs and all20 supplemental
threat IDs; inspect remaining58 inventory; check whitespace separately for new
untracked reports and run git diff --check and git diff --cached --check. No pytest,
cryptographic imports/execution, hashing/signing, installations, DB/services, Docker,
key generation, operational configuration or source changes are permitted/performed.

Companions: [profile](iam03c-trust04f-strict-ed25519-normative-profile.md),
[options/threats](iam03c-trust04f-verification-boundary-options.md),
[independent review/tests](iam03c-trust04f-independent-review-and-test-criteria.md).
