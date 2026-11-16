# TRUST-04B G1 evidence and owner decision brief

2026-11-16. **Documentation and read-only metadata review only.**
[Dependency assessment](iam03c-trust04b-dependency-assessment.md),
[compatibility matrix](iam03c-trust04b-ed25519-compatibility-matrix.md),
[26-vector provenance inventory](iam03c-trust04b-golden-vector-provenance.md).

## 1. Findings and evidence boundary

The required TRUST-03/04/04A sources were present. AGENTS.md, the historical handoff,
Git state, dependency declarations, relevant TRUST-02 sources/tests and frozen
specifications were inspected or rechecked against unchanged source content.
No missing source or security-critical wire contradiction was identified. No frozen
specification, source, test, dependency declaration or approval record was changed.

| Evidence class | Finding |
| --- | --- |
| VERIFIED_LOCAL_METADATA | No direct cryptography declaration/pin or matching project lock/constraint file; inspected .venv has no cryptography directory/metadata and disables system packages |
| VERIFIED_LOCAL_METADATA | System metadata says 3.4.8; OS package record says installed python3-cryptography 3.4.8-1ubuntu2.4, amd64. Package dependencies declare libssl3/CFFI/Python constraints, not actual loaded backend identity |
| UNVERIFIED | Effective runtime selection, complete transitive graph/other copies, selected backend/provider/build, package integrity/reproducibility and all strict mathematical behavior |
| EXTERNAL_VERIFICATION_REQUIRED | Current official release/support/advisory/Python/wheel/build/licensing evidence; source locations and required questions listed in dependency section 5 |
| SOURCE_SUPPORTED | Existing TRUST-04 defines 17 body fields, acyclic digests, exact frame, independent TEST source, two-of-three and 15 diagnostics. Existing static API observations prove no signature behavior |
| MISSING | Approved published artifact bundle, independent project literal bytes/hash/signature assets and named independent review for all 26 cases |

The distro revision refines the earlier upstream-version observation, not a safety
verdict. Do not infer absent/present security fixes from 3.4.8 alone or approve the
system package merely because installed. Missing current external information is
reported explicitly; no guessed latest version, supported range or advisory result
is substituted. No established-library incompatibility was proved either.

## 2. Candidate decision and G1 reassessment

**DEPENDENCY_CANDIDATE:** PyCA cryptography.  
**Assessment:** MORE_EVIDENCE_REQUIRED.  
**Approval:** PROPOSED — NOT APPROVED.

Select an exact reviewed Python-3.10-compatible maintained release/backend/artifact
set only after authoritative support/security/provenance review and strict-profile
conformance evidence. No numeric range or installation is approved. A supported
release line, compatible platform artifacts and strict behavior must all be evidenced;
one does not imply the others. If no combination meets the frozen profile, stop
for dependency/spec review; do not weaken signatures or implement custom arithmetic.

| G1 requirement | Current assessment | Needed next evidence/decision |
| --- | --- | --- |
| Frozen ROOT_POLICY wire format | Reviewed proposed specification, unchanged; no contradiction found | Owner accepts exact revisions/content digests, then independent golden byte agreement |
| Independent TEST anchor contract | Closed read-only pre-registered TEST source/context specified, not an operational source | Accepted fixture/pin provenance and explicit A01-TEST scope; no request-controlled self-bootstrap |
| Frozen error precedence | Fifteen codes and extraction/limit exceptions specified | Independently reviewed exact mutations/counters, later tests |
| Dependency candidate | PyCA identified; MORE_EVIDENCE_REQUIRED | Exact reviewed version/backend/hash/compatibility/support evidence and DEP-TEST decision |
| Strict Ed25519 compatibility | UNVERIFIED | Positive/adversarial/profile conformance on exact library/backend under separate test authorization |
| Independent golden vectors | NOT_READY; all 26 cases specified, no approved complete assets | Pinned published corpus plus independently derived project bytes/digests/signatures/review |
| A01-TEST | PROPOSED — NOT APPROVED | Explicit owner record for exact TEST custodians/anchors/quorum/fixtures |
| A04-TEST | PROPOSED — NOT APPROVED | Explicit owner record for frozen TEST verifier/output/code/test exclusions |

**G1 TECHNICAL READINESS: NOT_READY. G1 AUTHORIZATION: PENDING.**
TRUST-04's READY_FOR_OWNER_REVIEW described a specification-review package, not
execution permission. This assessment confirms TRUST-04A's technical gaps; it does
not revoke or grant any owner decision. Plans/metadata alone cannot clear G1.

## 3. Proposed owner decisions — independently reviewable

Each proposal below is **PROPOSED — NOT APPROVED**. Scope is one explicitly accepted
TEST evidence/implementation activity; any version/profile/artifact/pin/scope change
requires renewed review. No deadline or consent is inferred from this report.

### DEP-TEST — dependency and evidence authorization

Proposed wording: accept PyCA as a candidate for further review only; separately
name the exact authoritative evidence acquisition allowed, then approve exact
library/backend/version/artifact constraints after review. State independently
whether package installation/declaration changes are permitted and whether offline
compatibility testing is permitted. Neither is authorized by this documentation task.
No network access follows automatically from a later test or installation decision.

Required evidence: official selected-version API/release/support/security/Python/
platform information, exact artifact/dependency/backend provenance, reproducible
pins and strict conformance plan/results. Current external gaps are listed in the
dependency document. Exclude system-package default reuse, hidden upgrades/builds,
FIPS assertions and custom arithmetic. An unfilled version placeholder is not an
approved constraint. Any requirement/lock-file path outside the isolated module/test
scope needs exact separate approval before modification.

### VEC-TEST — public asset acquisition and independent preparation

Proposed wording: separately authorize obtaining and reviewing exact RFC/adversarial
artifacts and independently preparing approved TEST golden bytes/hash/signature
assets. Project-frame signing with published non-production material requires its
own explicit permission or independently supplied approved signatures. No new root
keys, live custodians, production seeds or crypto activity are authorized here.

Required evidence: all ten acceptance criteria and 26 records in the provenance
document, exact sources/licenses/revisions and named reviewers independent of the
implementation under test. No same-implementation-only expected generation or
fake valid signature fixtures. Authority-source authenticity, real customer custody
and production approval are explicitly excluded.

### A01-TEST — TEST custodians, anchors and quorum only

Proposed wording: authorize the separately scoped TRUST-05 to use exactly three
approved customer-custodian TEST identities/public-key anchors with independent
expected context/pin fixtures and fixed two-of-three signature quorum. Approval
must name accepted fixtures and their independent provenance. Distinct TEST IDs
are not assertions of independent real people or real customer authority.

Exclude actual enrollment/ceremonies, new/production keys, recovery/rotation,
provider-recovery delegation, vendor master root and all operational activation.
Require DEP-TEST/VEC-TEST prerequisites and the exact code/test scope to be accepted
before implementation. **Production A01 remains PENDING.**

### A04-TEST — ROOT_POLICY non-authorizing verifier only

Proposed wording: authorize separately scoped TRUST-05 only for IAM-TRUST-SIGNED-1,
IAM-TRUST-ASCII-1, ED25519-PURE-1 and ROOT_POLICY-TEST-1, exact frozen bytes/digests/
resource limits, independent TEST anchors, fifteen-code precedence and immutable
non-authorizing TEST SignatureEvidence. ROOT_TRANSITION, ISSUANCE, CHECKPOINT,
production environments and provider-recovery members remain unsupported.

Require exact accepted specification revisions, reviewed dependency/assets and the
explicit isolated files/tests in the existing
[TRUST-05 boundary proposal](iam03c-trust04a-trust05-implementation-boundary.md).
Exclude operational imports, structural/synthetic promotion, permission grants,
current-authority output, admission/policy/provider/API/audit changes, identity,
DB/schema/roles, final execution gates and external response actions.
**Production A04 remains PENDING.**

## 4. Authorization checklist and stop conditions

- [ ] Separately authorize exact external evidence acquisition if desired; current no-network rule stays in force.
- [ ] Accept exact supported package/backend/artifacts and reproducibility/security review; no metadata-only approval.
- [ ] Separately authorize any installation/build/declaration change and later offline compatibility tests, with precise environment/file limits.
- [ ] Accept independent strict-profile conformance and golden assets with full provenance and reviewers.
- [ ] Explicitly decide A01-TEST and A04-TEST, accepted document/fixture digests and exact future code/test scope.
- [ ] Keep production A01/A04 and A02/A03/A05 pending; no source-of-authority or production deployment implied.

Stop on a newly discovered security-critical wire contradiction, an unenforceable
strict profile, untrustworthy source/expected provenance, request-selected keys,
need for changed IAM semantics or out-of-scope source/dependency/network/DB actions.
Do not implement permissive fallback, accept synthetic authority or alter frozen
rules to bypass a blocker. Missing local evidence does not justify pretending an
external review or conformance test occurred.

Next recommendation: separately authorize official dependency/vector evidence
acquisition and independent TEST compatibility/vector preparation, then reassess
G1 and obtain exact owner implementation decisions. Do not begin TRUST-05, install
anything, verify signatures or contact external sources automatically.

## 5. Validation and retained security restrictions

Only local documentation/source/metadata/reference/consistency/whitespace checks,
git diff --check and original-file/index preservation checks ran. Distribution
metadata was parsed without crypto imports; no cryptographic interfaces, signing-key and signature/
golden generation, pytest/compilation, package manager, network, database, Docker,
Wazuh/Ollama/other service operation occurred. File preservation hashes do not
constitute cryptographic test-vector generation. External links were not requested.

All four new documents are this milestone's only repository changes. Existing
tracked/staged/untracked work, TRUST-02 serialization, IAM contracts/policy/admission/
providers/false currency, approval records and security configuration are preserved.
The unusual root filenames are neither executed, staged nor deleted. No production
trust material is established or included.

**IAM-03C-TRUST-04B: COMPLETE — documentation/read-only review only**  
**DEPENDENCY ASSESSMENT: MORE_EVIDENCE_REQUIRED**  
**ED25519 COMPATIBILITY: UNVERIFIED**  
**GOLDEN VECTORS: NOT_READY**  
**G1 TECHNICAL READINESS: NOT_READY**  
**G1 AUTHORIZATION: PENDING**  
**A01-TEST: PROPOSED — NOT APPROVED**  
**A04-TEST: PROPOSED — NOT APPROVED**  
**A01/A04 PRODUCTION: PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**  
**NEXT STEP: Recommendation only**
