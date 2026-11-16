# TRUST-04A G1 authorization checklist

2026-11-16. **Review preparation only. Unchecked means unmet, not implicitly waived.**
[Owner decision package](iam03c-trust04a-owner-decision-package.md),
[dependency/vector evidence](iam03c-trust04a-dependency-and-vector-review.md),
[implementation boundary](iam03c-trust04a-trust05-implementation-boundary.md).

## 1. Technical readiness versus approval

The checked technical items below mean **reviewed proposed specification**, not
approved implementation or executed crypto. TRUST-04 remains a PROPOSED FREEZE;
its READY_FOR_OWNER_REVIEW status is not G1 technical acceptance or authorization.

- [x] ROOT_POLICY-only TEST protocol/body/manifest/key-set fields identified and counted against actual TRUST-04 documents.
- [x] Exact label/NUL/U64BE/canonical frame and acyclic digest rules documented; TRUST-02 serializer unchanged, not JCS.
- [x] Two-of-three customer-only TEST quorum, explicit context/anchor source, lifecycle/time and every-supplied-signature behavior specified.
- [x] Fifteen-code diagnostic precedence, framing/limit exceptions, fixed non-authorizing output and 26 future cases specified.
- [x] Resource limits and 20-threat traceability documented, with custody/host/rollback/operational limitations retained.
- [x] PyCA candidate and required API behavior identified; local metadata assessment made without package import.
- [ ] Exact maintained Python-3.10-compatible library/backend version/artifact hashes and licensing/provenance accepted; numeric supported range is not verified.
- [ ] Current security/support/advisory review completed under separately authorized evidence acquisition; offline inspection does not establish it.
- [ ] Established APIs demonstrably enforce strict A/R/S profile across independent published/adversarial vectors; no homemade arithmetic/blacklist or fallback.
- [ ] Exact approved RFC/adversarial artifacts, releases/licenses/digests and explicit strict acceptance mapping available.
- [ ] Independent project canonical/body/frame/preimage/digest literals and valid two/three-signature fixtures materialized, checked by a second derivation and approved.
- [ ] Negative mutations/cap boundaries/counters pinned independently and ready to consume without same-UUT expected generation.

**G1 TECHNICAL READINESS: NOT_READY.** Missing dependency and golden-asset evidence
blocks proceeding as if the verifier could already satisfy its acceptance profile.
No confirmed security-critical wire inconsistency was found; if one is later found,
stop and request a spec revision rather than silently resolving it in code.

## 2. Explicit owner authorization — all pending

- [ ] A01-TEST proposal explicitly accepted for the exact next milestone; no inference from TRUST-02 structural-design assumptions.
- [ ] A04-TEST proposal explicitly accepted for the exact four TRUST-04 document revisions/content digests and required exclusions.
- [ ] Exact future code/test/asset module paths in the implementation-boundary document accepted; no automatic edits to existing trust/IAM files.
- [ ] DEP-TEST accepted for exact dependency/artifacts/environment; installation or requirement/lock-file changes explicitly authorized if needed, with separate paths and no implicit network action.
- [ ] VEC-TEST accepted for independent source acquisition/derivation and any project signing from published non-production material, or approved independently supplied assets; no keys/signatures generated under this review.
- [ ] Future focused/selected offline test and compilation execution scope explicitly accepted; no unrestricted pytest or protected DB/service tests.
- [ ] Owner record identifies owner/date, selected decisions, accepted revisions/evidence, exclusions, one-milestone scope and renewal conditions; authenticity verified independently of candidate proof.
- [ ] Production A01/A04 remain PENDING and A02/A03/A05 remain PENDING; no approval register changes implied.

**G1 AUTHORIZATION: PENDING.** Each proposal is PROPOSED — NOT APPROVED. Checkmarks
in section 1, a completed report or an owner request to prepare documentation are
not implementation consent. If approval evidence is ambiguous, keep pending.

## 3. Production restrictions — mandatory, not waivable by a test result

- [x] No real customer/root/custodian enrollment, root ceremony, new/production key generation or trust-anchor establishment.
- [x] No provider master credential, provider-only/customer-authority substitution or SaaS recovery delegation.
- [x] No structural/synthetic promotion, live current-authority evidence, IAM ALLOW or permission from a signature.
- [x] No admission/policy/auth/provider/API/audit/analyst changes, execution gate or external response/Shuffle/Wazuh/Ollama integration.
- [x] No PostgreSQL/model/schema/migration/role/database/container access; ai_soc and ai_soc_test protected.
- [x] No production deployment, signing/recovery/checkpoint/identity service, commit/push or history rewrite.

These boxes record retained prohibitions, not a grant to implement their opposites.
Even a future approved TEST verifier cannot clear production gates by returning
SignatureEvidence. Missing a production authority source is a reason not to support
production, never permission to fabricate one for this subset.

## 4. Blocking conditions, disposition and next task

| Blocker / open decision | Evidence needed to clear | Current disposition |
| --- | --- | --- |
| B01 Dependency selection/support/provenance | Exact package/backend/artifacts, Python 3.10 support, current advisory/license review and separate install/pin scope if needed | IMPLEMENTATION_BLOCKER; unverified, not approved |
| B02 Strict-profile compatibility | Independent conformance proof for canonical prime-order key/point/scalar behavior with established APIs | IMPLEMENTATION_BLOCKER; not tested, not proven impossible |
| B03 Independent vectors/assets | Approved source artifacts and reviewed literal project bytes/digests/signatures/mutations; no same-UUT expected generation | IMPLEMENTATION_BLOCKER; missing |
| B04 Owner A01-TEST/A04-TEST/code/test decisions | Explicit scoped owner record | OWNER_DECISION_REQUIRED; pending |
| B05 Dependency/vector preparation scope | Exact separate authorization for evidence acquisition, package/artifact changes or test signing if required | OWNER_DECISION_REQUIRED; pending |

Recommend **remaining blocker resolution and owner review**, not automatic TRUST-05.
Prepare/authorize the smallest separate dependency/profile/vector evidence activity,
obtain exact owner decisions, then reassess G1. If any security-critical wire issue,
unsatisfiable profile, request-controlled trust source or IAM behavior dependency
appears, stop and report. No blocker is waived by documentation completion.

## 5. Checks performed for TRUST-04A

Only source/document and static metadata reads, reference/count/link/status checks,
new-file whitespace checks, git diff --check and original-content/index preservation
checks. No project or cryptographic library import/execution, pytest/compilation,
keys/signatures, crypto tests, network/service/DB/Docker access or package installation.
File-content hashes used for preservation are not signed-message/vector generation.
Historical TRUST-02 results were not rerun. Only the four authorized new documents
are created; existing documents, source, tests, configuration and index are preserved.

**IAM-03C-TRUST-04A: COMPLETE — documentation review only**  
**G1 TECHNICAL READINESS: NOT_READY**  
**G1 AUTHORIZATION: PENDING**  
**A01-TEST: PROPOSED**  
**A04-TEST: PROPOSED**  
**A01/A04 PRODUCTION: PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**  
**NEXT STEP: Recommendation only**
