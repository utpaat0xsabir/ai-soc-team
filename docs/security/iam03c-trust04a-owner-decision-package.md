# TRUST-04A owner decision package

2026-11-16. **Documentation only. Every decision below is PROPOSED — NOT APPROVED.**
No request to prepare this package grants implementation approval. Production
A01/A04 and A02/A03/A05 remain pending; the existing approval register is unchanged.

Companions: [dependency/vectors](iam03c-trust04a-dependency-and-vector-review.md),
[TRUST-05 boundary](iam03c-trust04a-trust05-implementation-boundary.md),
[G1 checklist](iam03c-trust04a-g1-authorization-checklist.md).

## 1. Decision recommendation

The TRUST-04 package is reviewable, but **G1 TECHNICAL READINESS: NOT_READY** for
implementing and accepting the verifier. No security-critical wire contradiction
was established by this review; missing dependency/profile compatibility evidence
and independently approved golden assets are implementation blockers. No claim is
made that PyCA cannot satisfy the profile; it has not been demonstrated to do so.

TRUST-04's READY_FOR_OWNER_REVIEW classification is compatible with this result:
it assessed a proposed specification, not permission or technical evidence to run
cryptography. Do not treat its completion report or TRUST-02's historical 98/2,034
results as verification of signatures, real custodians or operational authority.

## 2. TRUST-04 consistency findings

Evidence references use the four existing documents: [wire](iam03c-trust04-root-policy-wire-spec.md),
[anchor](iam03c-trust04-anchor-and-verifier-contract.md),
[errors/vectors](iam03c-trust04-vector-and-error-matrix.md),
[readiness](iam03c-trust04-g1-readiness-review.md). These documents are not modified.

| ID | Classification | Evidence-based finding / disposition |
| --- | --- | --- |
| R01 | RESOLVED_IN_SPEC | Wire section 2 has 17 body fields; manifest has 14, manifest custodian 12, context 9 and snapshot 19. Grouped table rows expand to the stated counts. No missing body field was found |
| R02 | RESOLVED_IN_SPEC | Wire sections 3/5 define key fingerprint -> exact key-set projection -> manifest excluding only its own digest -> body/frame. Root-set digest remains in manifest hash. No digest depends on its enclosing digest/signatures |
| R03 | RESOLVED_IN_SPEC | ASCII/integer/time/UUID rules, explicit nulls, closed fields and domain/NUL/U64BE framing are specified; header is 33 bytes. TRUST02 bytes remain unchanged and are not claimed as JCS |
| R04 | RESOLVED_IN_SPEC | Independent expected context and pre-registered read-only TEST source precede key selection; no candidate key/pin/URL/boolean can create its own source. These are test assumptions, not established production trust |
| R05 | RESOLVED_IN_SPEC | Revoked supplied key/root denies before time/threshold/math; source revocation may be stricter than manifest. Source observation and body/supplied-key intervals are explicit, no implicit wall clock |
| R06 | RESOLVED_IN_SPEC | Fifteen ordered diagnostics, framing extraction exceptions and multi-fault examples are specified. Duplicate preflight precedes pin lookup; one eligible vote rejects before math; invalid third vote defeats success. No arbitrary arrival-order first-two shortcut |
| R07 | RESOLVED_IN_SPEC | 26 V04 cases and all 20 T03 threats are mapped. TEST SignatureEvidence is non-authorizing; rollout/rollback/current authority remain excluded |
| R08 | IMPLEMENTATION_BLOCKER | PyCA exact release/backend, support/advisory review and strict A/R subgroup/scalar acceptance evidence are missing. Constructor length checks/API presence are insufficient; no custom arithmetic or permissive fallback allowed |
| R09 | IMPLEMENTATION_BLOCKER | Approved RFC/adversarial source artifacts, complete literal project bytes/digests/signatures and independent review are absent. A future vector recipe is not an executable golden fixture |
| R10 | OWNER_DECISION_REQUIRED | A01-TEST/A04-TEST and exact code/test scope have no explicit owner approval. Prior structural-design assumptions authorize no verifier code |
| R11 | OWNER_DECISION_REQUIRED | No cryptography requirement/pin exists. Selecting/installing/pinning a dependency, especially changes outside trust/tests, needs separate exact authorization; local availability does not approve reuse |
| R12 | OWNER_DECISION_REQUIRED | Creating project-frame signatures from published non-production material needs a separate test-material decision, or independently supplied approved signatures. Verifier implementation must not create its own expected signatures |
| R13 | DEFERRED_OUT_OF_SCOPE | Real-person independence, signing displays, host integrity, live revocation, DB/checkpoint rollback, recovery, human identity, final gates and provider plaintext/runtime access are not solved by this subset |

Review clarifications already supported by the spec, not amendments: match custodian
correspondence by typed IDs rather than positional zip before canonical ordering;
preserve original bytes while comparing decoded UUID/hex/time values; parse leaf
shape before aggregate Pydantic validators so library error order does not replace
the prescribed diagnostics. Unknown fields and malformed primitives still reject.
The wrapper needs bounded parsing before calling TRUST-02's existing decoder;
that decoder alone is not evidence of preparse depth enforcement. All these are
future implementation acceptance checks, not changes to existing source behavior.

No essential source is missing. No new root assumption, IAM behavior change or
production source is required for a pure TEST diagnostic. If further review finds
a security-critical wire ambiguity, STOP and obtain a separately authorized spec
revision; do not resolve it in code or silently alter the frozen proposal.

## 3. Proposed decision A01-TEST

**Decision ID:** A01-TEST. **Status: PROPOSED — NOT APPROVED.**

Proposed owner wording:

> Authorize only the separately scoped IAM-03C-TRUST-05 offline TEST implementation to use three distinct customer-custodian fixture identities, a fixed two-of-three signature quorum, independently supplied registered TEST public-key anchors and exact independently approved ROOT_POLICY TEST fixtures. Distinct test IDs and keys do not establish distinct real custodians. This decision grants no customer authority and is effective only after the G1 technical prerequisites and exact file/test/dependency scope are explicitly accepted.

Exclusions: real customer/custodian enrollment or ceremony; new or production key
generation; root trust establishment; recovery/rotation implementation; SaaS-provider
recovery delegation; vendor master keys; production pin stores, issuer grants or
operational authority. Provider infrastructure identity supplies no customer vote.

Required evidence: accepted TRUST-04 document revisions, independently reviewed
TEST anchor/key/enrollment provenance, separate expected context, no duplicate key/
custodian/material votes, and explicit exclusions in code/import tests. No approvals
or actual custodian records are invented by this package.

Remaining risks: false fixture enrollment/host compromise, lack of real custody
independence and valid malicious two-key quorum. Scope ends at TRUST-05 completion;
changes to keys/pins/protocol/profile/dependency/test-material scope require renewed
review. It neither expires into permission nor carries forward into later phases.
**Production A01 remains PENDING.**

## 4. Proposed decision A04-TEST

**Decision ID:** A04-TEST. **Status: PROPOSED — NOT APPROVED.**

Proposed owner wording:

> Authorize only the separately scoped IAM-03C-TRUST-05 offline TEST verifier for IAM-TRUST-SIGNED-1, IAM-TRUST-ASCII-1, ED25519-PURE-1 and ROOT_POLICY-TEST-1 using the exact TRUST-04 body, framing, key-set/manifest digest DAG, independently supplied TEST anchors, fifteen-code diagnostic order and immutable non-authorizing SignatureEvidence. ROOT_TRANSITION, ISSUANCE, CHECKPOINT and production environments must reject. No operational IAM imports, source promotion, role grants or current-authority output are authorized. Implementation starts only after technical prerequisites and the exact dependency/vector/file/test scope are separately accepted.

Required evidence: accepted content revisions of all four TRUST-04 documents,
strict-library compatibility/provenance, independent golden assets and mutation
recipes, exact stage/counter assertions, resource-limit tests and compatibility
checks preserving existing IAM policies/hashes and false currency. Content digests
must be pinned in the eventual owner record; filenames or this proposal alone do
not evidence acceptance.

Exclusions: production A04 proof/admission contract, live verifier source, current
revision/revocation/checkpoint evidence, human identity, DB/roles/migrations, IAM
admission/policy/provider/API changes, audit mutation, execution gates and all external
actions. No TEST diagnostic may be wrapped/relabelled as production proof.

Remaining risks: parser/library/backend differences, unknown strict-point enforcement,
self-derived test expectations and compromised verifier process. Scope is one
approved TEST implementation milestone/version; any semantic change requires a
new owner decision. **Production A04 remains PENDING.**

## 5. Separate supporting proposals

| Decision | Proposed authorization and exclusions | Required evidence / status |
| --- | --- | --- |
| DEP-TEST | Select exact Python-3.10-compatible reviewed library/backend/artifact hashes; installation or requirement-file change only if explicitly named separately. No implicit upgrade/install/network or system-package reuse | Maintenance/advisory/license/provenance/strict-profile review; PROPOSED — NOT APPROVED |
| VEC-TEST | Obtain reviewed published algorithm/adversarial artifacts and independently derive project golden bytes/digests; project signing with published non-production seeds only if explicitly authorized, in a separate reference activity. No new/private production keys or signer in verifier | Exact sources/versions/licenses/digests, two independent derivations/review, accepted literal fixtures; PROPOSED — NOT APPROVED |
| IMPL-TEST | Approve only the exact future paths, tests and exclusions in the implementation-boundary document after blockers clear. No edits to existing IAM, serializer, selection, configuration or approval records | Explicit owner record selecting A01-TEST/A04-TEST/DEP-TEST/VEC-TEST and code/test scope; PROPOSED — NOT APPROVED |

These are separate decisions, not preselected consent or automatic follow-on work.
A negative, ambiguous or missing decision leaves G1 authorization PENDING and
cryptographic implementation NO-GO. A02/A03/A05 are not satisfied by these proposals.

## 6. Review outcome and validation

Only local source/document/metadata/link/whitespace and preservation checks were
performed; no package import, crypto API, tests, key/signature generation, network,
DB or service operation. The metadata observation is a fact, not library approval.
Full evidence and pending checklist items are in the companion documents.

**A01-TEST: PROPOSED — NOT APPROVED**  
**A04-TEST: PROPOSED — NOT APPROVED**  
**G1 TECHNICAL READINESS: NOT_READY**  
**G1 AUTHORIZATION: PENDING**  
**A01/A04 PRODUCTION: PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**
