# TRUST-04C G1 evidence and owner review

2026-11-16. **Evidence acquisition/preparation only; no verifier implemented.**
[Dependency evidence](iam03c-trust04c-authoritative-dependency-evidence.md),
[public catalog](iam03c-trust04c-ed25519-public-vector-catalog.md),
[independent golden plan](iam03c-trust04c-independent-golden-vector-plan.md),
[TEST asset manifest](../../tests/iam/fixtures/trust04c_public_vectors/manifest.json).

## 1. What changed in the evidence

Required TRUST-03/04/04A/04B documents and relevant TRUST-02 code/tests/declarations
were present. AGENTS.md and the historical handoff were read; existing Git state
and content were preserved. Earlier source-only records were reused where unchanged;
this milestone adds authoritative HTTPS evidence and public verification data.

| Previous gap | New evidence | What remains missing |
| --- | --- | --- |
| No current dependency candidate | Official support/release/API/install metadata supports reviewing exact cryptography 50.0.2; matching wheel/publisher SHA recorded, not downloaded | Owner selection, complete artifacts/transitives, exact environment/backend and actual compatibility |
| Unknown target support | Versioned docs list Python 3.9+ and Ubuntu 22.04 x86-64; PyPI tags include suitable ABI/platform candidate | Actual local execution; Python 3.10 is upstream EOL, requiring separate runtime-support/TEST exception decision |
| No acquired public vectors | Three RFC verification-only records and original 210-case C2SP corpus, license and manifest | Independent review and case-by-case strict-profile verdicts; source publication is not passing a local test |
| No project golden assets | Complete independent derivation/mutation/review plan and all 26 V04 states | Exact project canonical/frame/preimage/hash/signature literals; no hashing/signing performed |
| Strict subgroup behavior unproved | RFC/ZIP/corpus policy differences and maintainer backend delegation identified | Vetted enforcing APIs and independent exact-backend conformance tests |

No security-critical frozen-wire contradiction or proven library incompatibility
was found. A source policy being more permissive does not alter the project policy:
retain native labels separately and require explicit strict mapping. If reconciliation
or vetted enforcement proves impossible, stop instead of broadening acceptance.

## 2. G1 gates, assessed separately

| Gate / requirement | Current disposition |
| --- | --- |
| Frozen ROOT_POLICY schema/canonicalization/frame | Reviewed unchanged; seventeen body fields, closed TEST manifest/key-set, exact domain/NUL/U64BE frame and acyclic digests retained. No production purpose or serializer change |
| Frozen diagnostics/limits | All fifteen codes/order/extraction/budget exceptions retained; no new enum or wrapper code implemented |
| Independent TEST anchors | Contract exists; future pins/context still need independently reviewed fixture registration; public key data is not enrolled authority |
| Dependency evidence | SUFFICIENT_FOR_REVIEW of 50.0.2 candidate, not an approval or verified installation; source URLs/version/date and publisher checksum recorded |
| Security review | Official support, selected current advisories and runtime lifecycle consulted; bounded manual review, not exhaustive transitive/backend clearance |
| Strict Ed25519 | UNVERIFIED; documented APIs/published input vectors are not focused conformance execution |
| Public asset gate | ACQUIRED; raw native results preserved; independent provenance/license/profile review pending |
| Project golden gate | NOT_READY; twenty-four case groups still require project-specific derivation; acquired groups 01/21 are source inputs ready for review only |
| Isolated environment | Proposed exact offline commands/clean export/network isolation, never created/run; target-runtime policy and complete lock remain pending |
| Owner decisions | A01-TEST/A04-TEST, package/install, compatibility tests and project hashing/signing/implementation scopes remain pending |

**G1 TECHNICAL READINESS: NOT_READY. G1 AUTHORIZATION: PENDING.** Evidence is now
stronger and the candidate/public inputs are reviewable, but no compatibility gate
can pass without actual separately authorized execution and approved goldens.
Documentation completeness and asset counts grant no code/deployment permission.

## 3. Proposed owner decisions — not approvals

Each item is **PROPOSED — NOT APPROVED**, scoped to one separately named activity
and accepted specification/artifact revisions. Recheck support/advisories at adoption;
material version/profile/fixture/scope changes require renewed owner review.

| Decision | Exact proposed next scope | Exclusions / prerequisites |
| --- | --- | --- |
| DEP-TEST | Review cryptography==50.0.2 exact artifact as the documented candidate, complete offline pins/backend evidence and Python-3.10 runtime-support decision | No automatic installation/declaration edit; publisher checksum is not locally verified; no safe/unsafe inference for Ubuntu 3.4.8 |
| COMPAT-TEST | Separately authorize disposable offline focused conformance tests of the frozen strict profile against reviewed public vectors on the approved backend | No verifier integration, network during tests, production data/credentials or permissive algorithm fallback; environment/file/test scope must be exact |
| VEC-TEST | Separately authorize independent reference byte/hash derivation and project signatures from approved non-production material, with separate reviewers | No new root keys, no same-verifier oracle, no current hashing/signing authorization; published source signatures cannot be reused for different frames |
| A01-TEST | Exact three CUSTOMER TEST identities/public anchors and fixed two-of-three quorum using approved independent expected context/pin fixtures | No actual customers/custodian ceremony, root enrollment/recovery, provider delegation, vendor master root or production authority |
| A04-TEST | Exact ROOT_POLICY-only TEST protocol/algorithm/frame/digests, immutable diagnostic evidence and isolated approved TRUST-05 modules/tests after blockers clear | Reject ROOT_TRANSITION/ISSUANCE/CHECKPOINT/production; no IAM policy/admission/provider/API/audit/identity/gate/DB/external effects |

The current task **did authorize public-source research and verification-only asset
acquisition**, which were performed. It did not authorize installation, cryptographic
execution, project signing/hashing, new tests or TRUST-05 implementation. Existing
approval records are unchanged; production A01/A04 and A02/A03/A05 remain pending.

## 4. Remaining blockers and acceptance requirements

1. Independently review sources/reuse constraints/native-to-project semantics and
   register exact approved TEST assets. Additional publisher NOTICE lookup via the
   research tool was UNAVAILABLE; no assertion of its absence or completed license
   audit is made. Check any extra upstream notices before accepted redistribution.
2. Select/approve complete dependency/backend artifacts and target-runtime policy;
   upstream Python 3.10 EOL cannot be ignored or silently changed under AGENTS.md.
   Vendor downstream support was not established by this milestone.
3. Execute focused strict-point/scalar/encoding/variant/exception tests only under
   separate permission. API documentation and default OpenSSL delegation cannot
   prove the frozen acceptance set; no custom arithmetic/blacklist workaround.
4. Produce/review independent project frame/hash/signature goldens and all expected
   stage/counter mutations under separate authorization. No dummy values or fake
   mathematical success can replace them.
5. Obtain explicit A01-TEST/A04-TEST and exact implementation/dependency/test scope;
   then reassess G1 before proposing TRUST-05. No later phase starts automatically.

Recommend the next separately authorized **isolated dependency-compatibility and
independent golden-derivation/review activity**, after owner review of these inputs.
Keep operational/schema/root recovery/current-authority work excluded. If any gate
fails or source cannot be authenticated for its intended use, report/hold rather
than weaken or promote synthetic evidence.

## 5. Performed checks and limitations

Read-only HTTPS research used RFC Editor, official PyCA/PyPI, Python/PyPA, C2SP and
ZIP primary sources. A shell DNS restriction required sandbox approval for narrow
public metadata/vector reads; no authentication secrets or local project data were
sent. No downloaded script/package was executed. An optional upstream JWK field
was absent in some groups; acquisition first stopped before writing, then handled
the documented public optional shape while still excluding every private field.

Validation: document links/references/status/counts, all 26 V04 IDs exactly once,
public JSON structure/hex lengths/native result counts/private-field absence,
manifest CRC/size comparisons, new-file whitespace, git diff --check and original
content/index preservation. CRC is permitted non-cryptographic file integrity;
no source/vector SHA or signature calculation/verification occurred. Publisher
SHA/git object IDs are copied metadata, not computed results. No pytest/compile,
crypto-library import, package/venv installation, Docker, databases, Wazuh/Ollama/
Shuffle, scheduler, operational integration, commit or push ran.

Only four new documentation files and four public fixture/manifest/license files
were created in the authorized destinations. Preexisting tracked/untracked work and
index are preserved; no existing approval or freeze record is rewritten. No actual
customer, root credential, private seed or generated signature is included.

**IAM-03C-TRUST-04C: COMPLETE — evidence acquisition/documentation only**  
**DEPENDENCY EVIDENCE: SUFFICIENT_FOR_REVIEW**  
**ED25519 STRICT COMPATIBILITY: UNVERIFIED**  
**PUBLIC VECTORS: ACQUIRED**  
**PROJECT GOLDEN VECTORS: NOT_READY**  
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
