# TRUST-04 G1 readiness review

2026-11-16. **Documentation-only review; not implementation approval.**

Deliverables:

- [ROOT_POLICY wire specification](iam03c-trust04-root-policy-wire-spec.md)
- [Independent TEST anchor/verifier contract](iam03c-trust04-anchor-and-verifier-contract.md)
- [Vector, error and threat matrix](iam03c-trust04-vector-and-error-matrix.md)
- This readiness review.

## 1. Assessment and meaning

**G1 READINESS: READY_FOR_OWNER_REVIEW.** The initial TEST subset is field-exact
and sufficiently bounded for owner/security review. This classification says the
candidate specification and its pending implementation-subset decisions are ready
to review, **not** that G1 has been approved or an implementation can begin.
Production A01/A04 remain pending, as do A02/A03/A05. No approval record is modified.

Cryptographic implementation remains NO-GO. Golden vector materialization,
strict-library compatibility and actual dependency selection are future evidence
requirements; they are not established by these documents or historical tests.
If the chosen established library cannot enforce the frozen strict acceptance set,
stop for profile/dependency review instead of implementing arithmetic or weakening
verification. Real keys, signature creation, production trust, DB/environment setup,
recovery and operational integration are outside this milestone and any implied G1.

## 2. Sources, facts and TRUST-03 refinement

Required source documents were found. AGENTS.md and the historical handoff were
read. Existing Git changes, untracked TRUST-02/03 work and index were inspected and
preserved. Only the four authorized documentation files are added.

| Actual source | Review finding |
| --- | --- |
| `services/api/app/iam/trust/contracts.py`: TrustBinding, RootTrustPolicy, RootCustodian, TrustAnchorReference | Existing strict immutable structure; three custodians/quorum two, identifiers/digests, explicit SaaS/customer separation; no keys, manifest or verified authority |
| Same package `canonical.py`: canonical_bytes, parse_canonical, MAX_PAYLOAD_BYTES | Actual TRUST02-JSON-1 behavior agrees with relevant TRUST-03 assumptions; ASCII sorted compact JSON, duplicate/alias rejection, fixed inner schema, no signing frame; max structural bytes stays 65,536 |
| Same package `validation.py`: checked, validate_structure, StructuralAssessment; `denials.py`: StructuralCode | Explicit context/issuer structure and twenty diagnostics; no crypto, no production source and only STRUCTURAL_ONLY |
| `tests/iam/test_trust_structural.py` | Existing 98-case record is historical; fixtures are not independent custody, verified public keys or crypto tests; no tests executed here |
| `services/api/app/iam/contracts.py`: IAMContract, Identifier, Digest, PermissionScope, canonical_bytes, contract_digest | Existing types and record hashes reused, not revised or treated as authenticity |
| `services/api/app/iam/policy.py`: evaluate, default_policy | Pure policy retains role/action/approval semantics; signatures alone supply no grant |
| `services/api/app/iam/admission.py`: admit, SyntheticAuthority/SyntheticOriginRegistry | Exact synthetic-only gate remains unchanged; no input from a new TEST signature result |
| `services/api/app/iam/authority_provider.py`: ProtectedAuthorityBridge/ProviderSnapshot | Synthetic origins/epoch checks are not crypto production proof |
| `services/api/app/iam/postgres_authority.py`: PostgresAuthorityProvider.read/is_current | No authoritative snapshot; is_current remains False; caller/session safeguards unchanged |

Relevant unchanged documents: [TRUST-01 contracts](iam03c-trust-contracts.md),
[approval register](iam03c-owner-approval-register.md),
[TRUST-01 verification](iam03c-trust-verification-matrix.md),
[TRUST-02 record](iam03c-trust02-structural-contracts.md),
[TRUST-03 architecture](iam03c-trust03-cryptographic-architecture.md),
[TRUST-03 threats](iam03c-trust03-threat-model.md),
[TRUST-03 G1 plan](iam03c-trust03-verification-plan.md),
[D01–D04](iam03c-d01-d04-decision-package.md),
[minimum schema](iam03c-minimum-authority-schema-review.md),
[schema proposal](iam03c-authority-schema-design.md), and
[disposable DB plan](iam03d-isolated-verification-plan.md).

No reviewed implementation difference affects signing semantics, no missing source
or circular digest blocks this candidate, and no incompatible TRUST-02 change is
needed. Existing bytes are nested verbatim. TRUST-03 generic manifest capabilities
are narrowed explicitly, not interpreted as already implemented:

| Proposed freeze decision | Difference from broader TRUST-03 / why safe for this subset |
| --- | --- |
| F04-01 TEST ROOT_POLICY only | No transitions, issuance, checkpoints, source/incarnation, issuer ceilings, complete state, recovery, runtime identity or authority semantics. Extra fields/purposes reject |
| F04-02 Three customer custodians | No provider-recovery member, delegation or vendor key; both enterprise and SaaS can supply separate TEST context |
| F04-03 Closed RootManifest/RootKeySet | Exact field lists, key bytes/lifecycle/test refs and DAG replace earlier generic sidecar descriptions only for this TEST version |
| F04-04 Immutable inner plus exact wrapper | Seventeen body fields, fixed 24-byte label/33-byte header, explicit payload/digest/frame boundaries; TRUST02 is not JCS and keeps its own structural cap |
| F04-05 Independently composed TEST source | Closed context/snapshot/provenance and pin checks; no payload-selected anchor, trust-on-first-use, DB/network/default config or production source |
| F04-06 Strict Ed25519 acceptance | Pure profile, exact 32/64 bytes, strict point/scalar rules, established library gate; no ph/ctx or P-256 fallback |
| F04-07 Deterministic staged diagnostics | Fifteen private TEST codes, including TIME_INVALID; duplicate preflight before key lookup and explicit quorum-before-math behavior; existing IAM/TRUST-02 enums/order unchanged |
| F04-08 Independent golden assets | Published algorithm versus project-frame suites separate; literal expected bytes/hashes and project signatures generated only in separately approved future activity, never by verifier under test |

These are **proposed freeze decisions**, not automatically approved production
choices or established root assumptions. A signed candidate manifest cannot approve
them, enroll its own keys or establish customer authority.

## 3. Twelve-point G1 review

| Question | Review result / remaining gate |
| --- | --- |
| 1 Initial purpose schema specified? | Yes for ROOT_POLICY-TEST-1: exact transport/body/binding/payload/manifest/key-set/context/snapshot/signature/output fields and constraints; all other purposes forbidden |
| 2 Canonicalization unambiguous? | Candidate exact ASCII/escaping/integer/time/UUID/set/null rules; inner unchanged, outer aliases reject. Independent cross-language vectors still required |
| 3 Frame exact? | Yes: fixed 24 ASCII label bytes, one NUL, U64BE body length, exact body; 33-byte header; no trailing bytes |
| 4 Algorithm exact? | Pure Ed25519 with exact input/encodings and strict acceptance restrictions; actual library compatibility not yet tested |
| 5 Anchors independently supplied? | Yes by protected read-only TEST fixture composition, not wire keys/booleans. This is a limited test assumption, not production authentication |
| 6 Quorum deterministic? | Yes: exactly three enrolled customer identities; 2/3 eligible signatures; each supplied signature checked; duplicate/revoked/unknown handling explicit |
| 7 Failures deterministic? | Yes: fixed ordered stages and conceptual multi-fault outcomes; no partial evidence or raw source/crypto error text |
| 8 Vector sources identified? | RFC 8032 section 7.1 and candidate Wycheproof corpus; exact source revision/license/digests and golden bytes/signatures remain future acceptance assets |
| 9 Maintained library candidate identified? | PyCA cryptography candidate and API/version/backend/advisory/provenance criteria specified. Current maintenance/security status and strict behavior are not network-verified; no version approved |
| 10 Boundaries/STOP clear? | Yes: no code/keys/signatures now; later pure offline TEST-only core, no operational imports/IAM/DB/recovery; stop on unmet strictness or incompatible serialization |
| 11 A01/A04 subset decisions identified? | Yes, section 4 below; none marked accepted on owner's behalf |
| 12 Approval vs readiness separated? | Yes: reviewable candidate only; separate explicit code/test/dependency/test-material authorization required, production remains NO-GO |

The first implementation is not allowed to emit production evidence even if every
signature test passes. Absence of a production authority source is an explicit
exclusion, not a dependency to fabricate for this non-authorizing TEST purpose.
If requested support expands to such a source, STOP for separate approval.

## 4. Owner decisions still required

| Decision | Exact implementation-subset review required | Current status |
| --- | --- | --- |
| A01 limited next subset | Accept TEST-only independent customer fixture identities/pins, two-of-three policy and key/custodian mapping/lifecycle assumptions; recognize that fixture distinctness is not real independent custody | PENDING FOR NEXT IMPLEMENTATION; prior TRUST-02 assumptions authorize no further code |
| A04 limited next subset | Accept F04-01..08, all four document revisions/content digests, strict Ed25519 acceptance, exact bytes/digests/budgets/error priority and TEST output/source exclusion from IAM | PENDING FOR NEXT IMPLEMENTATION |
| Dependency selection | Approve exact maintained PyCA/backend/version/provenance/license and compatibility evaluation plan; define STOP if strict acceptance cannot be met by established APIs | PENDING; nothing installed/imported |
| Vector/test-material scope | Approve published source versions and separate reference tooling; explicitly authorize creation of project-frame signatures from published non-production material if needed; no operational/new root keys | PENDING; all golden values/signatures remain ungenerated |
| Code/test scope | Separately authorize exact new/changed files, selected safe tests and compatibility checks; no production imports, IAM changes, network, DB or dependency installation implied | PENDING; no automatic TRUST-05 start |

Production A01 still needs named actual custodians, independent custody/signing
paths, real key generation/device/backup/compromise/quorum-loss/rotation/recovery and
acceptable host/witness risks. Production A04 still needs authenticated production
verifier delivery, real issuance/current-state/complete-state/checkpoint proof,
production admission and final execution gates. A02 human identity, A03 disposable
target/privileges and A05 schema/profile are pending and not needed to *pretend*
this TEST verifier supplies those functions. No approval register is changed.

## 5. Limits, risks and implementation acceptance

The 24,576-byte signable inner budget is a narrower wrapper subset, not an incompatible
change to TRUST-02's 65,536 structural cap. Body includes hex expansion; transport
contains frame hex. Combined budget counts raw and decoded inputs explicitly.
Narrower field limits may prevent semantically valid objects reaching some maxima;
cap/cap+1 preflight fixtures must not add padding metadata or relax schemas.

The following remain mandatory future implementation evidence, not claims checked
by this review: strict API/point/scalar acceptance, actual independent golden bytes/
digests/signatures, cross-implementation agreement, bounded parser/runtime memory,
source-read/crypto-call counters, sanitized errors and negative integration/import
checks preserving all existing IAM policies, hashes, synthetic gates and false
currency. Missing vectors or incompatible library behavior fails acceptance.

Residual risks: two compromised custodians or deceptive shared displays can endorse
a valid malicious intent; false enrollment can invent independence; compromised
verifier/host can forge a local diagnostic; TEST revocation does not prove latest
real revocation; no database/checkpoint rollback or live session/execution race is
addressed. SaaS platform/DB administrators' plaintext/runtime access is outside root
signature confidentiality. Production requires independent storage/custody and
operational controls that this subset deliberately does not implement.

## 6. Validation and next recommendation

Performed only local source/symbol/document/canonical-rule review, link and
cross-file field/count/digest/error/case/threat consistency checks, approval-state
checks, git diff --check plus explicit new-file whitespace checks, and preexisting
file/index preservation comparison. Checks passed for 17 body, 8 binding, 14
manifest, 12 manifest-custodian, 9 context and 19 snapshot fields; the exact label
length is 24 bytes. The matrix has 15 ordered diagnostics, 26 specified vector cases
and all 20 TRUST-03 threats mapped. No project-module or cryptographic-library import, pytest,
compilation, vector generation, signing/verification, key generation, DB/container,
network or external service access. Historical TRUST-02 98/2,034 results were not
rerun and are not cryptographic evidence. New golden vector values were not computed.

Only the four deliverables were created. Recovery for a rejected specification is
to revise those documents under owner direction; existing code, test fixtures,
approval records, configuration, Git history and current index are preserved.

Recommend owner/security review of the frozen candidate and explicit A01/A04 next
subset/dependency/vector/code scope decisions. Only after that approval consider a
separately authorized TRUST-05 offline verifier. Do not begin it, IAM-03D, IAM-04,
root establishment or deployment under this documentation authorization.

**IAM-03C-TRUST-04: COMPLETE — documentation only**  
**ROOT_POLICY SPECIFICATION: PROPOSED FREEZE**  
**G1 READINESS: READY_FOR_OWNER_REVIEW**  
**A01: PRODUCTION APPROVAL PENDING**  
**A04: PRODUCTION APPROVAL PENDING**  
**A02/A03/A05: PENDING**  
**CRYPTOGRAPHIC IMPLEMENTATION: NO-GO**  
**DATABASE SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**PRODUCTION DEPLOYMENT: NO-GO**  
**NEXT STEP: Recommendation only**
