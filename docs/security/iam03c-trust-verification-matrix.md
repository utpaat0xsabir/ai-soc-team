# IAM-03C trust verification matrix

IAM-03C-TRUST-01, 2026-11-14. **Future test specifications only: no test code,
cryptography, keys, identity service, database or execution gate is implemented/run.**
Contracts/reasons/phases: [trust contracts](iam03c-trust-contracts.md).
Exact approvals: [owner register](iam03c-owner-approval-register.md).
Prior broader cases: [schema threat model](iam03c-authority-threat-model.md) and
[isolated verification plan](iam03d-isolated-verification-plan.md).

## Reading the matrix

All cases are **SPECIFIED / NOT EXECUTED**. Owner approvals remain PENDING. Fixture
preconditions below describe future unit-test inputs, not acceptance of decisions
or genuine production authority. The nominated 2-of-3/OIDC/MVA-1 choices remain
candidates; changing them requires updating these cases before implementation.

Symbols: tenant A/B are distinct; P is a registered actor, I an independently
scoped issuer, S a pinned source, R a monotonic revision, E its persisted epoch,
D a canonical digest. K1/K2/K3 label hypothetical key/custodian bindings; they are
not public/private key material. A test signature port can report deterministic
valid/invalid against labeled payloads; a positive result is STRUCTURAL_TEST_ONLY.
It cannot produce a production VerifiedAuthorityRead or activate current admission.

For unit cases, assume all checks preceding the tested branch passed unless a row
explicitly tests precedence. Trusted inputs must be independent fixtures under a
TEST_ONLY composition channel; do not populate a production verified flag from
candidate data. Combined isolated tests later use independently controlled lab
proofs/logins, bound to that lab root/target only, never production anchors. Current
SyntheticProvider/for_tests objects remain rejected by any future production path.

Every denial must assert the exact reason, no usable admitted/source snapshot or
execution permission, no secret/raw input echo, deterministic repeated result and
no unauthorized effect. Pre-connect tests assert zero attempted connection/process
calls; pre-query/profile tests assert no forbidden/deferred query. UNKNOWN cases
are explicitly different: effects may have committed, so no success/retry is
returned until reconciliation. Actual SQL/audit/isolation claims require I1/E1,
not fake-session tests or static format acceptance.

Phase codes are the proposed phases in trust contracts: O1 structural root only;
O2 real approved crypto/recovery/journal; O3 identity/target contract fixtures;
O4 source/state/projection; I1 authorized disposable PostgreSQL verification;
E1 separately authorized execution integration. None is authorized by TRUST-01.

## Deterministic case specifications

| Case / claim | Preconditions | Input shape / single fault | Expected denial or bounded outcome | Required independent trust evidence | Contract / future phase |
| --- | --- | --- | --- | --- | --- |
| V01 — Root quorum failure | Candidate policy requires two distinct custodians; current pin and frame otherwise valid | RootManifest with one authorized valid signature | TRUST_QUORUM_INSUFFICIENT; never lower threshold | Protected threshold/custodian map and exact frame; deterministic test verifier for O1, real signatures only later | TC-R01; O1/O2 |
| V02 — Forged signer | Root set/payload valid | Signature entry references key outside independent anchor map, even if body claims trusted | TRUST_SIGNER_UNKNOWN; verifier must not discover keys from body/URL | Independently pinned root set, not DB key row | TC-R01; O1/O2 |
| V03 — Duplicate signer | Threshold otherwise achievable | Two signatures share key or distinct keys share one protected custodian ID | TRUST_SIGNER_DUPLICATE; do not deduplicate into quorum | Independent custodian-to-key binding | TC-R01; O1/O2 |
| V04 — Invalid supplied signature | Distinct known signers, supported algorithm; two other supplied signatures could pass | One supplied signature invalid for exact frame | TRUST_SIGNATURE_INVALID even if remaining signatures reach threshold | Protected verifier/key/frame binding; no caller verified flag | TC-R01/TC-C01; O1 port logic then O2 real crypto |
| V05 — Unsupported algorithm | Bound context and root pin valid | Signature algorithm differs from independently approved profile | TRUST_ALGORITHM_UNSUPPORTED; no negotiation/fallback | Protected algorithm/profile policy | TC-R01; O1/O2 |
| V06 — Unknown anchor | Valid shapes/tenant; purported quorum supplied | Anchor view unavailable or manifest root-set/pin not independently registered | TRUST_ANCHOR_UNKNOWN; body keys cannot bootstrap | Outside-DB authenticated pin/configuration | TC-R01; O1/O2 |
| V07 — Checkpoint rollback | Verified CLEAR; latest independent checkpoint at R+1; actual fresh committed primary observed, not an old snapshot | Fresh DB AuthorityState at R | TRUST_ROLLBACK_DETECTED; quarantine, no counter reset or cached checkpoint | Independently current checkpoint/pin and real fresh-head proof | TC-R03; O2/O4 fixtures, I1 real restore/primary read |
| V08 — Conflicting checkpoints | Root/signatures/current source valid | Authenticated same generation/revision/epoch claims bind different state/event digests | TRUST_CHECKPOINT_CONFLICT; never choose newer timestamp | Independent latest checkpoint lineage and signatures | TC-R03; O2 |
| V09 — Incomplete recovery | Root/checkpoint otherwise valid | Verified pending PREPARED/COMMIT_UNCERTAIN, including missing operation/old head after reconnect | TRUST_RECOVERY_INCOMPLETE; missing DB row is not proof of failed commit | Authenticated pending record plus independent recovery quorum source | TC-R02/TC-R03; O2 state model, I1 crash/recovery |
| V10 — Complete-state omission | Current checkpoint and full group manifest known; no earlier journal error | Omit required group/row/tombstone or declare truncation | TRUST_STATE_INCOMPLETE when omission is structurally known; no partial graph | Independently authenticated complete-state commitment and group specification | TC-R03/TC-P02; O4/I1 |
| V11 — Complete-shaped tampering | Bounded group/row shape is complete; current pin matches | All shapes present but normalized state digest differs from checkpoint, including undeclared row omission hidden inside a group | TRUST_STATE_DIGEST_MISMATCH; a signed subset is insufficient | Whole-state expected digest from outside DB, canonical row encoding | TC-R03/TC-C01; O2/O4/I1 |
| V12 — Root revoked/stale | Signatures otherwise valid, no unknown anchor | Protected current root lifecycle marks set/key revoked; separate fixture has older root generation | TRUST_ROOT_REVOKED for revoked fixture; TRUST_ROOT_STALE for old generation fixture | Independent current lifecycle/version, not candidate validity labels | TC-R01/TC-R02; O2 |
| V13 — Missing rotation acknowledgement/signatures | Current old-set quorum signs one exact rotation intent | New-set acknowledgement array empty; separate root fixture has empty signature array | TRUST_SIGNATURES_MISSING; no new pin activation | Old/current independent root and designated next set, both bound to same transition | TC-R02/TC-R01; O1 empty-list rule, O2 rotation |
| V14 — Invalid human identity | Structurally valid HUMAN/SESSION input; no context/tenant shape failure | IdP issuer/subject/signature evidence is not authenticated by protected IdP registration | TRUST_IDENTITY_INVALID; not an administrator | Pinned IdP issuer/audience/key and enrollment source; no email/group shortcut | TC-H01; O3 then E1 actual identity adapter |
| V15 — Revoked session | Valid identity/assurance/current enrollment | Durable session-state proof says revoked/current revocation generation; token remains unexpired | TRUST_SESSION_REVOKED; JWT lifetime cannot override | Authenticated durable current session observation | TC-H01; O3 fixtures, E1 real session invalidation |
| V16 — Stale/expired session | Valid source and principal, not revoked | Well-formed session idle/absolute expiry <= trusted evaluation time, or old session generation | TRUST_SESSION_STALE; no refresh by timestamp rewrite | Explicit trusted aware time and current session generation | TC-H01; O3/E1 |
| V17 — Missing tenant enrollment | Valid human/session/assurance | Enrollment reference is syntactically present but no independently verified current enrollment for A/P | TRUST_ENROLLMENT_MISSING; login does not imply membership | Root-approved tenant enrollment and current principal state | TC-H01; O3/E1 |
| V18 — Cross-tenant principal | Bounded input and protected tenant A context | Validly typed principal/session/issuer/resource reference bound to B | TRUST_TENANT_MISMATCH before issuer/grant selection; no B lookup or victim audit | Protected authenticated tenant, not request parameter | TC-C01/TC-H01/TC-P01; O1 common check, O3/O4/I1 |
| V19 — Missing MFA/assurance | Known identity, current session/enrollment | Authenticated source assurance lacks required WebAuthn/step-up, even if candidate claims admin | TRUST_ASSURANCE_INSUFFICIENT | Independently registered assurance policy and authenticated method/time | TC-H01/TC-H02; O3/E1 |
| V20 — Replayed/altered administrative approval | Existing exact ApprovalRecord remains unmodified; independent human context valid | Step-up nonce already consumed, or proof binds operation D1 while request is D2 | TRUST_BINDING_MISMATCH; no rewriting old approval; IAM-02 permission still required if proof passes | Durable nonce/session proof, exact operation/resource/approver digests | TC-H02; O3/O4 unit branch, I1/E1 durable consumption |
| V21 — Substituted API-key verifier | Current key UUID/tenant and principal otherwise valid | DB key_hash changed to attacker value; protected presented-key proof no longer matches independently approved credential_binding_digest | TRUST_BINDING_MISMATCH; two UUIDs from current authenticator are insufficient production proof | Root-approved key enrollment and protected hashing boundary, no raw key in snapshot | TC-H01/TC-P02; O4 then I1/E1 |
| V22 — Protected database target | Bounded explicit target request, no actual connection | Requested database ai_soc or ai_soc_test (two variants) | TRUST_TARGET_PROTECTED; zero connection/process calls, including no probes | Protected denylist and explicit target scope | TC-L01; O3 guard fixture, I1 guard negative only |
| V23 — Unproved target isolation | Database name not protected, but no launcher proof | Prefix matches proposed disposable name; DB marker claims isolated while socket/volume/instance evidence missing or mismatched | TRUST_TARGET_UNVERIFIED; zero connection calls | Independent launcher/process/socket/storage/run manifest | TC-L01; O3, I1 endpoint attestation |
| V24 — Excessive DB privileges | Actual exact lab identity passed preflight | Reader/runtime role observed owner/SUPERUSER/BYPASSRLS or cross-tenant membership/unsafe EXECUTE | TRUST_PRIVILEGE_MISMATCH; no granting extra rights to pass | Real nonowner login/privilege/RLS observations under approved lab scope | TC-L01; O3 role-data fixture, I1 actual privileges/FKs/RLS |
| V25 — Unauthorized teardown | Lab may be correctly isolated | Cleanup request has no exact destructive run/volume authorization | TRUST_TEARDOWN_UNAUTHORIZED; no deletion/drop/volume cleanup | Separate explicit authorized cleanup scope and stopped/fenced identity | TC-L01; O3 guard, I1 only separately approved actions |
| V26 — Forged/unauthorized issuer provenance | All fields/signature are well shaped; current tenant/root valid | Correctly signed TEAM_SCOPE claim from issuer authorized only for ROLE_ASSIGNMENT, or role outside its explicit ceiling | TRUST_ISSUER_UNAUTHORIZED; signature possession is not permission | Independent issuer identity/current scope/role ceiling and original record digest | TC-P01; O4/I1 |
| V27 — Normal concurrent stale read | Old coherent read R/E verifies against its original checkpoint; fresh primary R+1 and latest checkpoint agree, CLEAR | VerifiedAuthorityRead still binds R/E | TRUST_REVISION_STALE, not TRUST_ROLLBACK_DETECTED; old read content is not current | Separate original-read checkpoint and independently current head/checkpoint | TC-P02/TC-R03; O4, I1 repeatable-read versus fresh view |
| V28 — Stale snapshot/time | Source/current head/identity valid; windows structurally consistent | Snapshot expired or bound evaluation time differs/observation age exceeds allowed ceiling | TRUST_SNAPSHOT_STALE; do not retimestamp proof | Protected clock, original validity and exact runtime ceilings | TC-P02; O4/I1 |
| V29 — Concurrent role revocation | Before-effect gate test with old read, no automatic retry; actor identity remains valid | Revoker completes R+1 after snapshot verification, before gate obtains tenant lock | TRUST_REVISION_STALE; no protected effect. Complement schedule: already-held gate commits/aborts before revocation acknowledgement, never after an earlier completed revocation | Actual shared lock/writer protocol, fresh primary/checkpoint and barrier ordering | TC-G01/TC-P02; O4 model, I1/E1 real concurrency |
| V30 — Missing execution gate | Provisional exact IAM-02 ALLOW would be possible; source stages already exercised separately | Effect request has no actual approved caller transaction/gate | TRUST_GATE_REQUIRED; no protected callback/commit/success receipt; parsing a gate declaration does not hold locks | Real gate/caller transaction ownership and exact operation binding | TC-G01; O4 negative eligibility, E1 actual effect boundary |
| V31 — Unsupported action metadata | Direct request-preflight branch; existing permission catalog/version known | Unknown/wildcard action or unsupported policy version | TRUST_REQUEST_UNSUPPORTED; current adapter compatibility remains INVALID_REQUEST with zero session calls | Existing canonical catalog, protected request, no default policy | TC-P01/TC-P02; O4 plus unchanged adapter regression |
| V32 — Synthetic authority rejection | Well-formed surrounding handoff request; bound source registration is explicitly for_tests/SyntheticProvider | Matching hashes/canonical graph supplied by synthetic source at production boundary | TRUST_SYNTHETIC_SOURCE before production-body parsing/admission; no fallback or type relabeling | Independent eligible production source registration, absent for fixture | TC-P02; O4/I1 boundary |
| V33 — Unknown execution outcome | Gate already started exact authorized DB operation | Connection lost during commit acknowledgement | UNKNOWN with TRUST_EXECUTION_UNKNOWN; may already have effect/audit; no success permission or blind retry; reconcile operation ID | Durable operation/revision/audit/journal proof under new authenticated read | TC-G01/TC-R03; O4 state model, I1/E1 loss injection |
| V34 — Missing atomic audit | Valid current authority/gate; no uncertain commit | Audit writer fails before known rollback of protected transaction | TRUST_AUDIT_UNAVAILABLE; no business/grant/revision/success-audit durable change | Existing unchanged writer/tenant lock/hash chain on same transaction | TC-G01/TC-H02; I1/E1 rollback/integrity |
| V35 — False runtime projection | Original source bytes/signature valid and current | Runtime receipt window/fields changed but supplied independent attestation binds old projected digest | TRUST_BINDING_MISMATCH; never apply original signature to new timestamps | Separate authenticated original issuance and newly bound projection attestation | TC-P02/TC-C01; O4/I1 |
| V36 — Multiple faults/order determinism | Bounded common preflight; explicit protected tenant A | Inspectable B reference plus unknown issuer, bad signature and unsupported role metadata in varying order | TRUST_TENANT_MISMATCH consistently; no raw invalid input in error; repeats/permutations identical | Protected context and declared error ordering; no authority from input order | TC-C01 and section 8 denial order; O1 common checks/O4 |
| V37 — Disabled team/admin profile | Direct profile-preflight branch, independently pinned MVA-1 | Catalog-valid teams.manage or ordinary online roles.assign request | TRUST_PROFILE_UNSUPPORTED before deferred-table query; no membership/admin default | Approved schema/profile/policy/source binding, not table absence | TC-P01; O4/I1 feature guards |
| V38 — Metadata does not imply raw/export | Same valid MVA-1 preflight; explicit metadata assignment | Catalog-valid evidence.raw.read, evidence.export or external action requested | TRUST_PROFILE_UNSUPPORTED before deferred/unsupported resolver; no permission inheritance | Exact action/scope/resource classification and pinned restricted profile | TC-P01; O4/I1/E1 negative integration |
| V39 — Missing/malformed required proof | Eligible nonsynthetic source, supported header; no earlier tenant fault | Missing issuer/provenance field; extra verified flag; bool revision; malformed/extra query columns or numeric read_only flag | TRUST_RECORD_INVALID; no coerced boolean/counter, fabricated default or usable snapshot | Exact typed field schema and complete source/transaction observations | TC-C01/TC-P02/TC-L01 where applicable; O1 types/O3/O4, I1 actual observer |

## Traceability and operational claims

| Security claim | Offline design/contract cases | Required later real-world evidence |
| --- | --- | --- |
| Independent root/quorum and no self-trust | V01–V06, V12–V13 | Approved real crypto/key custody/profile under O2; fixture acceptance is not valid signature evidence |
| Rollback/recovery/complete-state safety | V07–V11, V27, V33 | I1 crash/restore/omission, independent pin/journal, primary reads and full-state signature tests; simultaneous host/journal compromise remains outside proposed guarantee |
| Human authentication separate from grants | V14–V21, V37 | E1 actual approved identity/session/assurance/enrollment and acknowledgement protocol; no IdP login-to-role inference |
| Protected targets and least privilege | V22–V25, V39 | I1 independently attested new lab and real nonowner/RLS/constraint tests; no protected-db contact |
| Exact provenance/snapshot/policy | V10–V11, V26–V28, V31–V32, V35–V39 | Source/proof verification, genuine transaction properties and unchanged IAM semantic parity; no synthetic conversion |
| Execution-time authority/audit consistency | V29–V30, V33–V34 | I1/E1 real shared locks, transaction failure/UNKNOWN handling and audit atomicity; an old ALLOW/epoch check is not execution authority |

Current IAM-03A/B, policy and PostgreSQL fake-session tests already cover synthetic
origin, issuer scopes, stale windows/epochs, tenant binding, incomplete row shapes,
read/rollback errors and bridge rejection. They should be retained as regression
coverage in a later code phase. None establishes the new root, identity, state
commitment, real isolation or execution claims above. Existing 402 focused,
1,936 selected and 164 compiled results are historical, not rerun in TRUST-01.

For every future test record exact spec/profile/version, fixture/deployment scope,
trusted inputs and selected validation branch, failure reason, I/O/side-effect calls,
canonical result/digest and phase. Negative tests must not create operational
credentials or weaken TLS/auth/audit protections to obtain a pass. Any excluded
isolated test remains an unmet verification requirement, not presumed success.

## Approval and first-implementation scope

A01 covers V01–V13; A02 V14–V21; A03 V22–V25; A04 V26–V36 plus shared proof cases;
A05 V37–V39 and restricted-schema closure. These are overlapping dependencies,
not permissions to execute tests/services. Every actual implementation needs A06's
separate authorization, including environment, credentials, migrations and teardown.

Recommend TRUST-02/O1 only after explicit A01/A04 subset approval: strict root
frame/anchor data, duplicate/unknown signer and quorum bookkeeping, canonicalization
and deterministic reason tests using a TEST_ONLY verifier port. No production crypto,
root key generation, journal file I/O, identity service, DB access, schema changes,
new operational admission, is_current change or gate implementation. Do not add
more feature contracts merely because they are listed in this matrix.

## TRUST-01 validation boundary

Only documentation/reference/status/whitespace and input/index preservation checks
are performed now. The five A01–A05 register quotations are compared exactly with
the decision-package source. Contract IDs, reasons, phases and case references must
resolve; 23-table/16-retained accounting and disabled-feature assumptions remain
consistent with the unchanged minimum-schema review. No pytest, compilation,
cryptographic check, external identity/service call, database, SQL or migration is
run. No implementation/test file or key is created.

**OWNER APPROVALS: PENDING**  
**TRUST IMPLEMENTATION: NO-GO**  
**SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**NEXT STEP: Recommendation only — owner review, then separately scoped TRUST-02/O1 if approved.**
