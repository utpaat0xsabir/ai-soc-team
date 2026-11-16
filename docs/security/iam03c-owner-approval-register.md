# IAM-03C owner approval register

IAM-03C-TRUST-01, 2026-11-14. **Documentation only; all approvals PENDING.**
Source of truth: [decision package](iam03c-d01-d04-decision-package.md), section 9.
The quoted wording below is copied verbatim from that source; the analysis around
it is this register's interpretation, not a change to the approval requirements.
No person, custodian, target, provider or approval evidence is invented.

Related: [trust interfaces](iam03c-trust-contracts.md) and
[verification matrix](iam03c-trust-verification-matrix.md).

## Status and evidence rules

D01–D04 are PROPOSED, not approved. Completion of an architecture/documentation
milestone, baseline tests, a recommendation, an uploaded DB record or broad project
authorization does not establish approval. Each item below is PENDING; evidence
reference and approval date are **none recorded**. This register is not a signed
approval record and does not authorize the actions in its quoted text.

A future authoritative owner record must identify owner/date, exact selected option,
document/version/content digests, scope/conditions and any rejected alternative.
Verify its origin independently; a root manifest cannot approve the root that is
needed to authenticate it. A01 custody bootstrap requires an owner-authenticated
out-of-band ceremony. Unclear or conflicting evidence keeps an item PENDING.
Selecting an alternative requires revising affected contracts/tests before coding.

| Approval | Decision dependency | Current status | Implementation blocked |
| --- | --- | --- | --- |
| A01 | D01; supports D02 bootstrap and D04 proof | PENDING | Root/issuer trust, quorum/rotation/recovery, checkpoint/journal implementation |
| A02 | D02; D01 recovery attribution and D04 identity | PENDING | Human identity enrollment, MFA/session/revocation and privileged human admission |
| A03 | D03; D04 real transaction/privilege evidence | PENDING | Disposable environment/harness connection, role/migration/DB verification |
| A04 | D04; consumes D01/D02/D03 proofs | PENDING | New trust/proof/admission interfaces, projection, state verification and execution gate |
| A05 | Profile across D01–D04 | PENDING | Restricted-schema changes, deferred feature mappings and profile-specific source assembly |

## A01 — Independent root and restore trust

Exact owner approval requirement (verbatim):

> Approve two-of-three named distinct custodians, key custody/signature profile, quorum loss/root compromise response, independent journal/pin storage and crash/restore protocol; accept the stated host-compromise limitation or choose an independent witness instead

| Register field | A01 assessment |
| --- | --- |
| Recommended option | Two-of-three distinct offline Ed25519 custodian signatures; protected independent root pins, separate routine issuer/checkpoint keys and off-DB pending/checkpoint journal with complete-state commitment. Hardware custody preferred where supported. |
| Alternatives | Single offline administrator root with explicitly weaker single-person trust; hardware-backed root custody; independent online witness or dedicated monotonic service instead of the protected-local-journal trust boundary. No silent fallback on quorum failure. |
| Security implications | Custodians must be distinct people; root/issuer data cannot authenticate itself. Host/journal co-rollback or root-quorum compromise is outside a local-only guarantee. Ambiguous restore loses availability instead of accepting stale grants. |
| Required evidence | Owner-authenticated custodian/custody decision, signature/canonicalization profile, independent storage/backup-control inventory, quorum-loss/rotation/recovery procedure and explicit host-compromise acceptance or witness choice. No keys or fingerprints are generated here. |
| Acceptance criteria | Distinct authorized quorum; independent pin/source binding; missing/unknown/duplicate/invalid signer denies; state/anchor mismatch and pending/ambiguous recovery deny; planned crash/restore/omission tests. TC-R01/TC-R02/TC-R03 and V01–V13 cover this. |
| Current approval status | PENDING — no authoritative owner approval recorded |
| Implementation work blocked | D01 root/provenance primitives, signer/anchor implementation, journal persistence, recovery automation and operational trust transition. |

## A02 — Human/operator authentication

Exact owner approval requirement (verbatim):

> Approve local IdP/provider deployment and trust, WebAuthn/MFA/recovery, explicit tenant enrollment, durable session/identity sidecar, proposed timeouts and completed-revocation/audit-attribution semantics

| Register field | A02 assessment |
| --- | --- |
| Recommended option | Local OIDC provider with WebAuthn MFA, durable revocable session state, explicit tenant enrollment and exact-operation privileged step-up; proposed idle 15 minutes/absolute eight hours, step-up within five minutes, challenge 60 seconds. |
| Alternatives | External OIDC with explicit connectivity/provider risk; direct hardware-backed application authentication with its own enrollment/session/recovery design. Root ceremony hardware does not replace human application-session verification. |
| Security implications | Authentication establishes identity only. Tenant enrollment, issuer authority, roles and independent human approval remain separate. IdP/group/email/administrator claims cannot mint root or IAM privileges; completed revocation is not instantaneous cancellation. |
| Required evidence | Selected provider/origin/key/TLS trust and assurance rules, session/enrollment source and retention, timeout/recovery policy, service/human separation, step-up/replay binding, emitter/human audit mapping and revocation acknowledgement protocol. |
| Acceptance criteria | Wrong issuer/audience/tenant/kind or missing MFA/session/enrollment denies; revoked/expired session and replayed step-up deny; independent approver matches exact operation; identity outage denies; no auth-to-role inference. TC-H01/TC-H02 and V14–V21 cover this. |
| Current approval status | PENDING — no authoritative owner approval recorded |
| Implementation work blocked | Human/session service and storage, OIDC/WebAuthn adapters, account recovery/break-glass, human request/approval projection and human gate activation. |

## A03 — Disposable PostgreSQL target and privileges

Exact owner approval requirement (verbatim):

> Approve exact new disposable run identity, independent instance/socket/volume/network proof, dedicated test credentials and split privileges, specific AGENTS test-target exception and future injected-connection harness plan

| Register field | A03 assessment |
| --- | --- |
| Recommended option | One exact attested rootless PostgreSQL 16 instance/database, private Unix socket, fresh private volume and dedicated lab identities; split owner/migrator/runtime/reader/writer/harness privileges and forced tenant RLS. |
| Alternatives | Dedicated disposable VM/namespace/host if container isolation cannot be independently established. Reusing an operational cluster/schema is rejected, not a fallback. |
| Security implications | Neither ai_soc nor ai_soc_test may be contacted. A DB marker or a matching name prefix is not isolation proof. Current RolePlan and repository test-target convention need a specific future exception without weakening existing guards. |
| Required evidence | Exact approved run/instance/socket/storage manifest from a trusted independent launcher, no reused credential/environment/volume/network/service path, actual role/ownership plan, injected connection design and separate future setup/teardown authorization. |
| Acceptance criteria | Protected names rejected before connection; no defaults/.env/.pgpass reuse; actual connected lab identity matches approved manifest before DDL; real nonowner logins verify RLS/forbidden access; destructive cleanup separately authorized. TC-L01 and V22–V25 cover this. |
| Current approval status | PENDING — no authoritative owner approval recorded |
| Implementation work blocked | Any lab connection, Docker/cluster setup, target-guard changes, database role creation, migrations, actual isolation/concurrency tests or teardown. |

## A04 — Production provenance and admission contract

Exact owner approval requirement (verbatim):

> Approve new production proof/admission/gate contracts, canonicalization and state commitment, bounded runtime attestations, signature distribution and state verification budget; preserve existing pure semantics and reject synthetic conversion

| Register field | A04 assessment |
| --- | --- |
| Recommended option | Separate production proof/identity/admission/gate contracts in canonical IAM; independent root/issuer/credential binding; full-state checkpoint verification; explicit new short-lived verification attestations; same-DB final gate. Preserve pure IAM-01/02/03A semantics and synthetic-only barriers. |
| Alternatives | Relabeling synthetic providers is rejected. An independent signed-decision authorization service is a possible later design but adds infrastructure/TOCTOU and duplication risk; any alternative needs its own reviewed contract. |
| Security implications | Parsing/hashes/type labels do not establish trust. A provisional policy ALLOW cannot be used as an executable capability. Do not falsely apply an old signature to retimestamped data or accept UUIDs/timestamps as revision proof. |
| Required evidence | Exact field/canonicalization/version/signature/identity delivery specification, external trust handoff, complete-state inclusions/exclusions and budget, lifetime projection rules, error precedence, final-gate/UNKNOWN outcome protocol and negative/parity tests. |
| Acceptance criteria | No synthetic conversion; malformed/mixed/omitted/stale proof denies; current source/revision/session/anchor required; exact IAM policy and approval semantics retained; no side effect without a gate. TC-P01/TC-P02/TC-G01 and V26–V36 cover this. |
| Current approval status | PENDING — no authoritative owner approval recorded |
| Implementation work blocked | Production proof types/provider/verifier/admission, cryptographic integration, authority snapshot assembly/currency and execution-gate implementation. |

## A05 — Restricted initial authority profile

Exact owner approval requirement (verbatim):

> Approve the companion 16-table restricted initial authority profile and explicit future replacement/deferral of the specified relations/FKs; accept that this is not general-purpose or operational IAM

| Register field | A05 assessment |
| --- | --- |
| Recommended option | MVA-1 evidence.metadata.read only, API_KEY_SERVICE acting principal, explicit service_integration assignment to teamless evidence, independent ALL_TENANT_TEAMS scope receipt; 16 retained tables, six deferred and one key-binding merge, with dependency-closed FK/profile changes. |
| Alternatives | Keep the full 23-table proposal until its broader features are justified; choose a different bounded profile only after re-review. No reduced schema may silently inherit general-platform capabilities. |
| Security implications | Reduced tables do not waive owner/classification/provenance/receipt/revocation/audit checks. Deferred teams, approvals and general role issuance cannot be enabled by missing data, defaults or a trusted flag. Identity/journal storage is outside this table count. |
| Required evidence | Explicit profile/schema/policy manifest and action/role/resource limits; approved retained/deferred/merged mapping, FK removal/replacement plan, typed-registry restrictions, disabled-component proof and feature-negative tests. |
| Acceptance criteria | All 23 mapped once, 16/6/1 accounting consistent; missing tables never become empty trusted components; no implicit role or metadata-to-raw/export grant; every disabled action/feature denies. TC-P01 and V37–V39 cover this. |
| Current approval status | PENDING — no authoritative owner approval recorded |
| Implementation work blocked | Schema reduction, profile-specific new columns/FKs, source resolver/query shape changes, new profile activation or deferred feature expansion. |

## Cross-decision dependencies and execution boundary

A01 authenticates D04 source keys and D02 enrollment/recovery; D02 must not be a
circular prerequisite for identifying the initial offline root custodians. A02
supplies human identity, not authorization; A04 binds it to exact policy/operation.
A03 supplies genuine future database/privilege/transaction evidence; it supplies
neither root trust nor application grants. A05 restricts D01 manifests, D02 acting
identities, D03 schema/role tests and D04 supported components. It approves no schema
until an owner actually accepts that proposal and separately authorizes work.

The source package also contains **A06 / execution**: architecture approval alone
does not authorize code, credential generation, IdP/DB setup, migrations, roles,
destructive teardown, IAM-04, deployment, commits or pushes. A06 is not silently
folded into or satisfied by A01–A05. TRUST-01 requests no approval on the owner's
behalf and initiates none of those actions.

## Smallest next step after explicit approval

Recommend **IAM-03C-TRUST-02 — bounded offline root-envelope contract prototype**:
only structural parsing/canonicalization, signer identity/quorum bookkeeping,
deterministic denial ordering and synthetic verifier-port fixtures. It needs
explicit A01/A04 acceptance of that subset plus a separate code/test authorization.
Do not implement production cryptography, generate even operational root material,
open files/services through trust interfaces, activate snapshots, change is_current
or use the current admission bridge. Positive fixture results must remain
STRUCTURAL_TEST_ONLY, never a production VerifiedAuthorityRead.

A02/A03/A05 and the remainder of A01/A04 continue to block human, database, schema,
checkpoint persistence and production gate work even if that small prototype is
approved. Scope staged trust work by accepted evidence rather than treating a
single approval as authorization for all future phases. Any material algorithm,
threshold, custody, identity, target, profile or projection change needs renewed
review, not a permissive configuration option.

## Verification and status

This register's five quotations must compare byte-for-byte with the decision
package's A01–A05 requirement cells. Links/decision/contract/test references,
PENDING statuses, whitespace and input/index preservation are checked offline.
No tests, cryptography, identity provider or database is run; no claim of production
verification follows from documentation consistency.

**OWNER APPROVALS: PENDING**  
**TRUST IMPLEMENTATION: NO-GO**  
**SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**NEXT STEP: Recommendation only — explicit owner selection/evidence, then separate bounded authorization.**
