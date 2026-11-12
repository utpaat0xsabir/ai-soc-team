# IAM-01 — proposed identity and access-control contracts

Schema 1.0, implemented 2026-11-12. Offline/backend contract foundation only.
No authentication implementation, role provisioning, policy evaluation, API
authorization, storage, migrations, RLS, audit writes, tools or model execution.
AI-04B-2B real inference remains BLOCKED and TG-04B live Wazuh remains paused/blocked.

## Trust boundary and existing authentication

`iam_contracts.py` reuses gateway `_Contract` (strict, frozen, unknown fields
forbidden) and TrustedContext. Every IAM record is executable=false. Domain
records/references carry tenant UUIDs; no global-administrator exception exists.
Only trusted application code supplies context, authoritative records, current
evaluation time and separately obtained issuance evidence. Valid Python/JSON
contracts and literal origin labels do not authenticate their creator.

Existing `AuthenticatedPrincipal(tenant_id, api_key_id)` remains unchanged.
Proposed future API-key bridge: retain the authenticated tenant; use the API-key
record UUID as IAM API_KEY_SERVICE principal ID and authentication reference, and
as TrustedContext.principal_id for the existing one-key identity model. Never use
the raw key/hash or a model-selected tenant/principal. Logical service/user IDs
with multiple credentials would require an explicit reviewed mapping later.
The module deliberately does not import auth, db, ORM models or audit writers.

AuthenticationReference identifies SESSION, API_KEY, WORKLOAD or DELEGATION
context; PrincipalIdentity separates HUMAN, API_KEY_SERVICE, SYSTEM_SERVICE and
AI_ANALYST, active/suspended/revoked state, finite validity, assignment/membership
references and optional analyst tier. Only AI principals carry tiers. Tier grants
nothing. Current validity requires explicit supplied time and half-open windows.
Historical expired/revoked records can be represented, but current-input validation
rejects stale/revoked assignments, memberships, issuers and acting principals.
Revocation references/timestamps must agree; no durable revocation check is claimed.

## Catalogs and scopes

Proposed roles, all tenant-bound, with no permission inheritance or defaults:

| Machine ID | Proposed role |
| --- | --- |
| org_admin | Organization Admin |
| soc_manager | SOC Manager |
| l1_analyst | L1 Analyst |
| l2_analyst | L2 Analyst |
| l3_threat_hunter | L3 Threat Hunter |
| read_only_auditor | Read-Only Auditor |
| service_integration | Service Integration |
| ai_l1_service | AI L1 Service |
| ai_l2_service | AI L2 Service |
| ai_l3_service | AI L3 Service |

PermissionDefinition lists the owner's exact 34 requested action identifiers,
resource category and METADATA/RAW/EXPORT/CONTROL access kind. PermissionScope
lists exact actions/resource types/classifications; unknown strings, wildcards,
duplicates and conflicting categories deny. Catalog existence is not a grant.
Metadata read never implies raw read/export; proposal never implies invocation,
approval or execution; approval never implies execution. There is no role-to-action
mapping, inheritance, prefix matching or org-admin wildcard. Future IAM-02 must
define and evaluate those policies explicitly rather than infer them from names.

Team and TeamMembership carry tenant-local IDs, purposes, state and bidirectional
membership references. TeamScope supports ASSIGNED_TEAM (one explicit team),
EXPLICIT_TEAMS (bounded explicit list plus independent authorization reference),
or ALL_TENANT_TEAMS (no implicit list expansion; independent authorization reference
required). It never means all tenants. Current-input validation checks actual team
records/membership links, active state and matching assigned-team membership.
Team managers receive no unrelated-resource authority from these structures.

Resource holds tenant, type/UUID, owner, optional team/assignment reference,
classification and allowed scope references. PUBLIC, INTERNAL, CONFIDENTIAL and
RESTRICTED are exact classifications, independent of role; no automatic ordering
or lower-class/global-public access inference exists. Scope/resource declarations
must agree on type, exact classification and team; model override fields deny.
Metadata/raw/export remain separate actions even for the same resource.

## Assignment provenance and current-input consistency

RoleAssignment binds subject, role, exact PermissionScope, issuer provenance,
finite window and revocation metadata. Self-issued role assignments and team
memberships deny. Missing provenance or AI/API-key-service control-plane issuers
deny in current-input validation; only active human/system issuers are accepted
as structural control-plane inputs. This does not verify their actual issuing
permissions or identify a real authenticated operator.

IssuanceEvidence is supplied independently from the snapshot by trusted application
code. It binds tenant, record ID, subject-record ID, issuer, purpose, exact record
SHA-256 and validity. Assignment, membership and expanded-team scope inputs require
matching fresh evidence. Reusing a provenance ID after changing a role, action or
scope fails because content digests differ. Self-asserted evidence parsed from model
text is forbidden at the application boundary. These hashes establish consistency,
not signatures, issuer authenticity or authorization to provision roles.

`validate_snapshot` checks a complete bounded current record graph against
TrustedContext and separate evidence; it returns an immutable IAMSnapshot with
default_decision=DENY, not a permit. No requested operation is evaluated and no
gateway/model/response permission is produced. Do not treat a truthy return value
as authorization. Missing records, contradictory references, unknown versions,
tenant mix-ups, expired/revoked records and modified issued records fail closed.

Bounds: at most 64 principals/memberships/issuance records, 32 teams/scopes/
assignments/resources, 10 roles and 34 actions; explicit per-record reference
bounds, depth/node checks and a 64 KiB canonical record/snapshot ceiling apply.
Canonical UTC timestamps, sorted unique identifiers and ASCII-escaped JSON give
deterministic serialization. No data is silently truncated or fetched.

## Approval separation

ProposedOperation binds requester, executor, exact action, complete resource
metadata and parameter digest. ApprovalRecord binds operation/resource digests,
human approver, outcome, provenance and finite validity. Approver must differ
from requester and executor; AI/service principals cannot be human approvers.
Requester may also be executor only as a separate operation role; independent
human approval is still required. No queue, action runner or approval token exists.

`validate_approval` requires separately trusted approver identity and an authoritative
original operation. A model cannot substitute another human, tenant, resource,
classification or parameters by recomputing its own hashes. Revoked/expired
approval records fail current validation. A DENIED record remains DENIED; even
APPROVED remains non-executable. The helper does not establish that a real human
clicked approval, check approver/executor permissions or authorize execution.
Those concerns belong to separately approved future policy/workflow integration.

## Audit compatibility and database design

IAMAuditMetadata describes actor, tenant, exact action/resource/team scope,
role/permission context, policy version, ALLOW/DENY/UNVERIFIED report, stable
denial category, correlation UUID and aware time. Decision/reason combinations
are validated; an ALLOW metadata record is not an authorization token. Free-form
details, notes, raw evidence, credentials and secret fields are absent/rejected,
not silently redacted. Covert sensitive data in opaque identifiers is not DLP.
Use sanitized public validator errors; never log Pydantic input diagnostics.

Future trusted audit integration can map actor ID/type, attempted action, resource
and sanitized metadata to existing tenant-scoped `record_audit_event`. It must
continue using that writer's locking, per-tenant sequence, canonical hash chain,
transaction atomicity and append-only protections. IAM contract digests do not
replace audit hashes. No integration adapter or audit write is implemented here.

Future schema review should use tenant-qualified composite identifiers/FKs for
principals, teams, memberships, roles, assignments, scopes and resources, with
matching tenant predicates in RLS. PUBLIC classification and shared DB roles must
not bypass application tenant checks. These are design directions, not migrations
or a claim that RLS currently exists. Existing schemas/roles/permissions are untouched.

## Verification and next milestone

Synthetic tests cover identities, cross-tenant graphs, catalogs, team/classification
scopes, independent provenance/digests, stale/revoked inputs, self-assignment,
approval separation/downgrade attacks, immutable canonical metadata, audit-secret
rejection and forbidden I/O/dispatch. Existing pure audit hash/chain tests are safe
regressions; DB-backed auth/tenant-isolation/audit/API/concurrency tests remain
excluded. No database target/configuration was accessed.

Recommended IAM-02: separately approved pure offline RBAC/ABAC evaluation over
trusted IAM inputs, default deny, exact action/team/resource/classification scope,
explicit role-policy mappings, separation of consent/approval/execution and stable
decision reasons. No API enforcement, auth changes, provisioning, database/RLS,
audit persistence, tools or live inference without additional explicit approval.
