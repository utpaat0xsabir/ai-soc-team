# IAM-03C minimum authority schema review

Prepared 2026-11-14. **Proposal only: no existing schema/design is amended or approved.**
Companion: [D01–D04 decision package](iam03c-d01-d04-decision-package.md).
Reviewed inventory: [23-table design](iam03c-authority-schema-design.md), section 4.
All names below are proposed tables, not current repository ORM/database facts.

## 1. Conclusion and bounded meaning of minimum

Recommend a **16-table initial authority core** only for an explicitly pinned
`MVA-1` profile. Retain the other seven recommendations for separate disposition:
merge one one-to-one key binding into principals, defer four team/approval tables,
and defer two canonical-role/issuer-role-lifecycle relations whose initial sources
are the approved policy/profile/root manifest. This is a smaller architectural
recommendation, not deleting tables from a migration or editing the prior design.

The profile is a boundary for offline/isolated foundation implementation, not
permission to activate operations. It supports a verified API_KEY_SERVICE principal
with an explicit service_integration assignment whose scope is only
`evidence.metadata.read`, against an explicitly authorized **teamless evidence**
resource. The unchanged canonical IAM-02 policy remains an upper bound, not a grant.
Root/control-plane issuer and verifier identities are still independently verified
HUMAN/SYSTEM_SERVICE records; ownership alone never supplies them or the subject's
role. No special global administrator or new permission is introduced.

Explicitly outside MVA-1: human runtime admission; ordinary online role/issuer/policy
administration; team-owned resources; cases/integrations/tools/models and other
resource kinds; raw evidence, export, response execution, approval-dependent
operations and external effects. Root provisioning/recovery needs independently
authenticated, exact quorum-approved ceremony intent with separated requester and
approval identities; it is not ordinary IAM-02 roles.assign via an API service.
No missing approver table is a permission bypass. Any broader workflow remains denied.

Existing tenants/API keys receive no grants at migration. MVA-1 source acceptance
would require A01–A05 approval, future reviewed profile/schema/contract changes,
real isolated verification and separate IAM-04 enforcement authorization. Current
reader safeguards, no-snapshot outcome and is_current=False remain unchanged.

## 2. Classification of every original table

Categories describe **MVA-1**, not a claim that the full platform can omit these
security properties. “Subsequent” means the table/security feature must exist
**before** enabling the corresponding operational capability.

Phase labels: F0 = approved identity/trust/profile specification;
F1 = restricted authority schema; F2 = source/proof and snapshot verification;
F3 = team/general-role/human-approval expansion; F4 = separately authorized IAM-04.
These are planning labels mapped to package P0–P8, not new authorizations.

| Proposed table | Security purpose | Classification | Recommended phase / disposition |
| --- | --- | --- | --- |
| iam_authority_heads | One tenant/source/incarnation/policy/profile/current revision; suspended genesis | Essential for initial trusted authority | F1 retain; add reviewed state-digest binding per D04; no ACTIVE bootstrap default |
| iam_authority_revisions | Persistent monotonic counter/epoch, operation idempotency and atomic audit linkage | Essential for initial trusted authority | F1 retain; F2 verify ledger/state/checkpoint; audit sequence cannot replace revision because unrelated audit also advances |
| iam_objects | Tenant-wide typed UUID collision and revocation-reference integrity | Essential for initial trusted authority | F1 retain restricted kind vocabulary; current cross-category UUID comparisons make dropping it unsafe without a separate identity-contract redesign |
| iam_principals | Current tenant-bound identity/kind/validity/revocation and authentication binding | Essential for initial trusted authority | F1 retain; incorporate API-key binding below; F0/D02 supplies real identity evidence, not row labels |
| iam_api_key_bindings | One-to-one key-service principal association | Potentially redundant | Merge into iam_principals in the future F1 specification; preserve explicit composite key FK and exact key/principal/reference equality; do not drop integrity checks |
| iam_roles | Per-tenant canonical-role enabling/disabling lifecycle | Optional or deferrable | F3 for independently mutable role availability. MVA-1 uses only the exact rooted service_integration profile/catalog, with explicit assignments; canonical policy mapping remains code |
| iam_policy_approvals | Auditable finite approval/revocation of a pinned canonical policy digest | Essential for initial trusted authority | F1 retain; the policy code alone does not establish approved current use |
| iam_issuers | Tenant/source/key/validity for independent issuer verification | Essential for initial trusted authority | F1 retain; root pin outside DB controls trust; private issuer/root keys never stored in this row |
| iam_issuer_scopes | Explicit bounded record purposes for each issuer | Essential for initial trusted authority | F1 retain, restricted to SNAPSHOT/VERIFIER/ROLE_ASSIGNMENT/TEAM_SCOPE in MVA-1; never infer issuer permission from a role name |
| iam_issuer_roles | Mutable per-issuer ceiling over multiple roles | Optional or deferrable | F3 before general online issuance. MVA-1 has one exact role ceiling in the signed root/profile and assignment CHECK; omission never means all roles |
| iam_teams | Tenant-owned team identity/active state | Required for subsequent operational security | F3 before any team-enabled profile; absent only with explicit disabled-team schema/profile and no dangling references |
| iam_scopes | Immutable explicitly issued action/classification/resource/team mode | Essential for initial trusted authority | F1 retain; MVA-1 uses ALL_TENANT_TEAMS mode only for teamless resources with independent TEAM_SCOPE receipt, not implicit access |
| iam_scope_actions | Normalized exact scope permissions | Essential for initial trusted authority | F1 retain; MVA-1 exactly evidence.metadata.read; no direct-grant or wildcard extension |
| iam_scope_resource_types | Normalized exact authorized resource categories | Essential for initial trusted authority | F1 retain; MVA-1 exactly evidence; no category inferred from name/payload |
| iam_scope_classifications | Explicit exact classifications with no inheritance/default | Essential for initial trusted authority | F1 retain; root-approved scope and resource classification must agree; no fabricated PUBLIC/INTERNAL default |
| iam_scope_teams | Exact assigned/expanded team links | Required for subsequent operational security | F3 before ASSIGNED_TEAM/EXPLICIT_TEAMS/team resources; MVA-1 cannot reference team IDs or claim those modes |
| iam_memberships | Current issued principal/team membership with provenance | Required for subsequent operational security | F3 before any membership/team grant; key ownership is never a substitute |
| iam_role_assignments | Explicit current subject/role/scope/issuer grant | Essential for initial trusted authority | F1 retain; exact rooted one-role restriction, self-issuance rejection, uniqueness, finite validity and revocation; no automatic role from ownership |
| iam_resources | Trusted owner/classification/scoped binding to actual tenant resource | Essential for initial trusted authority | F1 retain evidence-only resolver/backing FK; source provenance cannot be inferred from evidence trust_level alone |
| iam_resource_scopes | Explicit resource-to-allowed-scope relation | Essential for initial trusted authority | F1 retain; scope assignment alone does not authorize every tenant resource |
| iam_issuance_receipts | Independent content/purpose/issuer binding for assignments/expanded scopes | Essential for initial trusted authority | F1 retain; F2 verify original evidence plus current short-lived projection attestation; no self-declared trusted flag |
| iam_revocations | Durable typed tombstones, no deleted/reused identities | Essential for initial trusted authority | F1 retain; include relevant key/principal/source/issuer/policy/scope/receipt/assignment changes; no process-only revocation |
| iam_approvals | Exact human approval/operation/resource/approver evidence and revocation | Required for subsequent operational security | F3 before approval-dependent operations or ordinary online role administration; MVA-1 disables those operations, never auto-approves them |

Accounting: **16 retained + 6 deferred + 1 merged = 23 reviewed**. No table is
silently deleted from the existing proposal. None of these tables currently exists
in SQLAlchemy models or migration definitions. Deferrals require an approved
**new restricted schema version**, not catching missing-table errors at runtime.

## 3. Dependency-closed changes required by the recommendation

The earlier full-schema DDL cannot be installed with seven tables simply removed.
Nullable FK columns still require their referenced tables. A future approved
restricted specification must do all of the following before creating migrations:

1. **Key binding merge:** add a nullable api_key_id to principals. Require
   API_KEY_SERVICE iff key binding is present; for that kind require
   principal_id=api_key_id=authentication_reference and method API_KEY.
   Composite FK `(tenant_id,api_key_id)` references existing tenant_api_keys
   `(tenant_id,id)` after additive uniqueness. Other principal kinds have no key
   binding and require their own verified authentication source. Retain current
   key revoked_at check and independent principal state/validity. Add the proposed
   credential_binding_digest for independently root-approved API-key enrollment
   and D04 authentication proof; provider never reads/exports raw key_hash. A DB
   key verifier substituted after enrollment must not authenticate that principal. This replaces
   only a redundant one-to-one relation, not key authentication or grant issuance.
2. **Role availability:** replace assignment.role_code FK to the deferred roles
   table with exact existing RoleID validation **and** MVA-1's single-role CHECK.
   The current rooted profile/policy pin is the authoritative allowed-role list;
   an empty/missing/wrong profile denies. Build only that explicitly approved
   RoleDefinition for graph consistency; it is still proposed catalog data, not
   an issuance. No default-policy or role-name grant. Disabling that role requires
   rooted profile/revision invalidation or explicit assignment revocation.
3. **Issuer role ceiling:** verify the exact role ceiling from independent current
   root/profile evidence plus issuer_scopes. No query for a missing issuer_roles
   table, no empty-list-means-any and no mutable multi-role administration. Add the
   relation before expanding to general online assignment.
4. **Team dependencies:** remove deferred-team FKs/columns from the restricted
   resource schema instead of leaving references to nonexistent tables. Resource
   team/target-team and principal team_membership_refs project empty/None only
   because a verified MVA-1 schema/profile forbids teams. Scope mode is exactly
   ALL_TENANT_TEAMS, team_refs empty; retain mandatory independently issued
   TEAM_SCOPE receipt. Reject every team ID, ASSIGNED_TEAM or EXPLICIT_TEAMS input.
5. **Resource backing:** retain explicit composite evidence FK and
   resource_id=evidence_id. Remove deferred role/team/other backing columns/FKs;
   resource_type must be evidence. Owner and allowed scopes remain explicit
   current records; assignment reference is null in MVA-1. Never infer ownership,
   classification or scope from key/tenant association. Unsupported resource types
   or missing authoritative metadata deny.
6. **Approvals:** omit approval storage/reader paths only in the version that
   forbids approval-required actions. Root provisioning approval proof belongs to
   the independent exact D01 ceremony bundle linked to revision/audit, not a fake
   IAM ApprovalRecord. Public/online privileged operations remain disabled until
   the existing human permission/approval semantics are fully supported.
7. **Typed registry/receipts:** restrict registry kinds to actual MVA-1 types;
   remove ROLE/TEAM/MEMBERSHIP/APPROVAL subtype expectations and receipt membership
   purpose from that profile. Retain PRINCIPAL, POLICY, SCOPE, ASSIGNMENT, RESOURCE,
   ISSUANCE, REVOCATION, REVISION, SOURCE and PROVIDER integrity. Key/principal ID
   equality remains the only intentional alias. Tombstones never disappear.
8. **Proof and adapter:** root manifest pins schema/profile/policy/canonicalization
   versions, supported purpose/action/role/resource sets and complete-state digest.
   MVA-1 observes disabled membership/approval components as explicitly unavailable
   features, not unverified data absence. Provider's ten components must still be
   accounted for under the approved production contract. Unexpected tables/columns,
   unsupported feature data, query failure or missing proof deny; no synthetic
   fallback, arbitrary row skipping or relaxed graph validator.

These are proposed specification changes requiring A04/A05 approval and a separate
implementation task. The original 23-table document and all current Python remain
unchanged. MVA-1 cannot be selected by a request or inferred from a database error.

## 4. Why retain the other relations?

- Do not collapse normalized scopes into free-form grant JSON to save tables;
  exact action/type/classification uniqueness, tenant FKs and provenance need
  queryable, constrained state. A signed payload is not automatically authorized.
- Do not replace revision ledger with audit sequence. Denials and unrelated business
  audit advance that sequence; authority currency and idempotency need distinct
  durable fields and atomically linked records, not a second audit algorithm.
- Do not remove policy approval because code defines permissions. Approved current
  policy content is independent authority that must be pinned/revocable.
- Do not remove issuer scopes or issuance receipts because root keys exist.
  Authentication of a signer does not authorize every purpose or exact grant.
- Do not eliminate object identity/tombstones by assuming random UUID collision is
  impossible. Existing type-less reference/revocation comparisons require an
  explicit cross-kind integrity rule or a separately reviewed contract redesign.
- Do not drop resource-scopes or owner/classification metadata on the theory that
  the read is metadata-only. Cross-tenant and same-tenant overbroad reads still matter.

Sixteen is a justified bounded recommendation, not a mathematical minimum or an
approved replacement design. Further mergers could trade table count for duplicate
invariants, polymorphic ambiguity or protocol changes; none is justified here.

## 5. Additional storage and full-platform limitations

D02 durable identity enrollment/session generation/liveness storage is a separate
identity-boundary prerequisite. D01 root manifests and pending/checkpoint journal
are independently controlled outside the authority DB. Neither is magically
provided by the 16/23 tables or a process-local cache. Exact identity schema and
provider integration require their own authorization; no total-platform table-count
claim is made. No root/identity secrets belong in these tables or documentation.

D04 adds proposed state-digest/profile proof fields to the future head/revision
specification; no new table is necessary for that commitment. Full-state hashing
includes retained authority/tombstone data and is bounded; exhaustion denies until
a separately reviewed capacity/proof design exists. Replica/cache currency or
request-subset hashing is not a substitute. No physical schema change is made now.

All retained relations keep tenant-qualified PK/FKs, role-specific RLS/privileges,
finite validity where applicable, no implicit grants, independent signatures,
monotonic revision, common writer/gate ordering and existing audit atomicity.
Those requirements do not become optional because a profile is small.

The future full platform must add the deferred team/membership/scope links before
team operation; explicit role/issuer-role state before mutable general issuance;
HUMAN/session verification plus approval persistence before approval-dependent
operations. Raw/export/response/tool/model/Wazuh operations need their own trusted
resource mappings and IAM-04 execution safeguards. Migrating a profile is itself
an authority change requiring rooted approval, new version, revision/checkpoint,
negative tests, default-deny handling of old snapshots and separate authorization.

## 6. Phase mapping, acceptance and offline review

| Review phase | Package sequence | Required evidence before progressing |
| --- | --- | --- |
| F0 — approve restricted contract | P0–P2 | A01–A05 owner decisions; root/identity/session/profile sources explicit; no circular bootstrap |
| F1 — prepare/implement restricted schema | P3 | Revised dependency-closed specification and approved migration/role plan; zero default roles/issuers, no dangling deferred FKs |
| F2 — verify source/state/snapshot | P4–P7 | C01–C10 tests; all source signatures, complete-state/checkpoint and real isolated tenant/audit/revocation evidence; no synthetic activation |
| F3 — expand security capabilities | Separate approved expansion after foundations | Deferred relation(s) and authentication/resolver/approval contracts verified before any newly enabled operation |
| F4 — operational enforcement | P8 / IAM-04 separately | Final execution gates, independent approvals, audit atomicity and explicit deployment authorization |

Future verification must test every disabled feature: a plausible team reference,
extra role ceiling, human administrator, approval, raw/export action, unknown
resource or malformed/missing source must deny even if the underlying IAM catalog
contains the name. Adding a deferred feature requires revisiting the profile and
all affected adapters/callers/tests, not toggling a trusted flag.

Offline documentation checks map all 23 names exactly once, confirm 16/6/1 accounting,
resolve links and D/A/C/P dependencies, inspect unchanged referenced symbols and
preserve all pre-existing input/index hashes. New-file whitespace and `git diff --check` passed, along with the shared
`/tmp/iam03c-decisions/validate.py` accounting/reference/preservation assertions. No executable SQL, schema test or migration is created;
no table or FK correctness is claimed from static documentation checks alone.

**Minimum schema recommendation: PROPOSED, subject to A04/A05 and the other decisions.**
**SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**NEXT STEP: Recommendation only — owner decision review, then a separately scoped restricted-specification implementation task.**
