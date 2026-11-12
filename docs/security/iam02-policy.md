# IAM-02: offline authorization policy 1.0

This milestone implements pure evaluation in `services/api/app/iam_policy.py`.
Every contract retains IAM-01 schema version `1.0` and `executable=False`.
There is no authentication bridge, API enforcement, grant issuance, durable audit,
approval queue, database access or integration with executable gateway paths.
An ALLOW is a policy decision, never an executable capability. Independent gateway,
disclosure, consent and runtime eligibility checks remain mandatory.

## Inputs and authority

`evaluate` requires an exact IAM-01 `TrustedContext`, authoritative `IAMSnapshot`,
`AuthorizationRequest`, explicit `AuthorizationPolicy`, aware evaluation time,
issuance evidence and a separate `TrustedVerification` snapshot. No default policy
is substituted when policy is absent. `default_policy()` explicitly constructs the
proposed development policy; it does not issue assignments.

`TrustedVerification` represents protected application-side verifier output. It
binds authenticated principal and authentication-reference hashes, complete current
IAM snapshot, approved policy digest and every independently verified issuance
receipt. It separately affirms issuer authentication and issuer authorization to
issue those records. For approval operations it also binds independently verified
approval provenance and the exact approval digest. Its validity window is at most
300 seconds, evaluated using caller-supplied trusted time.

Hashes, booleans, provenance labels and structurally valid contracts cannot prove
their own origin. The caller must protect this input channel and independently
authenticate/authorize issuers, verifier, policy and approval evidence. Untrusted
request/model objects must never populate these inputs. No such operational
verifier or issuance mechanism is implemented here. Missing verification denies;
tests use synthetic trusted fixtures, not operational authentication evidence.
Fresh snapshots include current revocation state. There is no durable revocation,
replay prevention, signature verification or freshness retrieval in this evaluator.

## Explicit role policy

No role inherits another role. Every permission must also appear in a current,
verified assignment scope and in the resource's allowed scope references.
Names below abbreviate only this documentation; code uses exact IAM-01 identifiers.

| Role | Explicit permissions in policy 1.0 |
| --- | --- |
| org_admin | users.manage, teams.manage, roles.assign, integrations.manage, models.read, models.configure, models.approve, audit.read, audit.verify, knowledge.read, detection_rules.read |
| soc_manager | alerts.read, alerts.triage, alerts.assign, evidence.metadata.read, evidence.raw.read, evidence.export, evidence.lineage.read, cases.read, cases.create, cases.assign, cases.investigate, cases.close, threat_intel.lookup, threat_intel.export, tools.propose, tools.invoke.approved, response.propose, response.approve, models.read, knowledge.read, knowledge.update.propose, knowledge.activate, detection_rules.read, detection_rules.update.propose, detection_rules.activate, audit.read, audit.verify |
| l1_analyst | alerts.read, alerts.triage, evidence.metadata.read, evidence.lineage.read, cases.read, cases.create, tools.propose, knowledge.read, detection_rules.read |
| l2_analyst | alerts.read, alerts.triage, evidence.metadata.read, evidence.raw.read, evidence.lineage.read, cases.read, cases.create, cases.investigate, threat_intel.lookup, tools.propose, response.propose, knowledge.read, detection_rules.read |
| l3_threat_hunter | alerts.read, evidence.metadata.read, evidence.raw.read, evidence.lineage.read, cases.read, cases.investigate, threat_intel.lookup, tools.propose, response.propose, knowledge.read, knowledge.update.propose, detection_rules.read, detection_rules.update.propose |
| read_only_auditor | audit.read, audit.verify, evidence.metadata.read, evidence.lineage.read, cases.read, alerts.read, detection_rules.read, models.read |
| service_integration | alerts.read, evidence.metadata.read, tools.invoke.approved, response.execute |
| ai_l1_service | alerts.read, alerts.triage, evidence.metadata.read, evidence.lineage.read, cases.read, cases.create, tools.propose, knowledge.read, detection_rules.read |
| ai_l2_service | alerts.read, evidence.metadata.read, evidence.raw.read, evidence.lineage.read, cases.read, cases.investigate, tools.propose, knowledge.read, detection_rules.read |
| ai_l3_service | alerts.read, evidence.metadata.read, evidence.raw.read, evidence.lineage.read, cases.read, cases.investigate, threat_intel.lookup, tools.propose, knowledge.read, knowledge.update.propose, detection_rules.read, detection_rules.update.propose |

Human roles require HUMAN identities. Service Integration requires API_KEY_SERVICE
or SYSTEM_SERVICE; response.execute additionally requires SYSTEM_SERVICE. AI roles
require AI_ANALYST and the matching tier, plus independently issued assignments;
tier alone grants nothing. AI approval, response execution, administration, model
configuration/approval and activation are prohibited independently of role mappings.
Admin/approval/activation and model configuration actions require humans. There are
no wildcard permissions, global administrators, automatic exports or implicit
metadata/raw/propose/approve/execute relationships.

## Scope and classification

Tenant checks cover every supplied tenant-bound identity, membership, assignment,
scope, verification and approval before grant evaluation. All references must
resolve consistently through IAM-01 snapshot validation before ALLOW. Principal,
assignments, memberships, issuers and approvals must be current and unrevoked.
Duplicate records or duplicate role/scope assignments deny rather than aggregate.

For team-owned resources, active membership in that team is mandatory, including
for ALL_TENANT_TEAMS scopes. ASSIGNED_TEAM and EXPLICIT_TEAMS must include the exact
team; expanded scopes require IAM-01 independent issuance evidence. Teamless
resources require independently verified ALL_TENANT_TEAMS scope. Tenant membership
alone never grants resource access. Cases investigate/close additionally require
resource ownership or an exact assignment reference.

PUBLIC, INTERNAL, CONFIDENTIAL and RESTRICTED are exact classification values:
both action policy and explicit resource-bound assignment scope must include the
actual value. No classification inheritance or downgrade occurs. Development
action rules permit all four values only subject to this explicit scope. Metadata,
raw content and export permissions remain separate. Unknown resource/action types
and scopes lacking sufficient attributes deny.

## Approvals and operations

Request operation UUID, exact resource metadata and canonical parameter digest form
an IAM-01 ProposedOperation. This first policy requires the authenticated requester
also be executor; delegated execution cannot be safely inferred from IAM-01 data.
Approval records bind the complete operation/resource digests, tenant, current
authoritative human approver, validity and independent provenance. Requester and
executor must differ from approver. Approval never supplies the execute grant.

| Requested action | Required human approver permission |
| --- | --- |
| response.execute | response.approve |
| models.configure | models.approve |
| evidence.export | evidence.export |
| threat_intel.export | threat_intel.export |
| tools.invoke.approved | tools.invoke.approved |
| knowledge.activate | knowledge.activate |
| detection_rules.activate | detection_rules.activate |
| roles.assign | roles.assign |
| integrations.manage | integrations.manage |

Where IAM-01 has no distinct approval permission, policy explicitly requires an
independent human holding that exact action within the same resource/classification/
team scope. Checking approver authority does not recursively execute that action or
request another approval. Extraneous approval on an action requiring none denies.
No operational response, tool invocation or role assignment occurs.

## Decisions, precedence and audit

Immutable decisions contain schema version, ALLOW/DENY, stable reason, policy
version/digest, context, correlation UUID, action/resource references, time and,
once constructed, exact operation/resource digests. Audit metadata contains only
identifiers, actor kind, matched assignment/scope/team, decision and policy context;
no credentials, raw evidence, prompts or arbitrary error text. Unknown action text
is omitted rather than echoed. Cross-tenant denial may retain the attempted target
tenant reference for audit while actor identity remains bound to trusted tenant.
Metadata is prepared only; existing append-only hash chains and storage are untouched.

Precedence is deterministic: malformed trusted context/request raises a sanitized
validation error; tenant violations precede snapshot/identity checks, executor and
unknown action/version/policy checks, independent verification, resource resolution,
principal-kind/missing grants, team mismatch, classification restrictions,
ownership, full snapshot graph validation, then approval failures. Malformed or
conflicting inputs never fall back to ALLOW. Equivalent valid input orderings use
canonical IAM-01 serialization; matching assignments are selected by sorted UUID.

## Verification and limitations

`tests/test_iam_policy.py` covers positive decisions, every explicit role identity,
privileged mapping exclusions, all action separation pairs, tenant precedence,
expired/revoked records, provenance substitution, role spoofing, scope/classification,
ownership, approval separation and exact digest binding, determinism, immutability
and sanitized failures. A positive approval path also runs with filesystem, socket,
subprocess, database/model imports and gateway execution forbidden.

Runtime authorization, trusted verifier integration, durable audit, concurrency
with revocation and operational issuance remain unimplemented. Next separately
approvable milestone: IAM-03 trusted snapshot/admission bridge design and offline
verification, explicitly specifying authenticated issuer authority and revocation
freshness before any later API or executable gateway integration. Real inference
and live Wazuh remain blocked and unchanged.
