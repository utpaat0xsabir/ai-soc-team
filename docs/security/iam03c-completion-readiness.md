# IAM-03C completion readiness

Latest implementation update: section 14, IAM-03C-FIX. Sections 1–13 retain the
original review findings and historical verification.

Review: IAM-03C-REVIEW, 2026-11-14. Repository HEAD: `8bffe40`.
Scope: static investigation, guarded offline verification and this document only.
No PostgreSQL connection, operational configuration read, migration, role change,
live integration, scheduling, deployment, commit or push was performed.

## 1. Executive summary

**IAM-03C is PARTIAL. Operational IAM authority is NO-GO.** The PostgreSQL
adapter is an intentionally denying query foundation, not a functioning authority
source. It reads tenant/key identifiers and key revocation through an injected
session, then raises `SCHEMA_INCOMPLETE`. `is_current()` always returns false
(`services/api/app/iam/postgres_authority.py:62`, `:97`, `:120`). The protected
bridge rejects this provider before retrieval because it admits only the exact
synthetic provider type (`services/api/app/iam/authority_provider.py:156`).

The current schema cannot supply the complete authority graph. Passing offline
tests demonstrates contract behavior and preserved denial barriers, not trusted
issuance, real PostgreSQL isolation, current revocation, least privilege or runtime
enforcement. No unauthorized successful adapter path was established in this review;
removing its safety barriers before resolving the gaps would be unsafe.

Ready to propose a bounded **IAM-03C-FIX offline readiness** phase, subject to
separate approval. Not ready to declare implementation completion or enable
freshness. **IAM-03D isolated database verification is required** before operational
trust; IAM-04 enforcement remains a later separately approved milestone.

At entry, Git had no tracked modifications and two untracked files, reported by
`git status --short` as `"ensitive filenames"` and `"ts\""`. Neither was opened,
modified or removed. Only this new readiness document is an authorized repository
change. `AGENTS.md` and `docs/development-handoff.md` remain unchanged. The handoff's
older database observations were not used as evidence of current deployed state.

## 2. Current IAM architecture

Canonical implementation paths are under `services/api/app/iam/`, not the former
flat compatibility modules. Architecture and test relocation are documented in
`docs/architecture/backend-modular-refactoring-ref01.md` (REF-01C and REF-01H2).
The requirements below are reconstructed from the current code and
`docs/security/iam01-contracts.md:8`, `:75`, `:122`,
`docs/security/iam02-policy.md:10`, `:63`,
`docs/security/iam03a-admission.md:66`, `:86`, and
`docs/security/iam03b-authority-provider.md:7`, `:29`, `:89`, `:148`.

Existing authentication hashes the supplied API key, queries an unrevoked key,
and returns its stored tenant/key UUIDs (`services/api/app/iam/auth.py:21`, `:41`,
`:69`). The tenant is obtained from the key record, not a requested tenant.
`api_keys.py:8` generates random keys; `:13` hashes them. Neither function issues
IAM permissions. The intended API-key IAM identity maps principal UUID to key
UUID, with independently verified current state; human/system/AI authentication
bridges are not implemented (`admission.py:275`).

The offline authority flow is protected synthetic registration -> coherent
ProviderSnapshot -> origin/epoch checks -> IAM-03A admission -> IAM-02 policy ->
final epoch check (`authority_provider.py:120`). IAM-01 checks the bounded record
graph; IAM-02 checks exact role/action, team, classification, ownership and approval.
An ALLOW remains non-executable. There is no production provider construction path
or IAM enforcement call site in API, analyst, gateway or Wazuh execution code;
searches for `admit`, `ProtectedAuthorityBridge`, `PostgresAuthorityProvider` and
`is_current` found definitions, compatibility exports and internal IAM calls.

Authentication and existing tenant filters continue to operate independently.
For example, `services/api/app/api/v1/evidence.py:108`, `:150` filter evidence by
authenticated tenant; `api/v1/wazuh.py:59` filters integrations by the principal's
tenant. These are not proof of action-level IAM authorization.

## 3. Verified implementation inventory

| Component | Implemented behavior | Tested evidence | Limit |
| --- | --- | --- | --- |
| `iam/contracts.py:84`, `:93`, `:111`, `:238`, `:270`, `:360` | Strict identities, finite validity/revocation, tenant references, assignments, scopes, graph and issuance digest checks | `tests/iam/test_iam_contracts.py:66`, `:83`, `:109`, `:234`, `:249`, `:279` | Contracts do not provision or authenticate authority |
| `iam/policy.py:25`, `:85`, `:98`, `:207`, `:258` | Explicit opt-in policy; intersection of role mapping, assignment scope and resource scope; independent trusted verification required | `tests/iam/test_iam_policy.py:86`, `:128`, `:141`, `:183`, `:202`, `:208` | Code policy is available; approved operational policy source is absent |
| `iam/admission.py:203` | Exact authenticated object binding, tenant validation, issuer anchors, request/operation binding, current graph, IAM-02 delegation | `tests/iam/test_iam_admission.py:57`, `:66`, `:76`, `:91`, `:120`, `:131` | Synthetic identity registry only; constructs verifier assertions inside that boundary |
| `iam/authority_provider.py:21`, `:108` | Ten equal component epochs; one provider per tenant; independent synthetic origin; pre/post currency checks; exceptions deny | `tests/iam/test_iam_authority_provider.py:45`, `:53`, `:71`, `:89`, `:127` | Exact `SyntheticProvider` type only; no operational trust transition |
| `iam/postgres_authority.py:32`, `:43`, `:50` | Injected dedicated transaction protocol, exact projected bounded SELECTs, row validation, rollback, categorized errors | `tests/iam/test_iam_postgres_authority.py:70`, `:95`, `:116`, `:128`, `:140`, `:158`, `:170` | Always errors; observation metadata is not database proof; no snapshot assembly |
| `iam/auth.py:41`, `:69`; `iam/api_keys.py:8` | Key authentication, stored tenant binding and revoked-key exclusion | `tests/iam/test_auth.py:25`, `:65`, `:79`, `:114`; `tests/iam/test_api_keys.py` | Fake DB unit tests do not prove database behavior or issuer authority |
| `database/roles.py:11`, `:68`; `app/db.py:6`, `:14`, `:21` | Existing eight-table role plan and ordinary API engine/session lifecycle | Pure role rendering and `tests/database/test_foundation_packages.py:70` | No dedicated authority transaction adapter or applied least-privilege evidence |

In this inventory, `iam/`, `database/` and `api/v1/` paths are relative to
`services/api/app/`. All subsequent abbreviated module citations use that root.
Test paths are repository-relative. Tests mentioned as coverage are synthetic or
static unless explicitly described as database-backed and excluded.

## 4. Schema compatibility analysis

The complete ORM inventory in `database/models.py` is eight tables: tenants,
tenant_api_keys, evidence_records, evidence_lineage, audit_logs, wazuh_integrations,
wazuh_sync_checkpoints and wazuh_sync_leases. `database/roles.py:11` lists the same
inventory; `migrations/env.py:17` imports those models. Static review of all nine
revision sources finds no IAM authority tables or RLS policies. This is a claim
about repository definitions, not the contents or applied revision of a database.

| Required element | Existing schema and consumer | Missing requirement / safe derivation | Consequence if assumed |
| --- | --- | --- | --- |
| Tenant identity and state | `models.py:25`: id/name/slug/created_at; adapter `postgres_authority.py:97` selects id | ID existence is derivable; ACTIVE/SUSPENDED state is not | Existing row could be treated as an active tenant without authority |
| Principal identity | `models.py:215`: key id/tenant/hash/revoked_at; `auth.py:41` authenticates key | API-key-service UUID mapping is the documented narrow mapping; kind/status/validity and other principal kinds require trusted records | A key UUID alone cannot establish a current IAM principal |
| Tenant membership | Key FK `models.py:235` binds one key to one tenant | Safe to derive credential ownership only; no general human/system/AI membership or membership lifecycle | Credential association could be mistaken for resource permission |
| Teams/memberships | No table; contract consumers `contracts.py:146`, `:160`, `:360` | Explicit tenant-local teams, active state and issued membership records required | Cannot safely establish team access or expanded team scope |
| Role assignments | No table; consumers `contracts.py:238`, `policy.py:207` | Subject, role, exact scope, issuer, validity/revocation and uniqueness must be durable and authoritative | Defaulting a service/admin role would create grants |
| Permission mapping/scopes | No database mapping; `policy.py:25`, `:98` contain development role/action policy; `contracts.py:221` defines scopes | Exact mappings can remain reviewed immutable code if independently approved and digest/version bound; actual subject grants and scopes cannot be derived from role names | Catalog entries become unintended permission grants |
| Resource authorization metadata | Evidence tenant/hash/trust/schema fields `models.py:90`, `:132`, `:139`, `:151`; Wazuh tenant/active `:413`, `:444` | Existing tenant ownership is reusable; IAM owner/team/classification/assignment/allowed scopes absent (`contracts.py:253`) | Evidence trust_level/schema_version are not IAM classification/policy version |
| Authority revision/version | No authority generation; checkpoint generation `models.py:562` is sync progress | Need tenant/source-bound generation covering every authority mutation and approved policy digest | Old authority can appear current after revocation or policy change |
| Revocation | `models.py:257` persists only key revoked_at; `auth.py:49`, adapter `:114` consume it | No principal/grant/member/issuer/provider/approval revocation registry, reference or shared revision; nullable timestamp alone is insufficient for complete RevocationState | Old snapshots survive changed control-plane authority |
| Provenance/issuance | Audit actor/resource/details `models.py:334`; no IAM issuer/source/receipt table | Independently protected issuer/provider anchors and exact issuance receipts required; cannot derive from digest or evidence provenance | Self-asserted authority could be laundered as verified |
| Freshness | created_at timestamps; no shared current-authority observation | Trusted clock and current generation protocol required; creation time and UUID equality cannot prove currency | Stale repeatable-read snapshot might authorize removed grants |
| Approval state | No approval table; `contracts.py:452`, `admission.py:301` consume contracts | Authoritative exact-operation human approval, validity/revocation and independent approver grants required when action needs it | Consent could be fabricated or reused for another operation |
| Audit linkage | `models.py:263`: per-tenant sequence/hash chain; `audit/integrity.py:123` writes under tenant lock | Can carry sanitized IAM references/digests, but no IAM decision persistence or authority mutation linkage exists; human actor_type is not in existing allowed values (`models.py:278`) | Unreviewed mapping or separate transaction could lose attribution/atomicity |
| Tenant-scoped reads/constraints | Key tenant FK/index `models.py:223`, `:235`; adapter predicates `:97`; lineage composite FKs `models.py:166` | Future IAM references need tenant-qualified keys/FKs and query filters; no RLS definition found | Shared role permissions alone cannot prevent cross-tenant joins |

Migration source inventory: initial tenant/evidence/lineage definitions are in
`migrations/versions/6cf3679d8b90_create_tenant_and_evidence_tables.py:24`;
key fields/index/uniqueness in `1e6b673facf2_add_tenant_api_keys.py:24`;
audit storage and mutation trigger in `211e576b1806_add_append_only_audit_logs.py:24`;
audit sequence/hash backfill and constraints in `20d4e84d93ca_add_audit_log_hash_chain.py:63`;
Wazuh integration in `5ad5e0e78db3_add_tenant_scoped_wazuh_integrations.py:24`;
evidence dedup index in `013505dd4ffd_add_unique_tenant_scoped_wazuh_evidence_.py:24`;
checkpoint/generation in `b71a4c2d9e10_add_wazuh_sync_checkpoints.py:16`;
lease/source fields in `c82b5d3ea021_add_wazuh_sync_leases.py:15`;
attempt metadata in `d93c6e4fb132_add_wazuh_attempt_status.py:14`.
All filenames after the first share `migrations/versions/`. None supplies the
missing IAM authority graph. Alembic was neither imported for execution nor run.

### Proposed migration design — design only

Prefer additive tenant-qualified authority storage, with the smallest graph that
fully supports the approved principal/action scope. Proposed names are not existing
tables: tenant lifecycle state; principal state and explicit credential mapping; teams/memberships;
permission scopes and role assignments; resource authorization metadata;
issuer/provider authority and issuance receipts; applicable approval records;
and a tenant authority revision plus retained revocation records. A reviewed
code policy can avoid a redundant role-permission table, but its approved content
digest and changes must participate in the same revision protocol.

Use tenant/id uniqueness and composite FKs on all cross-record links, indexed
lookup paths beginning with tenant, finite validity checks, paired revocation
metadata and explicit duplicate/conflict rules. Do not cascade-delete provenance
or audit evidence. Start existing identities without grants; never infer admin or
ACTIVE authority from an old key. Keep evidence hashes/lineage unchanged.

Before writing a revision, review actual dependencies, indexes, ownership,
provisioning authority, lock order, audit actor compatibility, bootstrap trust,
backfill and recovery. Every authority mutation and revision advancement must be
atomic with its authoritative audit linkage; failed changes must advance neither.
Review tenant-lock ordering against `audit/integrity.py:137` to avoid deadlocks.
Restrict authority readers to needed columns and no DML; protected writers alone
may change grants/revisions. Evaluate RLS separately; retain application filters.

Recovery should disable the new consumer and retain additive state and audit
history. Never reset authority generations, silently restore revoked grants or
rewrite old audit hashes. Database migration creation/application, ownership and
role/login changes require separate explicit authorization; none is proposed as
an action in this review. No migration file was created.

## 5. Authority provenance assessment

Role assignments originate only in supplied IAM graphs and synthetic test fixtures,
not a repository-defined PostgreSQL authority table. Permission eligibility comes
from explicit policy plus independently issued assignment scopes and resource
scopes (`policy.py:207`); `role_catalog` and `permission_catalog`
(`contracts.py:179`, `:196`) are proposed definitions, not grants. Existing key
provisioning creates credential ownership, not IAM roles
(`services/api/app/provision_api_key.py:26`, `provision_tenant.py:28`).

Admission verifies separate synthetic issuer anchors and receipt content bindings
(`admission.py:257`, `contracts.py:375`). Provider origins bind exact Python objects
(`authority_provider.py:83`); copies and matching hashes are insufficient. Both
registries are explicitly test constructs. A component able to replace protected
Python setup remains inside that trust boundary; arbitrary code compromise there
is not defeated by immutable Pydantic contracts.

The adapter checks the exact authenticated object, UUID types, context, source
tenant, executor and requested resource tenant before reading
(`postgres_authority.py:69`). It does not authenticate a database server, issuer,
source UUID or transaction observer. `InjectedReadSession.observe_transaction()`
returns assertions, explicitly not source proofs (`:43`). Protected construction,
authenticated database endpoint/transport, least-privilege credentials, trusted
issuer provisioning and policy approval must be independently established. Do not
copy synthetic registries into production or convert arbitrary rows into
`TrustedVerification(...=True)`.

## 6. Freshness, revocation and transaction assessment

`PostgresAuthorityProvider.is_current()` is deliberately false for every argument.
This review leaves it unchanged. Read success cannot currently produce a snapshot.
The observation contract requires READ ONLY / REPEATABLE READ, matching source,
exact evaluation time and observation age 0–15 seconds; identical before/after
observations are required (`postgres_authority.py:32`, `:89`, `:118`). Those checks
validate injected metadata, not actual PostgreSQL transaction properties.

The provider emits only two SELECTs, each with LIMIT 2 and fetchmany(2), projecting
no key hash or raw payload. It requires exactly one row with exact fields/UUIDs;
missing, duplicate, malformed, extra-field, mismatched and revoked-key records deny
(`:97`–`:116`). A failed read cannot yield partial authority. All exceptions inside
the transaction block become stable categories; rollback is attempted once even
on successful identity reads, and cleanup failure overrides the earlier category
(`:123`–`:131`). There is no commit, flush, retry, session creation or session close.
The caller owns the session lifetime and must supply only a dedicated read
transaction. Identity/request failures before the transaction block do not rollback;
tests assert that behavior (`tests/iam/test_iam_postgres_authority.py:87`). Reusing a
request write transaction would therefore be unsafe integration, not supported usage.

IAM-03A uses snapshot windows <=60 seconds, exact bound evaluation time,
revocation age <=15 seconds, issuer/receipt windows <=300 seconds and complete
current graph checks (`admission.py:75`, `:245`, `:253`, `:271`, `:284`). These are
synthetic validation limits, not a live revocation or anti-replay mechanism.
IAM-03B requires literal True from currency checks before/after evaluation
(`authority_provider.py:169`, `:179`). Its tests simulate epoch races; they do not
exercise concurrent PostgreSQL transactions.

Before currency can safely return true, evidence must establish all of:

1. A protected, authenticated tenant/source/principal binding and an immutable
   coherent snapshot of all ten components, including observed approval absence.
2. A durable non-reused authority generation covering tenant/key/principal states,
   roles/scopes/memberships, resources, policy content, issuer/provider anchors,
   receipts, approvals and revocations. Every relevant writer must advance it
   atomically; rollback and failed provisioning must not advance it.
3. A fresh observation of committed current generation through a trusted read
   independent of the old repeatable-read view. Re-reading the same transaction
   sees a coherent past snapshot; unchanged transaction ID/epoch is not currency.
4. Unambiguous epoch-to-tenant/source binding despite the interface accepting only
   an epoch; unknown epochs, failure, stale/future observation, conflict or missing
   records must return false or deny without cached-allow fallback.
5. Trusted time, bounded deadlines and explicit invalidation on trust/policy
   reconfiguration, connection failure and revoked authority. UUID generation by
   itself proves neither ordering nor that writers participated.
6. Real isolated tests of concurrent removal, revision changes and fresh reads,
   plus an execution-boundary protocol that closes the race after the final check.
   Pre/post evaluation checks alone cannot guarantee atomic execution or immediate
   revocation. Define locking/fencing/revalidation for the operation in IAM-04.

## 7. Tenant-isolation assessment

The adapter has explicit tenant predicates on tenant and key reads and requires
key UUID = authenticated principal UUID. It rejects request tenant/executor
substitution before SQL and rechecks returned row ownership (`postgres_authority.py:72`,
`:83`, `:97`, `:114`). Fake SQL/row tests cover these boundaries
(`tests/iam/test_iam_postgres_authority.py:95`, `:116`, `:128`). IAM-01/02/03A/03B
also reject cross-tenant graphs and anchor mismatches.

This establishes offline predicate and contract behavior only. There are no IAM
joins to verify yet. No RLS policy is defined in the reviewed migrations;
`database/roles.py:90` grants shared runtime SELECT capabilities on existing
identity tables. Database roles are not application roles. Neither grants SQL
rendering nor application checks prove the actual deployed permissions.

Relevant existing database-backed tests were inspected but not executed:
`tests/api/test_tenant_isolation.py:16`,
`tests/api/test_evidence_api.py:190`, `:241`, `:356`, `:631`,
`tests/api/test_audit_api.py:120`, `:326`, `:421`, and
`tests/database/test_database_roles_integration.py:155`.
They cover current API/database isolation, not the absent IAM schema. The selected
synthetic API suite covers foreign evidence/integration responses and revoked-key
behavior (`tests/api/test_api_routes_offline.py:14`, `:125`); real constraint,
transaction and tenant-join behavior remains unverified.

## 8. Threat-model findings

“Adapter denies” below means no authority snapshot is returned at all, not that the
missing operational property has been implemented. Test references are offline.

| Case | Expected fail-closed behavior | Current implementation and coverage | Remaining proof |
| --- | --- | --- | --- |
| Tenant A key requests B | Reject before reading B or evaluating grants | Adapter `:72`, `:83`, bridge `authority_provider.py:145`; adapter tests `:128`, policy tests `:108` | Real joins/constraints and all runtime consumers |
| Revoked principal retains old snapshot | Reject revoked or no-longer-current state | `admission.py:275`, `:284`; admission tests `:91`, `:120`; adapter always denies | Durable principal revocation plus fresh generation read |
| Role removed during operation | Invalidate decision; prevent unauthorized side effect | Synthetic epoch race tests `test_iam_authority_provider.py:127`; adapter false currency | Transactional removal and execution fencing; no current operation integration |
| Missing records | No defaults, partial snapshot or allow | Adapter exact row count `:106`, missing-row tests `:95`; graph tests `test_iam_admission.py:91` | Complete authority queries once schema exists |
| Duplicate/contradictory records | Deny rather than merge or select a winner | Adapter `:106`; duplicate/conflict tests `:95`; provider tests `:53`, `:127`; policy tests `:208` | DB uniqueness and contradictory-record semantics |
| Incomplete query result | Deny missing required graph/fields, never truncate into allow | Adapter field checks `:106`; provider ten components `authority_provider.py:28`; tests `:95` / provider `:127` | Complete joins, overflow detection, consistent observed absence for all components |
| Unverifiable provenance | Reject claimed source, flags and digests | Bridge origin checks `:161`; provider tests `:71`; adapter extra issuer/verified fields tests `:95` | Protected production anchors and authenticated origin |
| Connectivity failure | Deny with sanitized category, cleanup, no cached grant | Adapter `:103`, `:123`, `:125`; tests `:140`; synthetic provider failure/timeout tests `:127` | Real driver errors, deadlines and cleanup/pool behavior |
| Revision changes between admission/execution | Discard old allowance and revalidate/fence execution | Bridge checks before/after evaluation `:171`, `:180`; synthetic tests `:127` | No execution hook; final-check-to-side-effect race remains |
| Transactions see different revisions | Do not combine states or declare old view current | Ten equal component epochs; adapter before/after comparison `:118`; fake mixed-epoch/transaction tests `:140` | Actual PostgreSQL MVCC and fresh independent currency observation |
| Service claims excess permissions | Use only current issued scopes plus explicit policy and kind | `policy.py:207`, `:258`; policy tests `:128`, `:202`, `:244`; adapter never grants | Operational service identity and grant provenance |
| Untrusted component fabricates authority | Reject outside protected constructor/origin boundary | Exact synthetic type/origin gates `authority_provider.py:156`, `:161`; tests `:71`, `:209`; adapter ineligibility test `:158` | Trusted composition integrity; compromise of trusted Python/DB writer is outside synthetic guarantees |

Adapter `:N` and adapter test `:N` in this and the gap table mean
`services/api/app/iam/postgres_authority.py:N` and
`tests/iam/test_iam_postgres_authority.py:N`, respectively.

## 9. Gap matrix

Severity: Critical could permit unauthorized access; High prevents trustworthy
operational authorization; Medium is incomplete integration/verification; Low is
documentation/maintainability. Critical rows are conditional activation hazards,
not confirmed exploitable successes through the currently denying adapter.

| Requirement | Current implementation | Test coverage | Gap | Severity | Recommended action |
| --- | --- | --- | --- | --- | --- |
| Durable complete authority | Only tenant/key SELECTs; `postgres_authority.py:97`, `:120`; eight tables `database/roles.py:11` | Adapter tests `:70`, `:77` enumerate blockers | No principal/grant/team/resource/issuer/approval authority graph | High | Approve minimal data-source/schema design; implement only under later scope |
| Authentic provenance | Synthetic object registries `authority_provider.py:83`, `admission.py:86` | Provider tests `:71`; admission tests `:233` | Operational construction/origin/issuer verification absent | High | Specify independent trust anchors and protected delivery; retain synthetic-only gate |
| Do not trust fabricated source assertions | Observer is injected metadata `postgres_authority.py:43`; bridge rejects live types `authority_provider.py:156` | Adapter tests `:158`, `:170` | Enabling arbitrary observer/registry claims as real authority could authorize fabrication | Critical (if enabled) | Never enable by protocol conformance or trust booleans alone |
| Freshness and revocation | `is_current=False` `postgres_authority.py:62`; only key revoked_at `models.py:257` | Adapter tests `:70`, `:140`; provider tests `:127` | No durable complete revision/revocation protocol or fresh committed read | High | Preserve false; prove writer participation, atomic revision and independent read in IAM-03D |
| Prevent stale execution | Optimistic pre/post checks `authority_provider.py:171`, `:180` | Synthetic race tests `test_iam_authority_provider.py:127` | No execution fencing after final check; accepting ALLOW as capability could use revoked grant | Critical (if used for execution) | Design and verify execution-boundary revalidation/atomicity in IAM-04 |
| Transaction/read-only ownership | Dedicated protocol and rollback `postgres_authority.py:43`, `:125`; ordinary sessions `app/db.py:14` | Adapter tests `:140`; foundation wiring test | No actual observer, read-only SQL transaction or dedicated least-privilege session verified | High | Offline adapter conformance, then isolated PostgreSQL read-only/isolation/lifecycle tests |
| Complete result integrity | Exact bounded key rows `postgres_authority.py:104`; component epochs `authority_provider.py:28` | Adapter tests `:95`; provider tests `:127` | No authority joins, cardinality/overflow/completeness proof | High | Reject missing/extra/conflicting/overflow graphs; test full query mapping |
| Tenant scope | Explicit filters `postgres_authority.py:97`; graph tenant checks `contracts.py:360` | Adapter tests `:116`, `:128`; policy tests `:108` | Future tenant-qualified IAM FKs/joins and real behavior unverified | High | Tenant-scoped schema/query review and isolated two-tenant tests |
| Approved permission policy | Code mappings and scope intersection `policy.py:25`, `:207` | Policy tests `:101`, `:244`, `:255` | No protected operational policy selection/digest revision | High | Bind approved policy digest to authority generation; no default grant fallback |
| Durable IAM audit linkage | Metadata only `admission.py:153`; existing writer `audit/integrity.py:123` | Pure audit tests; DB atomicity `tests/api/test_audit_api.py:528` excluded | No integrated IAM decision/mutation audit and actor mapping | Medium | Reuse writer under approved transaction design; verify concurrency/integrity/rollback |
| Runtime enforcement | API auth/tenant dependencies, e.g. `api/v1/evidence.py:108`; no IAM callers outside IAM | Offline route contracts preserve existing behavior | APIs/analysts/gateway/Wazuh do not consume verified IAM authority | High | Separately authorize IAM-04 after trusted provider verification |
| Versioned navigation | Older docs use flat paths; canonical files exist under `iam/` | `tests/iam/test_iam_packages.py:23` | Historical path names can misdirect future work | Low | Use canonical paths; defer unrelated documentation edits |

## 10. Recommended implementation stages — none started

### IAM-03C-FIX — offline implementation readiness

Scope: resolve the authority source, schema, trust, generation, transaction and
failure contracts offline. Retain unconditional operational denial and synthetic
provider separation. Dependencies: approval of this bounded phase and decisions
on authoritative provisioning, policy ownership and supported principal types.

Expected code reach, subject to approval: `iam/postgres_authority.py` and narrowly
required provider/admission contracts; corresponding `tests/iam/` fake-session
fixtures and tests. Review all callers/compatibility exports/package tests when
interfaces change. Specify future model/role-plan/migration changes as designs;
do not add or apply them in an offline-only code phase unless explicitly included
in its approval. No new endpoints, provisioning services or authentication kinds
are needed merely to complete readiness.

Required tests: TDD positive complete synthetic graph mapping and negative missing,
revoked, stale, future, tenant/principal mismatch, duplicate/conflicting, overflow,
partial results, provenance substitution, cleanup failure and unchanged/changed
revision simulations. Assert read-only projections, dedicated ownership and no
commit/flush/connection construction; preserve bridge ineligibility and false
production freshness. Add rollback/revision/audit atomicity simulations where
logic is introduced; simulations do not replace IAM-03D. Run targeted checks then
the guarded selected suite, in-memory compilation and whitespace validation.

Acceptance: every required field has a trusted source; no inferred grants, active
states or verifier flags; exact bounds/error semantics and migration/recovery plan
reviewable; all offline regressions pass. Stop if data provenance, bootstrap issuer
trust, writer participation, policy ownership or fresh-read semantics is unresolved.
Explicit authorization is required for this implementation phase itself. Any DB
access, migration, role/credential change or runtime activation remains outside it.

### IAM-03D — isolated database verification

Scope: approved additive authority schema/migration implementation and verification
of the completed query/transaction adapter on a separately authorized disposable
`ai_soc_test` target only. Dependencies: approved IAM-03C-FIX design, separately
approved schema changes and recovery plan, trusted fixture provisioning, confirmed
non-production target and dedicated least-privilege identity.

Expected changes: reviewed `database/models.py`, new Alembic revision(s), role SQL
inventory/grants, dedicated session/transaction observer and complete provider
mapping plus isolated integration tests. Build only the approved authority subset;
missing required fields must still deny. An approved operational provider contract
must replace synthetic-only provenance explicitly; no automatic gate relaxation.

Required tests: migrate a fresh approved fixture schema and check model/index/FK
parity; cross-tenant references/reads; actual READ ONLY and REPEATABLE READ; missing,
contradictory, revoked and overflow records; fresh committed currency observations;
concurrent grant removal/policy replacement; all writer generation updates;
transaction cleanup, connection failure/deadlines, lock ordering; least privilege
and prohibited DML; audit hashes/sequences, concurrency and rollback of combined
authority/revision/audit changes. Exercise recovery without deleting audit/history.
Role/login changes and destructive test operations require their own authorization;
if unavailable, report the coverage blocker rather than weaken protections.

Acceptance: authenticated source and issuer provenance established; full coherent
state; fresh reads detect committed changes; failed operations do not change
authority/revision/audit; no tenant leaks; realistic concurrent tests pass under
restricted access. Stop on target ambiguity, elevated privilege dependency, schema
mismatch, missing writer coverage, stale read, audit/integrity failure or unsafe
recovery. No production access, production migration, login change or operational
enforcement is implied. IAM-03D needs separate explicit database and implementation
authorization; none was supplied here.

### IAM-04 — enforcement integration

Scope: consume verified authority at API, analyst, gateway and Wazuh execution
boundaries. Dependencies: IAM-03D security acceptance, approved action-to-boundary
mapping and execution race/revocation protocol. Supported identities must be
explicit; unsupported human/system/AI authentication remains denied until designed.

Expected changes: protected composition and authentication-to-authority delivery;
exact operation/resource/policy binding at each consumer; deterministic deny
handling; execution-time revalidation or transactional fencing; sanitized audit
mapping using the existing append-only writer. Preserve gateway disclosure,
consent, human approval, evidence provenance and checkpoints/leases. No external
LLM or model-provided authority. ALLOW must never become an unrestricted token.

Required tests: each boundary rejects absent/forged/stale/revoked/cross-tenant
identity and grants; allowed exact operations require all independent checks;
revocation races before the side effect; approval separation and replay/substitution;
API compatibility; failure rollback keeps evidence/audit/checkpoints consistent;
concurrency, tenant isolation, audit integrity and local fake Wazuh/Ollama guards.
Use offline fakes first and only separately approved isolated integration later.

Acceptance: no operational side effect proceeds without verified current exact
authority, independent approval where required, and consistent audit/transaction
behavior. Stop on any bypass, unverifiable state or final-check race. Explicit
IAM-04 approval is required; live Wazuh/Ollama, scheduling, deployment, production
changes, commits and pushes each retain their separate gates. L1-01 is excluded.

## 11. Verification requirements and results

Commands were run from the repository root, using the existing `.venv` interpreter;
no dependencies were installed. A temporary runner outside the repository,
`/tmp/iam03c_review_offline.py`, loads only selectors from
`tests/offline-selection.json` (44 selectors across 43 files). `--iam` filters that
list to its eight IAM modules, preserving order. It disables pytest cache and
bytecode writes, uses `/tmp/iam03c-review-pytest` for temporary fixtures and disables
third-party pytest plugin autoload. It installs synthetic config aliases and an
unusable `app.db` engine/session/get_db before importing application tests. It
blocks SQLAlchemy engine/session construction, Engine connections/raw connections,
metadata create/drop, socket connections and real sync/async HTTP transports.
Subprocess package/route tests install their own guards before application imports
(e.g. `tests/iam/test_iam_packages.py:23`,
`tests/api/test_api_routes_offline.py:125`). Mock/ASGI transport tests remain local.
The allowlist alone is not an I/O guard. No operational environment file is needed.

Exact execution commands:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-review-iam.log 2>&1
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py > /tmp/iam03c-review-selected.log 2>&1
```

| Focused IAM selection | Cases passed |
| --- | ---: |
| Contracts | 91 |
| Policy | 70 |
| Admission | 67 |
| Authority provider | 60 |
| PostgreSQL fake-session adapter | 44 |
| Authentication | 7 |
| API keys | 5 |
| Package/import-order identity | 14 |
| Total | 358 |

Focused result: **358 collected, 358 passed in 19.40s**; no failures/skips/xfails.
Initial complete selected run: **1,892 collected; 1,891 passed, 1 failed in
76.09s**. `tests/detection/test_correlation_matches.py:379` failed because the
review runner replaced SQLAlchemy's Session class with a function, preventing the
test from patching Session.execute. This was a review-harness error, not evidence
of a product defect. Only the temporary runner was corrected: preserve the Session
class and block Session.__init__ instead. No test, assertion or application code
was modified; all connection/transport guards remain. A complete rerun was then
performed because this guard change resolved an actual failure:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py > /tmp/iam03c-review-selected-rerun.log 2>&1
```

Final corrected run: **1,892 collected, 1,892 passed in 78.81s**, with no
failures, skips or xfails. This matches the selected 1,892-test baseline (delta 0);
it does not verify the 214 excluded cases. The temporary corrected runner SHA-256
is `8b5eb27b0b9cf1157f026614d3a21beb8856aac586daf15f516489ed32433e8a`.
Logs and runner are temporary `/tmp` analysis artifacts, not repository deliverables.

Additional checks performed now:

- In-memory `compile(path.read_bytes(), str(path), 'exec')` for all Python files
  under `services/api`, `tests` and `scripts`: **164 files passed**, without imports,
  bytecode generation or application execution.
- `git diff --check`: passed. Since this document is untracked, an explicit
  document whitespace/final-newline check was also performed and passed; its three
  Markdown hard-break lines intentionally retain two spaces.
- Final `git status --short`: only this new document plus the two unchanged
  pre-existing untracked files; no tracked modifications. No database/schema change.

The compilation/whitespace check was run with
`PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -` and this exact body:

```python
from pathlib import Path
paths = sorted(p for root in ('services/api', 'tests', 'scripts')
               for p in Path(root).rglob('*.py'))
for path in paths:
    compile(path.read_bytes(), str(path), 'exec')
p = Path('docs/security/iam03c-completion-readiness.md')
s = p.read_text()
assert all(line == line.rstrip() or line.endswith('  ')
           and line[:-2] == line[:-2].rstrip() for line in s.splitlines())
assert s.endswith('\n') and not s.endswith('\n\n')
print(f'In-memory compilation: {len(paths)} Python files passed; document whitespace passed')
```

Excluded: every database-backed test, all Alembic execution, live service tests and
unrestricted pytest. The historical guarded full collection is 2,106, of which 214
are outside the allowlist; full collection was not repeated here. Exclusions
include real API/tenant isolation, migration/role, audit atomicity/concurrency and
Wazuh persistence suites and the two legacy health TestClient cases described in
REF-01H2. Selected synthetic API tests cover health/readiness without that portal.
This documentation-only review introduces no production logic requiring TDD.
Unrestricted `python3 -m pytest -v` and repository-writing `compileall` were not run;
use guarded selection and in-memory compilation under the explicit restrictions.

## 12. Operational blockers

No production IAM principal/grant/issuer/resource schema or approved source mapping;
no protected operational provider origin/construction; no complete revision and
revocation writer protocol; no verified fresh currency read; no actual read-only
least-privilege transaction adapter; no isolated PostgreSQL conformance evidence;
no durable IAM audit integration or execution-boundary enforcement/race protocol.
No deployed schema, role capability, database connectivity or runtime tenant
isolation was inspected. Static SQL and fake transactions cannot establish these.

## 13. Explicit go/no-go criteria

GO for a separately approved offline IAM-03C-FIX only when its scope names affected
files, data-source decisions, acceptance tests, preserved denial gates and recovery.
This review provides a basis for that proposal, not authorization to execute it.

IAM-03C remains incomplete until all required security properties are verified:
authenticated tenant/principal and issuer/provider source; complete exact scoped
grants and resources; protected policy/approval provenance; authoritative current
revocation and revision checks; coherent bounded reads; least-privilege ownership;
and integrity/concurrency/rollback behavior demonstrated in the appropriate isolated
stage. Unit test counts alone are never completion evidence.

Operational GO additionally requires IAM-04 boundary enforcement, execution-time
revocation/race protection, independent human approvals where required and durable
consistent auditing, plus each deployment/live-service authorization. Until those
criteria pass, deny operational IAM authority even if future unit tests are green.

**IAM-03C STATUS: PARTIAL**  
**OPERATIONAL IAM AUTHORITY: NO-GO**  
**NEXT AUTHORIZED STEP: Recommendation only — separately approve IAM-03C-FIX offline implementation readiness.**

STOP after IAM-03C-REVIEW. No fixes, migrations, IAM-03D, IAM-04 or L1-01 started.

## 14. IAM-03C-FIX implementation — 2026-11-14

This section supersedes the earlier review's implementation status and next-step
recommendation. Earlier line references/results describe the pre-fix review
snapshot; current adapter references below describe this implementation.
**Offline boundary hardening is implemented; overall completion remains PARTIAL,
and operational IAM authority remains NO-GO.** Missing production schema,
provenance and persistent currency verification remain explicit stop conditions:
no authority construction, migration or operational activation was attempted.

### Changed files and bounded safeguards

| File | Change |
| --- | --- |
| `services/api/app/iam/postgres_authority.py` | Pre-query rejection of unsupported actions/policy versions, strict supplied observation flag, mapping-shaped/detached row validation, explicit provenance/revision blockers and session-ownership documentation |
| `services/api/app/iam_postgres_authority.py` | Compatibility re-export of the canonical module's new standard-library Mapping import; no duplicate implementation |
| `tests/iam/test_iam_postgres_authority.py` | 44 additional offline cases and forbidden-session-call instrumentation; existing tests/assertions retained |
| `docs/security/iam03c-completion-readiness.md` | This implementation/verification update |

No new package, engine, session factory, authority constructor, schema, endpoint,
policy rule, database role, grant or migration was introduced. Existing SEC-02
changes, `.gitignore`, `.gitleaks.toml`, security reports, instruction/handoff
files, untracked terminal artifacts and the index are outside the change scope.
Recovery means reversing only this four-file IAM-03C-FIX change, retaining prior work.

`PostgresAuthorityProvider.read` still binds the exact protected authenticated
object to tenant/key UUIDs, checked TrustedContext and source tenant, then binds
resource/executor tenant and executor principal before SQL
(`services/api/app/iam/postgres_authority.py:74`, `:90`). Invalid/missing UUID
attributes, missing tenant/key rows, revoked keys, mixed tenants/principals and
extra authority fields deny; API-key ownership never grants a role.

The adapter now rejects actions outside the unchanged IAM Permission catalog and
policy versions other than the currently supported 1.0 with `INVALID_REQUEST`
before any observation/query/rollback (`:84`). This is input rejection, not a
second policy evaluator or fallback to a default policy. IAM-02 still exclusively
computes any policy allowance through the synthetic admission path.

Transaction observations must be the exact existing observation type with an
actual supplied `True` flag before revalidation (`:96`). Pydantic Literal[True]
otherwise normalizes integer 1; the regression test uses a forged copied record
to preserve that invalid input. Complete existing contract revalidation, source,
evaluation-time, 0–15-second observation age and identical before/after observation
checks remain. This does not prove PostgreSQL READ ONLY or REPEATABLE READ.

Rows must be a bounded list/tuple with exactly one Mapping (`:113`). The adapter
copies it to a plain dictionary, then checks exact fields and UUID types before
use. A duck-typed object with iterable keys and string indexing is no longer
accepted as a mapping. Real SQLAlchemy RowMapping objects remain supported,
verified with a locally constructed Row and no engine/connection. Exact projected
SELECT columns, tenant/key predicates, LIMIT 2 and fetchmany(2) are preserved.
Extra issuer, provenance, revision, assignment or snapshot fields cannot enter
through identity rows. These checks never produce an authority snapshot.

`SCHEMA_GAPS` now explicitly includes `authority_provenance` and
`authority_revision` in addition to the existing missing graph categories.
There is no production issuer/source verifier to call; missing/unknown/unsupported
issuer claims cannot establish trust. Structurally valid identity reads still
raise `SCHEMA_INCOMPLETE` (`:131`). No verified=True flag, synthetic issuer, local
revision, timestamp or random UUID is substituted for authoritative persistence.

### Existing authority-pipeline responsibilities

The pipeline and its trust boundaries remain:

1. `iam/auth.py:get_current_principal` authenticates an unrevoked stored API key
   and binds tenant/key IDs. It is unchanged and not invoked against a database.
2. `iam/postgres_authority.py:read` validates the injected identity/read boundary;
   it cannot complete step 3 because required durable authority is absent.
3. `iam/authority_provider.py:ProviderSnapshot` requires a coherent ten-component
   synthetic state/epoch. `ProtectedAuthorityBridge.authorize` independently binds
   provider/origin/tenant and checks currency before/after admission. Its exact
   SyntheticProvider eligibility restriction remains unchanged, so PostgreSQL
   cannot enter through a protocol-shaped or fabricated provider.
4. `iam/admission.py:admit` checks protected synthetic origin, exact authenticated
   identity, tenant graph, issuer anchors, issuance/operation/request binding,
   API-key/principal state, snapshot age and revocations; it builds verification
   only inside that existing test boundary.
5. `iam/contracts.py:validate_snapshot` checks strict current graph/provenance
   consistency; `iam/policy.py:evaluate` checks independently verified exact
   role/action/team/classification/ownership/approval and returns a non-executable
   ALLOW/DENY. Their contracts, role/action catalogs and implementations are unchanged.

Missing/duplicate/conflicting grants, unsupported roles/actions, missing receipts,
unknown issuers, substituted provenance and stale snapshots continue to deny in
those existing validators. No extra snapshot validator or production trust
transition was added to work around missing persistence.

### Session, freshness and failure semantics

The existing dedicated-transaction contract is retained, not replaced with a
shared request transaction. Once the read transaction block is entered, the
adapter attempts exactly one rollback on success-to-denial or failure; the caller
closes the session. Preflight rejection and `is_current()` perform no session calls.
There is no commit, flush, close, implicit transaction start, session/engine
construction, connection acquisition or retry. Forbidden-call instrumentation
checks attempted accesses even if an exception could otherwise be swallowed.
Cleanup failure still overrides the earlier reason as `CLEANUP_FAILED`.

This resolves the test requirement about rollback side effects in favor of the
explicit existing contract: **no additional/uncontracted rollback**, not removal
of the already required dedicated-read cleanup. Removing that rollback would
break the prior contract/tests and leave transaction cleanup ambiguous.

`is_current()` is unchanged and returns False for every input without reading
session state (`services/api/app/iam/postgres_authority.py:67`). A valid-looking
read_epoch UUID is observation metadata, not a durable authority revision.
No optimistic epoch check, observation age or copied data establishes operational
freshness. Sanitized error categories remain unchanged; repeated identical cases
produce identical denials and never expose driver rows/messages.

### Test coverage and incremental verification

The unchanged reviewed `tests/offline-selection.json` remains the only execution
allowlist. The existing external runner injects synthetic settings and an unusable
`app.db`, blocks SQLAlchemy construction/connections/create/drop and real network
transports, disables bytecode/pytest cache writes and uses `/tmp` fixtures.
No production environment file or live database configuration is consulted.

Fresh pre-change IAM baseline: **358 passed in 18.84s**, including 44 adapter cases.
The 44 new cases bring the adapter to **88 cases** and the focused IAM selection to
**402**. Initial new-test run: 8 failed/394 passed; the malformed-row test was then
made specific to the first query so a later query could not mask acceptance of the
bad row. Final pre-implementation red run: **9 failed/393 passed in 19.78s**.
Failures concerned earlier rejection, numeric read-only observation, mapping shape
and explicit blocker inventory; none returned an operational ALLOW.

The first implementation run had **1 failed/401 passed in 19.39s** because checking
the flag after revalidation allowed coercion. Moving the check before revalidation
resolved that failure without changing a contract or weakening an assertion.
Final focused run: **402 collected, 402 passed in 19.56s**.

| Required safeguard | Offline coverage |
| --- | --- |
| Tenant/principal mismatch, invalid IDs | Existing binding/row cases plus six new malformed authenticated-ID cases; no session calls on rejection |
| Missing records, revoked key, contradictory/cross-tenant rows | Existing bounded identity-row suite, retained unchanged |
| Missing/unsupported/contradictory provenance and revision claims | New schema blocker, injected observation/row claim cases; existing issuer/origin and receipt conformance suites |
| Unsupported actions, roles, duplicate grants | Five new preflight action/version cases; unchanged IAM-01/02/03B catalog/assignment conflict tests |
| Invalid/stale freshness and observations | Ten new incomplete/claimed observation cases plus retained stale/future/mixed-epoch/transaction cases |
| Unexpected query shapes | Seven new malformed result cases and one real RowMapping positive-shaped-denial case |
| Execution errors, deterministic reasons and lifecycle | Four repeated-denial/cleanup combinations, forbidden method-access instrumentation and retained connection/cleanup tests |
| Missing authority revision and no currency fallback | Two new explicit blocker cases and four currency inputs with no session calls |
| Bridge compatibility and no operational ALLOW | Retained exact-provider rejection/no-fallback test, package compatibility checks, and all read cases requiring AuthorityReadError |

Exact execution commands (repository root):

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-fix/baseline-iam.log 2>&1
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-fix/red-iam.log 2>&1
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-fix/red-iam-final.log 2>&1
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-fix/green-iam.log 2>&1
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-fix/green-iam-final.log 2>&1
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py > /tmp/iam03c-fix/regression.log 2>&1
```

Final selected regression: **1,936 collected, 1,936 passed in 76.78s**, with no
failures, skips or xfails. This is the baseline 1,892 plus **44 new cases**, all in
the already selected adapter test file. No selector, excluded case, marker or
assertion was removed to obtain that increase. All sixty existing offline API
route/OpenAPI/HTTP checks and all fourteen IAM import-order compatibility checks
passed within the selection.

Final verification passed: **164 Python files compiled in memory**,
`git diff --check`, explicit four-file whitespace/final-newline checks, and entry
content-manifest/index comparison. Exactly the four listed IAM-03C-FIX files changed;
all other pre-existing tracked/untracked inputs, including SEC-02 security settings
and instruction/handoff documents, are byte-for-byte unchanged. The index remains
unchanged. AST comparison also preserves the observation contract definition,
read signature and entire `is_current()` implementation. No API/authentication,
role/action, audit hashing, Wazuh ownership, gateway or evidence implementation
was altered; selected regressions verify their existing offline contracts.
The 214 excluded cases, unrestricted pytest, live connectivity and external
security scanners are not run. Compilation uses memory rather than generating
bytecode. Offline tests do not prove PostgreSQL isolation, concurrency, least
privilege, authenticated issuer provenance or execution-time revocation.

### Remaining blockers and IAM-03D readiness

The model inventory is still the eight pre-existing tenant/key/evidence/audit/Wazuh
tables. Static migration/role-plan inspection still supplies no durable principal
state, role assignments, memberships, resource authorization metadata, trusted
issuer/provider/receipt/approval graph or complete authority generation/revocation.
API-key ownership/revoked_at alone cannot fill those gaps. No model, Alembic source
or permission plan was changed.

Ready for **offline IAM-03D preparation and blocker resolution only**, not database
verification or operational activation. Before separately authorizing IAM-03D:

1. Approve the minimal tenant-qualified authority schema/source design already
   outlined in section 4, including integrity constraints, safe initial no-grant
   state, ownership, indexes and retained provenance/audit linkage.
2. Establish protected production principal delivery, issuer/provider trust anchors
   and policy approval; source identifiers/hashes/observations are not proof.
3. Define an authoritative, non-reused revision covering every relevant writer,
   including key/grant/tenant/issuer/resource/policy/approval revocation. Mutation,
   revision and audit updates must commit or roll back atomically.
4. Define a fresh committed currency read independent of an old repeatable-read
   snapshot, with tenant/source binding, trustworthy time and bounded failures.
5. Approve a dedicated least-privilege read transaction/observer, session ownership,
   migration/recovery plan and isolated fixture/target verification. Actual schema
   changes, database access and role/login changes require separate authorization.
6. Plan real isolated tenant/integrity/concurrency/rollback tests and later IAM-04
   execution-boundary race prevention. Do not equate pre/post admission checks with
   atomic side effects or immediate revocation.

No missing operational prerequisite was fabricated. IAM-03D, IAM-04, L1 and live
integration work have not begun.

**IAM-03C-FIX: PARTIAL — safe offline hardening complete; persistent authority blocked.**  
**IAM-03C OPERATIONAL AUTHORITY: NO-GO**  
**NEXT RECOMMENDED STEP: Remaining blocker resolution and offline IAM-03D preparation; separate authorization required.**
