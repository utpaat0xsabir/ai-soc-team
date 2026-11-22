# Source registry migration proposal

Revision `e4b2b2000001` stages the nine source registry tables after
`d93c6e4fb132`. G1 authorized offline migration code. Database execution and
runtime activation require separate approvals. The schema stays outside active
application metadata. All registry writes and reserved source audit inserts
are denied. The revision adds no accepting RLS policies, definer routines, or
runtime grants.

| Proposed decision | Required design and acceptance |
|---|---|
| Dedicated installations and immutable global ownership | Approve an independently authenticated physical installation identity. Keep a permanent global unique enrollment identity and tenant-qualified installation FK. Deny alias enrollment as a new installation and deny cross-tenant transfer. Verify with concurrent restricted enrollment attempts. |
| Global claim and repeat collection | Use the existing concrete global locator unique key. Authenticate the collector, lock integration, lease, checkpoint, then tenant audit row, and validate current scope, epoch, generation and digest. An exact authenticated request can return the existing receipt. A different request for the same origin remains pending owner policy. A conflicting constrained insert must roll back the candidate evidence, audit, receipt and progress. Test concurrent claims and lost acknowledgements. |
| Workload enrollment and retrieval | Approve scope, authenticated login and role OID, principal, action and credential epoch. Keep publisher and attestor separately authenticated. Proposed enrollment PK is tenant plus enrollment ID. Proposed immutable attempt PK is tenant plus attempt ID, with restrictive composite FKs to exact enrollment, receipt and configuration. Bind attempt, receipt, request and transcript digest by an exact composite attestation FK. Keep these fields outside the SV-B1 canonical attestation. Reject caller-supplied matches, wrong roles, stale attempts and reused attempts. |
| Reserved audit actions | Approve a protected binding keyed by tenant and operation ID, exact actor/action/resource, request and record digests, applicable retrieval digest, and server transaction ID. Pair it once with a unique tenant audit sequence. Use fixed action-to-table dispatch for the seven reserved actions from A1. Check the actual session login and same transaction at audit insertion and authority finish. Deferred checks must reject missing or reused linkage. Prove ordinary audit inserts still work and reserved forgeries or orphans never commit. Keep the existing tenant lock and chain calculation. |
| Suspension, activation and revocation | Approve one-way suspension only for the paired timestamp and audit reference. Reject all enrollment identity edits, history mutation and truncation. Serialize activation and revocation-sensitive writes with the tenant audit lock. Include disabled generations in the maximum. Reject stale activations and revoked retries. |
| Authoritative read | Approve scoped reads from the verified primary. A narrowly owned read operation must establish complete revocation visibility for the exact tenant and attestation, check latest generation and suspension, and fail closed on scope, availability or freshness uncertainty. An RLS-filtered miss cannot prove absence. This result grants no inference permission. |
| Lifetime and freshness | Approve policy-bound maximum lifetime, retrieval freshness, and credential epoch semantics. No values are selected here. |
| Roles and ownership | Approve restricted enrollment operator, collector, retrieval publisher, attestor, revoker, reader and audit capabilities. The classifier has source read access only; the API has ordinary audit access only. Keep migration, schema owner, routine owners, test runner, and read-only observer distinct. No runtime role gets ownership, inherited authority, direct history mutation, or `BYPASSRLS`. Scope future policies by actual `session_user`; verify `current_user` and fixed qualified definer resolution. |

## Guard and execution preconditions

Preserve the existing PostgreSQL 16, explicit pinned `ai_soc_test` target,
predecessor/successor, lock, login, membership, and privileged routine
reachability checks. For the first approved successor, pin the complete
predecessor and candidate catalogs separately. In the staged inventory require
the exact nine staged relations, FK and index definitions, forced RLS with
no accepting policies, enabled deny-write triggers, expected owner, and no
runtime execute rights. Inventory role and default ACL drift independently.
Do not infer privilege absence from an explicit grant list.

A separately approved administrative handoff must name exact function
signatures, owners, search paths, security flags, grants, and policies. Runtime
definer owners remain outside the migration role's reachable roles. Reject a
partially transitioned inventory. Require actual restricted-login tests before
enablement. The staged revision checks the expected predecessor keys, pins its
rendered statements, and verifies the disabled catalog before commit. Existing
guard checks still apply. The only staged routine is
`source_registry.deny_staged_write()`, owned by the migration schema owner,
`SECURITY INVOKER`, with fixed `pg_catalog, pg_temp` lookup and no public or
runtime execute grants. It needs no handoff. Do not transfer it to make an
accepting routine. A future separately reviewed release must name the exact
accepting signatures, narrow owners, grants and RLS policies.

Enrollment and retrieval rows model provenance, but there is no trusted
workload bridge or authenticated retrieval publisher. The reserved audit
trigger unconditionally denies the namespace at this stage. A binding row
shape alone cannot prepare an operation, accept an audit event, complete
pairing or prove same-transaction commit. Scope suspension, activation,
revocation, global claim and complete reads remain unreachable. The future
write release must add their transition and paired-audit checks while removing
the corresponding fences atomically under its separately approved handoff.

After execution approval, apply the registry DDL as one guarded transaction with bounded
locks, exact predecessor validation and no data backfill. A routine downgrade
must refuse deletion of security history. Run separately authorized disposable
target tests for RLS, grants, definer ownership, audit atomicity and restore
fencing. Preserve the E2 credential blocker independently. No authority, trust
projection, classification issuance or inference activation belongs in this
migration.

## Proposed handoff inventory

No function in the staged revision is eligible for promotion. The following
signatures are a design proposal for the later accepting release. The first
UUID in an action call selects a protected, typed request record. It conveys
no identity. Routines derive authorization from the actual session login and
the current enrollment and action grant.

| Proposed signature | Routine owner capability | Execute audience and RLS boundary |
|---|---|---|
| `source_registry.prepare_installation(uuid)`, `prepare_scope(uuid)`, `prepare_configuration(uuid)`, `prepare_suspension(uuid)` | Control-plane executor with narrowly scoped enrollment and policy reads and intent insert | Authorized operator only; exact tenant and approved source/action, with a private global uniqueness claim for enrollment |
| `source_registry.prepare_receipt(uuid)` | Collector executor with scoped evidence and checkpoint reads and intent insert | Enrolled collector only; exact tenant, scope, configuration and lease fence |
| `source_registry.publish_retrieval(uuid)` | Retrieval executor with exact receipt and configuration reads and immutable attempt insert | Independent publisher only; exact publisher/consumer enrollment and receipt |
| `source_registry.prepare_attestation(uuid)` | Attestation executor with exact receipt and attempt reads and intent insert | Enrolled attestor only; cannot publish attempts |
| `source_registry.prepare_revocation(uuid)` | Revocation executor with scoped history reads and intent insert | Enrolled revoker only; exact tenant and attestation |
| `source_registry.finish_<action>(uuid, bigint)` | Matching action executor with only the operation-specific row insert or one-way suspension column update | Same authenticated actor and transaction as prepare; exact intent and audit sequence |
| `source_registry.read_current(uuid, uuid)` | Read executor with complete keyed revocation visibility and scoped source reads | Authorized source reader or classifier; exact tenant and attestation, no writes |

Approve final function signatures, ownership assignments, executable grants
and policies in the handoff review. These are capability descriptions. No
database role names, grants, default policies, request storage, or execution
entry points are created for them by the staged revision.

## B3-F1 catalog acceptance

The protected role contract permits one membership edge: migrator to NOLOGIN
owner, with SET enabled and both INHERIT and ADMIN disabled. Any additional
edge touching either role denies migration, including dormant edges and chains
through intermediary roles. Explicit memberships in the predefined data-write
and server-file/program roles, or memberships into roles with superuser,
replication or BYPASSRLS attributes, also deny this disposable-target migration. The
guard assumes trusted superusers, catalog administrators, Docker and operating
system administrators, and excludes concurrent administrator DDL or ACL changes
during the run. It does not constrain those administrators.

The guard checks the legacy audit function body against revision
`211e576b1806` and its statement-level trigger against `20d4e84d93ca`.
The stage verifies both audit triggers, rejects audit mutation grants and
replication-mode SET privileges outside the administrative boundary, and
accepts only controlled PostgreSQL renderings of the reserved prefix
predicate. Ordinary audit inserts remain covered by the existing writer.

Catalog verification compares exact column and CHECK expression renderings
generated by the same PostgreSQL 16 server on empty temporary reference tables.
The guard uses the migration transaction for this work and drops each reference
before the next table. The migration owner requires TEMP on the approved target.
The references add no persistent schema objects and contain no evidence.
Catalog verification also checks FK actions, index backing and trigger state.

The owner must have owner-only effective defaults for tables, sequences,
routines, types and schemas, including global defaults and applicable local
additions. PostgreSQL's built-in PUBLIC defaults for routine EXECUTE and type
USAGE require separately approved provisioning before B4. Local defaults
cannot remove global grants. The staged schema retains its zero local-default
ACL inventory and the migration performs no role/default-privilege provisioning.

B4 must prove catalog compatibility on PostgreSQL 16, including temporary
reference compilation, live trigger and FK firing, role reachability,
default ACL resolution, ordinary audit insertion, denial of exact and unknown
reserved actions, and successful rollback after a failed catalog postcondition.

## B4-A1 independent observation and approvals

The B4 observer is an offline contract with separate predecessor and successor
validators. E2 still requires only the predecessor. A reviewed future adapter
must receive a pre-established independent observer connection and use one
repeatable-read or serializable read-only transaction per phase. Verify the
container pin and endpoint independently at both captures. Establish the
trusted search path before running inventoried queries. Collect server
identity and role observations from PostgreSQL, exhaust every result, record
provenance against the approved request, artifact and snapshot, and abort on
any missing or ambiguous observation. The observer role has no TEMP, no role
switch, no advisory lock, and no authority routine calls.

Approve a PG16 expression reference generated independently from the pinned
DDL on an isolated reference instance. Pin the full PostgreSQL version and
the reference artifact in the approval packet. Never derive expectations from
the catalog being assessed. The successor verifier compares the actual column
and CHECK results with this reference, and reuses the guard's prerequisite,
legacy-audit, constraint and index contracts. The observer needs none of the
owner's temporary-reference privileges. The production installer still uses
its own TEMP-backed comparison.

Before digesting historical snapshots, prove all required relations and
selected columns are visible and reject active or enabled row filtering.
Compute E2 and audit-chain checks inside the trusted collector. Persist only
identifier and digest manifests, counts, verification outcomes, and the
catalog digest. Compare before and after with writers quiesced. Capture after
rollback-scoped probes have rolled back. Any known history difference denies
acceptance.

An empty result on a FORCE RLS registry table proves no absence. Independent,
snapshot-bound evidence must establish registry emptiness, including workload,
attestation and revocation state, from the reviewed fresh install and its
unbroken write fences with administrator activity excluded, or from a
separately approved complete structural verification. An incomplete check
returns AUTHORITY_STATE_UNKNOWN. Keep offline inference and classification
isolation evidence tied to the same approved build. The observer grants no
authorization and cannot establish application isolation by reading catalogs.
The live adapter and any independent database attestation mechanism still
require review and approval.

| Gate | Requested authorization, scope and identity | Risk and least-privilege alternative | Evidence and stop condition | Status |
|---|---|---|---|---|
| B4-01 | Designate disposable ai_soc_test. Operator verifies CONNECT boundary | Target confusion. Isolate this database and exclude ai_soc | Owner and disposability record. Stop on ambiguity | **PENDING** |
| B4-02 | Inspect and pin the full local container ID and endpoint. Approved operator | Endpoint substitution. Use the exact loopback publication and address pair | Pin and matching observed session. Stop on drift | **PENDING** |
| B4-03 | Authorize restricted migrator login and process-local secret injection | Owner assumption. Time-bound the exact SET-only path | Real login, privileges and role graph. Stop on unexpected authority | **PENDING** |
| B4-04 | Authorize independent observer login and catalog/selected history reads | Disclosure or incomplete visibility. Use minimum read grants and no owner path | Approved adapter, reference pin and snapshot visibility. Stop on any unknown | **PENDING** |
| B4-05 | Approve separate restricted application and negative-test logins | Excess runtime grants. Authorize only required probes | Effective grants and login identity. Stop on escalation | **PENDING** |
| B4-06 | Approve owner TEMP use only on ai_soc_test | Temp object namespace changes. Verify existing owner capability first, no migrator or PUBLIC TEMP | Effective owner privilege and cleanup plan. Stop if scope differs | **PENDING** |
| B4-07 | Approve owner-global default ACL hardening in ai_soc_test | Affects future objects created by this owner. Revoke only disallowed defaults | Effective default ACL baseline. Stop on any nonowner default | **PENDING** |
| B4-08 | Approve schema-local default ACL scope for public and source_registry | Additive grants. Prefer verifying absence over changes | Zero registry-local rows and no unauthorized public additions. Stop on drift | **PENDING** |
| B4-09 | Approve database-scoped snapshot and isolated restore rehearsal | Shared-volume recovery risk. Use disposable database artifacts only | Verified checksum, restore, catalog and history. Stop without a recovery path | **PENDING** |
| B4-10 | Approve lock, statement and overall run budgets | Blocked writers and uncertain timeout outcomes. Keep existing per-operation limits | Operator budget and reconciliation procedure. Stop on breach | **PENDING** |
| B4-11 | Approve disposable writer and admin-change quiescence | Drift between snapshots. Quiesce only the disposable target | Named window/controller and proof before captures. Stop on overlap | **PENDING** |
| B4-12 | Approve isolated structural and fault fixtures and scoped fixture identity | Distorted security results or fixture leakage. Preserve staging fences | Inventory, fault plan and cleanup boundary. Stop if a probe touches the registry under acceptance | **PENDING** |
| B4-13 | Independently authorize one guarded execution for the approved artifact, pin and request | Committed DDL. Use only the exact predecessor/successor and disposable login | Signed execution decision and preflight packet. Stop if any gate is unresolved | **PENDING** |
| B4-14 | Independently authorize acceptance sign-off and cleanup | Ambiguous commit or premature disposal. Use independent verification and approved retention | Post-observer result, probe receipts and credential/fixture reconciliation. Stop on drift | **PENDING** |

## B4-A2 injected observer and execution prerequisites

The adapter has no engine, credential loader or transaction owner. The
approved operator must acquire the independent restricted Psycopg connection
and establish a read-only REPEATABLE READ or SERIALIZABLE transaction, the
reviewed search path and a finite statement timeout before calling it.
Use one dedicated connection and one outer transaction per capture. The
adapter checks that transaction and the server's effective transaction
settings, authenticated identities, database, endpoint and exact PG16
version family. The adapter validates the protected role graph, rejects
observer membership, and checks direct and effective capabilities, including
PUBLIC-derived CONNECT, USAGE, SELECT and callable routine access. It checks
one server snapshot before and after the allowlisted reads. The caller owns
commit, rollback and connection disposal, including on any query error.

The adapter's fixed inventory binds SQL text, bind values and types, phase,
expected width, cardinality and visibility scope. The operator must approve
the timeout and row budget before any query. The adapter verifies the
effective server timeout, drains the bounded result, and returns stable
failure codes. A revision view, history RLS, unexpected relation kind or
incomplete SELECT scope blocks data capture. Catalog misses and explicit
visibility failures remain distinct from mismatched definitions. The exact
successor expressions must match an independently approved reference digest
for the pinned DDL and actual PostgreSQL version. No reference is generated
from the observed successor.

Run the existing Docker target verifier through the explicit adapter helper
for each phase and recheck the target at the operator acceptance boundary.
The supplied pin must identify the approved disposable container, with
loopback 127.0.0.1:5432 and the expected backend client/server address pair.
SQL cannot establish Docker identity. Supply credentials only through the
separately approved process-local mechanism. The migrator, NOLOGIN owner,
independent B4 observer and negative-test login retain distinct roles. Keep
the E2 runner and observer credentials and its predecessor-only flow separate.

The successor capture is pending until acceptance. It has no registry-row
SELECTs and cannot convert FORCE RLS-filtered absence into emptiness. An
independent reviewer must supply a snapshot-bound attestation from a
separately approved complete acquisition method. Pin the exact attestation
digest and named attestor through a trusted approval channel, with an explicit
freshness policy and decision clock. The attestation binds the exact database,
endpoint, container, server and capture snapshot identity, successor revision,
all nine counts, completeness scope and evidence digest. The adapter neither
issues nor signs it. A fresh-install proof is acceptable only if separately
approved and it establishes unbroken write fences, complete coverage and no
out-of-band administrative mutation. An RLS-filtered count is never sufficient.

The operator must independently reproduce the reviewed artifact manifest
using the approved interpreter and dependencies. From the repository root,
a future offline reproduction prints the following command's output to
stdout. Compare it byte for byte with the reviewed manifest and independently
pin its SHA-256 through the approval channel.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=services/api .venv/bin/python -m app.database.source_registry_artifact
```

The manifest hashes an explicit source allowlist, includes untracked execution
files, and records revision graph and DDL identity. It excludes itself from the
dirty-state calculation and does not include credentials or payloads. The
operator must use a frozen, reviewed working tree and dependency environment
through capture, guarded execution and acceptance. The manifest does not
secure a mutable filesystem against concurrent changes and is not a release
signature or execution approval.

Before B4-13, obtain and document every B4-01 through B4-12 approval above.
Verify owner TEMP and owner-global/default ACLs, test and record the disposable
snapshot and isolated restore, capture the evidence and audit baseline, and
approve writer quiescence plus the lock, statement and overall run budgets.
Use separate structural and fault fixtures without weakening staged fences.
After any ambiguous acknowledgment, independently observe the target before
retrying. B4-14 covers acceptance, rollback-scoped probes, retention and cleanup.
All fourteen gates remain PENDING. The adapter has no execution or
authority-activation entry point.
