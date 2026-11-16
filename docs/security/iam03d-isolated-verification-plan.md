# IAM-03D isolated verification plan

Plan only, 2026-11-14. **No database/container/environment is created or accessed.**
This is not authorization to implement IAM-03D, apply migrations, provision roles,
change credentials, enable snapshots or perform operational integration.
Specification: [schema design](iam03c-authority-schema-design.md).
Adversarial cases: [threat model](iam03c-authority-threat-model.md).

## 1. Prerequisites and target conflict

Resolve and approve D01–D04 in the schema design first: independent root and
restore/DBA threat model; authenticated operator/service/human identity delivery;
isolated target/privilege/command ownership; production provenance/epoch contract.
No synthetic registry, random epoch, root key supplied by DB row, fabricated
issuer or local timestamp can satisfy those gates.

The explicit task requires a future **dedicated disposable** PostgreSQL environment
that accesses neither `ai_soc` nor `ai_soc_test`. Proposed database name:
`ai_soc_iam03d_disposable_<approved_run_id>`, with a fresh isolated cluster/volume,
unique non-production identities and no access route to operational databases.
This is a proposed name convention, not a created database or wildcard permission.
The exact one-run name/server/cluster identity must be approved and pinned.

Conflict: AGENTS.md and existing database tests/RolePlan assume `ai_soc_test`;
RolePlan also accepts `ai_soc`. Neither name is permitted by this task's future-lab
requirement. Do not weaken those existing guards, set a production URL, or run
current database suites indiscriminately. Separate approval must cover a dedicated
lab harness/guard and explicit exception to the general test-target convention.
No such exception is enacted here. Until approved: **database execution BLOCKED**.

Future environment must have:

- Offline PostgreSQL version matching the approved deployment target (existing role
  generator targets PostgreSQL 16); locally available approved binaries/images,
  no implicit image pull/dependency install or external network access.
- A new database/cluster only, not a schema inside either excluded database; no
  production volume mounts, backups, data, Wazuh/Ollama endpoints or credentials.
- Separate disposable owner/migrator, fixed-tenant reader/writer/executor logins,
  and root-command capability with exact RLS/EXECUTE plan; real nonowner login tests.
- Synthetic fixtures and locally controlled test signer/root keys confined to the
  lab. These explicitly test provenance behavior and are not production trust.
  Never display private keys, connection credentials, payloads or DSNs.
- Explicit migration, role/login, recovery and test-operation authorization;
  destructive DDL/DML tests and cleanup require their own approval. Rollback-based
  tests do not authorize destroying existing objects.
- Bounded runtime/lock/statement timeouts, single heavy suite at a time, barrier-
  controlled sessions/processes, and a test report outside Git with private modes.

## 2. Guard before any connection or mutation

A future harness must require an explicit opt-in and exact approved run identity.
Parse only an injected lab DSN, with no app Settings/.env/default URL import;
reject either excluded database name, unapproved host/socket/port, unknown server
identity, non-disposable path or credentials from operational configuration **before
connection**. Never fall back to localhost/default app database on missing input.

After connecting only to that preapproved lab, verify current_database(), server
identity and current_user against the exact manifest before any DDL/DML. Verify
nonowner runtime role properties and tenant policy membership. Redact values;
report comparisons/results rather than connection strings. An apparent fixture
or schema prefix is not sufficient isolation. A guard failure aborts the run;
never retry against another database. Do not automatically enumerate/contact
operational clusters to identify the lab.

Migration code must be callable with the injected lab connection without eager
app.db/settings connections. Current `migrations/env.py` imports canonical models
and settings and ordinary app.db constructs an engine on import; dedicated future
wiring must prevent accidental defaults while preserving existing production
entry points. It requires separate code authorization; no workaround is run here.

## 3. Verification matrix — future, not executed

All tests use explicit tenant A/B fixtures and the approved lab connection. Each
case must assert deny/error outcomes **and** absence of unauthorized durable change,
revision progress, authority or misleading success audit. Do not accept SQL compile
or administrator SET ROLE as substitutes for real behavior.

| Case | Required procedure / assertion |
| --- | --- |
| V01 — Migration/default deny | Apply approved additive revisions to fresh and legacy-shaped synthetic fixtures; compare model/column/index/FK/trigger parity. Existing keys get no roles, issuer trust, policy pin or ACTIVE authority; revision-0 heads deny. Migration cannot provision provenance |
| V02 — Constraints/catalog parity | Exercise every required NULL/type/status/window/revocation pair, unsupported role/action/type/classification and uniqueness/cardinality constraint. Commit deferred constraints and assert failures; compare CHECK vocabularies to existing contracts/policy |
| V03 — Tenant/typed identity integrity | Inject B IDs into every A FK, including key binding, role, issuer, receipt, source/provider, resource scopes and approval. Test UUID collision/subtype absence, key/principal alias and prohibited reuse. Cross-tenant inserts fail; RLS cannot expose B rows |
| V04 — Identity versus permission | Authenticate synthetic valid key ownership without explicit grants; all protected actions deny. Missing/revoked key, suspended principal/tenant, unsupported HUMAN/SYSTEM/AI delivery and migrated identities deny; no tenant-membership default |
| V05 — Independent provenance | Use independent lab root pin and signer. Reject missing/unknown/row-substituted root/key/issuer/source, invalid signature/encoding/purpose, wrong role ceiling, self-assignment, expired/revoked issuer, unsigned bootstrap and copied synthetic registry. Approved test fixtures prove test cryptography only |
| V06 — Privileges/RLS/pooling | Connect as real tenant reader/writer/executor logins; test SELECT/DML/EXECUTE and attempted SET ROLE/GUC/tenant-parameter changes, inherited/PUBLIC permissions, pooled reuse and forbidden key-hash access. Reader cannot mutate or acquire write capability; runtime cannot call root command |
| V07 — Concurrent assignment | Synchronize competing same-tenant commands with one expected revision and duplicate intent; assert one effective grant, correct conflict/retry or idempotent result, no duplicate active assignment, contiguous committed revisions/audits. Verify independent tenants make progress |
| V08 — Snapshot/currency/expiry | Open repeatable-read snapshot, then commit authority changes elsewhere. Old transaction remains internally coherent but not current; fresh primary check detects mismatch. Test missing/invalid epoch, wrong tenant/source/incarnation/root, policy same-version/different-digest, clock bounds and expired authority; no stale cache/replica fallback |
| V09 — Revocation writer protocol | Race role, API-key, issuer, provider, principal, team, scope, tenant, resource, receipt, policy and approval changes against reads/gates. Every effective writer increments revision atomically and uses tenant-first lock. Expired no-op/repeated revoke cannot recreate a grant |
| V10 — Final DB execution gate | Barrier schedule: (a) revoker commits before gate lock, (b) gate owns lock before revoker, (c) old ALLOW reused after head changes. Assert fresh reauthorization or deny, operation-first ordering only when its lock predates revocation, no stale protected write committed after revocation. Audit/business/authority state consistent |
| V11 — Completeness/bounds/row shapes | Remove each required closure record/receipt/tombstone or approval component; wrong/extra columns, duplicate/conflicting records, unknown backing resource type, oversized canonical blobs and cap+1 records deny. No filtering/truncation may convert partial data into ALLOW |
| V12 — Rollback/audit atomicity | Inject failures before/after audit flush, authority change, tombstone, ledger insert, head update and deferred validation. Full rollback preserves original head/graph/evidence and no success audit. Deferred audit link cannot be omitted/mismatched; sequence/hash chains remain valid under concurrent writers |
| V13 — Connection loss/unknown commit | Disconnect before read, during transaction and during commit acknowledgement. Deny on unavailable authority; reconcile operation_id in a new approved connection for UNKNOWN outcome. Never assume noncommit, duplicate effective change or reuse an old allowance |
| V14 — Conflicts/timeouts/retries | Force serialization/deadlock/lock timeout and retry-budget exhaustion with barriers. Abort whole transaction; retry only approved categories with immutable intent/new authorization. No external I/O under gate lock; locks release and emergency revocation eventually proceeds within approved bounds |
| V15 — Restore/privileged compromise | Exercise approved D01 boundary: tampered signed content, omitted revocations, stale complete image and reset incarnation/head/audit. Show the independent rollback/witness protocol denies, or document trusted-DBA assumption and residual lack of such guarantee. Owner bypass of RLS must never be called protected |
| V16 — Policy/approval/exact binding | Existing role/action matrix and separation unchanged; replace each resource owner/team/classification/operation parameter/policy digest/approver/receipt field independently. Missing independent human authority or altered canonical artifact denies. Approval remains distinct from execute permission |
| V17 — Sanitization/lifecycle | Canary driver/validation inputs never appear in public errors or stored details. Verify dedicated reader rollback exactly once, caller closes, early failure no rollback, no commit/session creation; final gate uses its own caller-owned write transaction, not reader rollback |
| V18 — External/queued boundary | No operational network call permitted. Fake queued work with old grant must revalidate/deny at dispatch. Unsupported remote fencing/cancellation remains a blocker; database transaction success alone is not external atomicity |
| V19 — Recovery/compatibility | Disable new consumers/commands without DROP or generation reset; old application API/OpenAPI/auth/evidence/audit/Wazuh behavior preserved. Resume only after trusted head/provenance verification; rolled-back deployment never resurrects revoked authority |
| V20 — Failed attempts | Invalid/denied mutation rolls back grant/revision, then produces sanitized audit-only denial if authenticated tenant known. Unknown tenant cannot select victim audit chain. Audit outage fails closed; no invented success record or guaranteed persistence during DB loss |

Destructive mutation of audit history, database role/login creation, restore and
DDL tests are not covered by merely approving a regression run. Identify their
required authorization individually; if unavailable, report V-case blocked rather
than disabling protections or claiming complete coverage. Existing append-only
hash algorithm/trigger remains unchanged.

## 4. Evidence, acceptance and stop conditions

For each case record exact code/schema revision, isolated target attestation,
effective login capability (no secret), fixture identity, ordering/barriers,
expected/actual durable state and sanitized logs. Prove audit hashes/sequences,
all-or-nothing mutation/revision/audit behavior, tenant constraints and realistic
concurrent reads/writes; fake sessions cannot prove them. Never use production
credentials or production alert/evidence fixtures.

Stop immediately on target ambiguity, missing permission approval, network/default
configuration escape, bypass, unsupported provenance, stale allowance, omitted
audit, unbounded lock hold, inconsistent revision or unsafe recovery. Do not broaden
privileges, disable RLS/triggers, weaken TLS, rewrite history or manufacture trust
to obtain a pass. A case blocked for missing approval remains unmet.

IAM-03D acceptance requires D01–D04 resolved, all applicable V cases passed with
realistic restricted identities and failure injection, no unreported exclusions,
reviewed migration/recovery feasibility and separately approved production bridge.
It still does not authorize IAM-04 execution integration or operational rollout.

## 5. Offline validation performed in this design milestone

Only documentation consistency and existing safe code checks are run here. A
fresh guarded IAM selection uses unchanged tests/offline-selection.json, synthetic
settings and an unusable app.db, blocked SQLAlchemy construction/connections and
real socket/HTTP transport, disabled pytest cache/bytecode and /tmp fixtures:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python /tmp/iam03c_review_offline.py --iam > /tmp/iam03c-schema-design/iam.log 2>&1
```

Result: **402 focused IAM cases passed in 19.60s**. This includes 88 PostgreSQL
fake-session cases plus admission, policy, provider, contract, key/auth and import
compatibility tests; no real database behavior is claimed. The unchanged full
selected regression's **1,936 passed** is historical from IAM-03C-FIX, not rerun for
three documentation additions. All 214 excluded cases remain unexecuted; no full
collection/unrestricted pytest, SQL, Alembic or external security tool is invoked.

Final documentation checks performed: exactly 23 proposed table rows; every
listed FK includes tenant; role/action/status vocabulary traceable to contracts;
all T01–T22 mitigations map to defined V01–V20 cases; D01–D04 IDs/statuses agree
across documents; local links resolve; no unfinished placeholders; new-file
whitespace/final-newline checks; git diff --check; in-memory compilation of existing
Python files; and no input/index changes outside the three authorized additions.
Validation command: `python3 /tmp/iam03c-schema-design/validate.py` — passed.
It checked 23 unique tenant-keyed table specifications and all proposed-table
references, local links, 22 threat-to-case mappings, all four blocked decision IDs,
role/action catalog counts, absence of unfinished markers, whitespace/final newlines,
and exact three-file addition scope. Entry hashes confirmed all pre-existing
tracked/untracked inputs and index unchanged. **164 Python files compiled in
memory**, without imports, connections or bytecode. `git diff --check` passed;
new untracked documents were also explicitly whitespace-checked. These are static
checks of the written specification, not executed FK/SQL/cryptographic/concurrency
proof. Composite FK semantics were manually reviewed against the universal T rule.

These checks establish document consistency, not actual PostgreSQL correctness.

## 6. Recommendation

Resolve D01–D04 and approve a bounded future implementation/lab-harness phase with
explicit target/role/migration permissions. No connection, container, schema,
credential, policy or production contract change follows from this plan alone.

**SCHEMA IMPLEMENTATION READINESS: NO-GO**  
**OPERATIONAL IAM AUTHORITY: NO-GO**  
**NEXT STEP: Recommendation only — resolve the recorded blockers before IAM-03D.**
