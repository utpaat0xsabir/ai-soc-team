# Production rollout and rollback — review plan only

Status: no production changes authorized by this document. Live inspection used
read-only sessions. Runtime/migration role changes, live schema migrations,
Wazuh permission changes, worker configuration, and scheduler activation remain
separate approval gates. Do not interpret passing tests as production activation.

## Verified starting point

- ai_soc: revision 013505dd4ffd; synchronization tables absent.
- ai_soc_test: revision d93c6e4fb132.
- Configured database identity: superuser and core-table owner.
- Wazuh UUID metadata: HTTP 403; sort mappings: HTTP 200.
- Scheduler disabled; zero jobs and zero synchronization source scopes.
- Audit append-only trigger enabled; application TLS CA readable.

Recheck these facts immediately before execution; they are observations, not
assumptions about future state. Existing uncommitted/untracked repository changes
must be reviewed and captured in an approved release artifact. No commit, push,
deployment, or secret change was performed while preparing this plan.

## Gate 1 — preflight and recovery preparation

1. Obtain approval for the exact release artifact, maintenance window, schema
   changes, role plan, and affected PUBLIC privileges. Inventory dependent logins,
   connection pools, schema owners, memberships, column grants, SECURITY DEFINER
   routines/extensions, default privileges, and database CREATE/TEMPORARY grants.
   The role generator is not a cluster-wide privilege auditor.
2. Keep scheduling disabled and stop synchronization writers. Account for manual
   ingestion and mixed-version processes; all future workers must use leases.
3. Take an approved consistent backup/snapshot, including roles/ACL metadata, and
   verify restore on isolated infrastructure. Define downtime and recovery limits.
   A backup file existing is not a verified recovery procedure.
4. Verify existing evidence hashes and audit chains read-only. Record the tenant
   chain heads externally without exposing alert payloads or credentials.
5. Run regression tests on ai_soc_test and phase tests under the restricted role
   profile. The three mutation tests remain excluded under the standing ban on
   destructive database operations; report that verification limitation.
6. Verify PostgreSQL 16 compatibility and compare actual schema to the expected
   revision/model. A matching Alembic version alone does not prove no manual drift.
   The current /ready endpoint only checks connectivity, not schema compatibility.

## Gate 2 — separately approved production migrations

Required upgrade path:

| Revision | Change |
| --- | --- |
| b71a4c2d9e10 | Integration ownership key and empty checkpoint storage |
| c82b5d3ea021 | Fenced leases and nullable durable source identity |
| d93c6e4fb132 | Nullable attempt status metadata |

Use an authorized migration operator, with runtime writers paused. Inject its
database credentials through the approved secret mechanism; never put passwords
in command arguments, review SQL, tickets, or logs. The initial upgrades may use
the existing authorized schema administrator because ownership has not yet been
transferred. That is a migration operation, not approval for the application to
continue running as superuser.

Before approval, review generated upgrade SQL and lock behavior. Apply the exact
path to d93c6e4fb132 with finite lock/statement timeouts and stop on the first error.
Do not downgrade older audit migrations or remove audit triggers. Afterward,
verify revision, constraints, enabled audit trigger, existing row counts, evidence
integrity, and audit chain heads. Existing integration ownership must match its
preflight snapshot; no historical synchronization progress may be inferred.

These three pending upgrades are additive, but they acquire schema locks. A
failed transaction should roll back; if any earlier upgrade already committed,
retain its additive schema and inspect before proceeding rather than guessing
that the entire sequence was undone.

## Gate 3 — separately approved role and credential cutover

Generate the SQL offline with scripts/prepare_database_roles.py and review it
against the inventory. It requires the upgraded schema, new role names, and an
administrator authorized to transfer ownership and revoke affected PUBLIC ACLs.
Execute only the approved artifact in the target database with stop-on-error.
The database/revision guard runs before role creation; ownership/ACL changes are
one transaction. The generator itself does not execute anything.

Capability roles are NOLOGIN. Provision separate fresh non-superuser application
and deployment logins through the approved administrator workflow, with secure
interactive credential provisioning or an approved secret service. Required
membership relationships are:

- Application login: INHERIT, member of ai_soc_runtime with INHERIT TRUE,
  SET FALSE, ADMIN FALSE; no owner/migrator membership or other elevated grants.
- Deployment login: NOINHERIT, member of ai_soc_migrator with INHERIT FALSE,
  SET TRUE, ADMIN FALSE; explicit CONNECT to ai_soc. Deliberately SET ROLE to
  ai_soc_owner for migrations. Keep this identity out of application processes.

Do not automatically demote/drop the original ai_soc role or change database
ownership: inventory its ownership and operational uses first. Retire/rotate
application access to its old credentials only as a separately approved action.
Update the API/worker secret reference to the new application login, reconnect
all pools, then prove the effective current_user/session_user are non-superuser
and lack ownership, role-creation, bypass-RLS, and elevated memberships. Verify
real login authentication; administrator SET ROLE tests do not establish that.

Smoke-test authenticated evidence ingestion, integrity, lineage, audit chaining,
integration visibility and tenant denial, synchronization status, and the legacy
ingestion route. Confirm permissions through catalog queries rather than trying
destructive audit/evidence mutations. Separate provisioning commands from runtime:
the runtime profile cannot create tenants, API keys, or integrations.

## Gate 4 — Wazuh and tenant-scope approval

Review the exact index metadata permission required for UUID discovery; preserve
read-only alerts access, TLS verification, and least privilege. Do not grant
write/admin permissions or silently bypass the 403. Verify real mappings and PIT
behavior after the separately approved permission change.

Establish dedicated source ownership or a trustworthy server-enforced organization
field/value mapping. Do not invent organization IDs or trust arbitrary log text.
Select bootstrap history, overlap, safety delay, interval, and retention settings
from actual source behavior. Finite event-time overlap cannot guarantee arbitrary
late arrivals. Define reconciliation and retention-gap response before activation;
data removed before bootstrap cannot be recovered by this application.

## Gate 5 — controlled synchronization, then scheduling

After explicit authorization for live ingestion, run one bounded manual window
with the restricted application login. Validate imported evidence hashes, audit
chain continuity, checkpoint/attempt state, replay deduplication, and lease
ownership. A failed request may still have earlier committed pages; inspect
durable status rather than resetting checkpoints.

Only after another explicit production-scheduling approval, provide scoped worker
jobs and environment-referenced tenant API keys. Do not copy secret values into
job configuration. The enable setting and --allow-production are both required
for the live ai_soc worker, but flags are not a substitute for human approval.
Start with one integration and monitor safe status, logs, latency, source retention,
and progress. Serial processing can delay other jobs; choose capacity/intervals
accordingly. A service supervisor/deployment artifact is not installed by this plan.

## Recovery and rollback

- On failure, stop scheduling with SIGINT/SIGTERM, disable its enable setting, and
  pause affected writers. Allow an atomic page to finish; do not force-reset a
  checkpoint or steal a live lease. Wait for expiry after an unclean process exit.
- Retain additive tables, attempt metadata, and committed evidence/audit/progress.
  Automatic downgrades intentionally refuse to discard synchronization state.
- Roll back only to a separately verified compatible application artifact while
  retaining restricted runtime access. The current legacy endpoint is tested
  under the profile; this does not certify arbitrary older application versions.
  Do not restore superuser application credentials as an automatic rollback.
- If the role transaction failed, verify whether it rolled back before retrying.
  If it committed but a permission is missing, have an authorized administrator
  inspect and approve the smallest corrective grant; do not use GRANT ALL.
- Use the tested backup/restore procedure only under explicit recovery approval.
  Preserve external audit heads and record any unavoidable history gap. No
  destructive restore, database reset, role drop, or retention deletion is
  authorized by this document.

## Audit-lock protocol cutover — preparation only

The active writer remains `tenant-row-no-key-update-v1`. The isolated
`advisory` role profile and `_record_audit_event_advisory_candidate` are not
activation mechanisms. Production activation requires a separate approved
release and maintenance window.

### Writer inventory and controls

All current code paths call the shared `record_audit_event` writer:

| Writer | Entry point and start mechanism | How to pause, drain, and stop |
| --- | --- | --- |
| Evidence creation and lineage | `app.api.v1.evidence`; API server (`uvicorn app.main:app --app-dir services/api` is the documented development command) | Close API admission, drain requests, stop every API worker |
| Legacy Wazuh page ingestion | `app.main.ingest_wazuh_alerts`; same API server | Close API admission, drain requests, stop every API worker |
| Wazuh synchronization | `app.integrations.wazuh.sync_wazuh`; called by API or `python3 scripts/run_wazuh_scheduler.py` | Disable scheduler, stop it cooperatively, close API admission, drain requests, stop workers |
| Development IAM decisions | `app.iam.development`; same API server | Close API admission, drain requests, stop every API worker |
| API-key provisioning | `python -m app.provision_api_key` | Freeze operator invocation and wait for any running command to exit |
| Wazuh integration provisioning | `python3 scripts/provision_wazuh_integration.py` | Freeze operator invocation and wait for any running command to exit |

The repository has no production API or scheduler supervisor manifest, so the
exact service-manager commands and proof of complete process coverage must be
provided by the deployment owner before activation. Health labels or process
names alone do not prove all writers are stopped.

### Protocol identification

Each SQLAlchemy connection opened by the application sets PostgreSQL
`application_name` to `ai-soc-team/tenant-row-no-key-update-v1`. During a
maintenance window, inspect `pg_stat_activity` for every application login and
record PID, application name, state, and transaction start. The identifier helps
show the protocol used by connected sessions; it can be spoofed and does not
prove an idle, disconnected, or unlisted process is absent. Pair it with the
service-manager/process inventory, immutable release digest, and the full-stop
barrier below. One-shot provisioning commands must be frozen and run only from
the approved artifact after the barrier.

### Forward cutover

1. Approve the exact artifact, role profile, maintenance window, outage limit,
   and recovery plan. Capture the current release identity and externally record
   verified per-tenant audit heads.
2. Close admission to all audit-producing HTTP routes. Disable and stop the
   Wazuh scheduler; freeze both provisioning commands and any other operator
   writer. Prevent new processes from starting.
3. Let in-flight requests and synchronization pages finish or abort through
   their normal transaction boundary. Stop all old API/scheduler processes.
4. Verify the deployment inventory has no old writer process and inspect
   `pg_stat_activity` until no application transaction or pool session remains.
   If any process or session cannot be accounted for, keep admission closed.
5. Start every writer from one immutable candidate release. Verify each API
   instance and scheduler database session reports the candidate protocol via
   `application_name`; verify the release digest separately from the deployment
   inventory. Confirm the expected advisory role profile through catalog
   inspection; do not infer it from the generated SQL alone.
6. Verify audit-chain continuity and recorded heads. Resume API admission and
   scheduled/manual writers only after every check passes.

The protocol marker, role-plan rendering, and database session inventory are
checkable. Pausing all entry points, proving process completeness, release
uniformity, and deciding whether to resume remain operator-enforced; this
repository does not automate them.

### Full-stop rollback

1. Close all audit-producing HTTP admission, disable and stop the scheduler, and
   freeze provisioning commands.
2. Drain or abort in-flight transactions, stop every candidate process, and
   verify no candidate process or application database session remains.
3. Start all writers from the single previously approved row-lock artifact.
   Verify its release digest and `tenant-row-no-key-update-v1` identifier on
   every API and scheduler connection before reopening admission.
4. Verify chain continuity and recorded heads, then resume writers. Never roll
   back only a subset: mixed row/advisory writers can race on the same chain
   head. Audit rows written by the candidate need no format conversion, but
   recovery still requires the full stop and protocol check.

### Transaction and error policy

The candidate requires PostgreSQL `READ COMMITTED` and a finite 5-second
transaction-local `lock_timeout` before advisory-lock acquisition. The current
SQLAlchemy engine does not set an isolation level or runtime lock timeout; the
database default and deployed role/session settings must be verified and made
explicit in a separately approved activation change. A lock timeout aborts the
whole business transaction; do not commit partial evidence, audit, or checkpoint
work.

For SQLSTATE `23505` (unique violation), `40001` (serialization failure),
`40P01` (deadlock), and `55P03` (lock unavailable/timeout), roll back the entire
business transaction before returning or retrying. Do not retry an audit append
alone. `23505` is a protocol/chain anomaly and must not be retried automatically.
The application currently has no generic database retry policy. Any future
`40001` or `40P01` retry must restart the complete operation in a fresh
transaction, be bounded (at most two retries), and require a proven idempotency
key and no non-transactional side effects. `55P03` fails closed; no immediate
retry. No such retry is implemented by this preparation.
