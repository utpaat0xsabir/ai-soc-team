# Restricted PostgreSQL roles — prepared and tested, not applied live

The readiness review found that the configured application role is a superuser
and owns core tables. This profile removes those capabilities from a future
runtime identity. It does not modify that existing role, supply credentials, or
activate production ingestion.

## Capabilities

| Role | Purpose |
| --- | --- |
| ai_soc_owner | NOLOGIN owner of the eight application tables, Alembic version table, and audit mutation guard function; trusted DDL capability |
| ai_soc_migrator | NOLOGIN capability with SET access to owner, no automatic inheritance or membership administration |
| ai_soc_runtime | NOLOGIN application capability, no ownership or role memberships |

All three are NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS,
and NOINHERIT. They are capability groups, not usable login accounts. Existing
names cause CREATE ROLE to fail, rather than silently reusing a privileged role.
Separate application and deployment logins must be provisioned by an explicitly
authorized administrator during a later cutover. No passwords are generated or
printed by this tooling.

## Runtime permissions

| Objects | Grants |
| --- | --- |
| tenants, tenant_api_keys, wazuh_integrations | SELECT |
| evidence_records, evidence_lineage, audit_logs | SELECT, INSERT |
| wazuh_sync_checkpoints, wazuh_sync_leases | SELECT, INSERT, UPDATE |
| tenants.created_at, wazuh_integrations.created_at | UPDATE on these columns only, needed for existing locking SELECTs |
| Application schema | USAGE, not CREATE |
| Application database | CONNECT, not CREATE or TEMPORARY |
| alembic_version | No runtime access |

No DELETE, TRUNCATE, REFERENCES, TRIGGER, ownership, or grant options are given to
runtime. Evidence/audit history cannot be updated through this profile. API keys
and integrations cannot be created or reconfigured by runtime. Administrative
provisioning scripts must use a separately authorized operator identity.

PostgreSQL requires UPDATE privilege for row-locking SELECTs. The two created_at
column grants permit existing tenant/audit and integration locks without broad
table UPDATE. They also permit actual changes to those two metadata timestamps:
this is a deliberate residual capability, not a lock-only permission. It does
not permit updating tenant IDs, integration ownership, credentials, evidence, or
audit rows. A future alternative would require a separately reviewed lock-service
design; no SECURITY DEFINER functions were introduced here.

The profile explicitly revokes table and separate column grants from PUBLIC and
the fresh runtime capability before granting its allowlist. Schema CREATE and
database CREATE/TEMPORARY are revoked from PUBLIC. These PUBLIC revocations can
affect other logins sharing this database: inventory them before approval and
grant any independently justified operator privileges explicitly. They are not
an instruction to revoke privileges on unrelated databases. New application
tables receive no automatic runtime grants; review each future migration and
update this profile deliberately.

## Offline preparation

From the repository root:

```bash
python3 scripts/prepare_database_roles.py --database ai_soc
```

The command prints SQL and never opens a database connection. It has no apply
mode, login creation, password argument, secret lookup, or configuration mutation.
Invalid arguments are reported without echoing their values. Database selection
is restricted to ai_soc or ai_soc_test; identifiers are conservatively validated
and quoted. Optional owner/runtime/migrator role and schema names are supported.

The generated transaction checks current_database() and requires migration
d93c6e4fb132 before any role creation. It uses 5-second lock and 30-second statement
timeouts. All referenced tables and the audit guard function must exist. It then
creates capability roles, transfers ownership, and applies the exact privilege
profile. Production remains at 013505dd4ffd at the last review, so this SQL is
not yet eligible for live application. See the rollout plan for ordering.

## Test coverage and limits

Integration tests guard both the engine URL and current_database() as ai_soc_test.
They create unique NOLOGIN roles and an isolated schema inside one transaction,
seed authorized test data as owner, then SET LOCAL ROLE to runtime. Application
sessions use savepoints so their commits cannot escape the outer transaction.
All role creation, memberships, database ACL changes, schema/table changes, and
test data are rolled back; no DROP/DELETE/TRUNCATE cleanup is used.

Tests exercise evidence ingestion/integrity, audit chaining, lineage, legacy Wazuh
ingestion, checkpoint/lease synchronization, and HTTP tenant isolation under the
restricted effective role. Catalog checks verify ownership, role flags,
memberships, forbidden privileges, removal of an accidental PUBLIC column grant,
and the narrow locking grants. Destructive operations are not attempted.

SET LOCAL ROLE from an administrator session proves effective SQL permissions,
not authentication as a separate production login: session_user remains the
administrator and can RESET ROLE. A real non-superuser login verification is a
separate required cutover gate. This shared runtime role also does not provide
database row-level tenant isolation; existing authenticated application filters
remain the tenant boundary. A compromised owner/migration identity can still
change audit protections; external audit anchoring remains future work.

## References

- https://www.postgresql.org/docs/16/sql-select.html
- https://www.postgresql.org/docs/16/sql-grant.html
- https://www.postgresql.org/docs/16/sql-set-role.html
