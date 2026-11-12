"""Offline PostgreSQL 16 role-plan generator. Never connects or applies SQL."""

import argparse
from dataclasses import dataclass
import re

from app.database.models import Base


EXPECTED_REVISION = 'd93c6e4fb132'
APPLICATION_TABLES = (
    'tenants', 'tenant_api_keys', 'wazuh_integrations', 'evidence_records',
    'evidence_lineage', 'audit_logs', 'wazuh_sync_checkpoints', 'wazuh_sync_leases',
)


def _identifier(value):
    if not isinstance(value, str) or re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value) is None:
        raise ValueError('invalid_database_role_identifier')
    return '"' + value + '"'


@dataclass(frozen=True)
class RolePlan:
    database: str = 'ai_soc'
    schema: str = 'public'
    owner_role: str = 'ai_soc_owner'
    runtime_role: str = 'ai_soc_runtime'
    migrator_role: str = 'ai_soc_migrator'

    def __post_init__(self):
        if self.database not in ('ai_soc', 'ai_soc_test'):
            raise ValueError('invalid_role_plan_database')
        _identifier(self.schema)
        if self.schema.startswith('pg_') or self.schema == 'information_schema':
            raise ValueError('invalid_role_plan_schema')
        roles = (self.owner_role, self.runtime_role, self.migrator_role)
        for role in roles:
            _identifier(role)
            if role.startswith('pg_') or role in ('public', 'postgres'):
                raise ValueError('invalid_database_role_identifier')
        if len(set(roles)) != 3:
            raise ValueError('database_roles_must_be_distinct')


def bootstrap_sql(plan: RolePlan) -> tuple[str, ...]:
    """Fresh NOLOGIN capabilities; existing names fail instead of being reused."""
    statements = [
        f'CREATE ROLE {_identifier(role)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
        'NOREPLICATION NOBYPASSRLS NOINHERIT;'
        for role in (plan.owner_role, plan.runtime_role, plan.migrator_role)
    ]
    statements.append(
        f'GRANT {_identifier(plan.owner_role)} TO {_identifier(plan.migrator_role)} '
        'WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;')
    return tuple(statements)


def ownership_sql(plan: RolePlan) -> tuple[str, ...]:
    schema, owner = _identifier(plan.schema), _identifier(plan.owner_role)
    statements = [f'GRANT USAGE, CREATE ON SCHEMA {schema} TO {owner};']
    statements.extend(f'ALTER TABLE {schema}.{_identifier(table)} OWNER TO {owner};'
                      for table in (*APPLICATION_TABLES, 'alembic_version'))
    statements.append(f'ALTER FUNCTION {schema}."prevent_audit_log_mutation"() OWNER TO {owner};')
    return tuple(statements)


def runtime_grants_sql(plan: RolePlan) -> tuple[str, ...]:
    schema, runtime = _identifier(plan.schema), _identifier(plan.runtime_role)
    database, owner, migrator = (_identifier(plan.database), _identifier(plan.owner_role),
                                 _identifier(plan.migrator_role))
    statements = [
        f'REVOKE CREATE, TEMPORARY ON DATABASE {database} FROM PUBLIC;',
        f'GRANT CONNECT ON DATABASE {database} TO {runtime}, {owner}, {migrator};',
        f'GRANT CREATE ON DATABASE {database} TO {owner};',
        f'REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC;',
        f'GRANT USAGE ON SCHEMA {schema} TO {runtime};',
    ]
    # Table REVOKE does not clear separately granted column privileges. Clear
    # both, including PUBLIC inheritance, before granting the exact profile.
    for table in (*APPLICATION_TABLES, 'alembic_version'):
        qualified = f'{schema}.{_identifier(table)}'
        columns = (tuple(Base.metadata.tables[table].columns.keys())
                   if table != 'alembic_version' else ('version_num',))
        names = ', '.join(_identifier(column) for column in columns)
        statements.append(f'REVOKE ALL PRIVILEGES ON TABLE {qualified} FROM PUBLIC, {runtime};')
        column_privileges = ', '.join(f'{operation} ({names})'
                                      for operation in ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES'))
        statements.append(f'REVOKE {column_privileges} ON TABLE {qualified} FROM PUBLIC, {runtime};')
    for table in ('tenants', 'tenant_api_keys', 'wazuh_integrations'):
        statements.append(f'GRANT SELECT ON TABLE {schema}.{_identifier(table)} TO {runtime};')
    for table in ('evidence_records', 'evidence_lineage', 'audit_logs'):
        statements.append(f'GRANT SELECT, INSERT ON TABLE {schema}.{_identifier(table)} TO {runtime};')
    for table in ('wazuh_sync_checkpoints', 'wazuh_sync_leases'):
        statements.append(f'GRANT SELECT, INSERT, UPDATE ON TABLE {schema}.{_identifier(table)} TO {runtime};')
    for table in ('tenants', 'wazuh_integrations'):
        statements.append(f'GRANT UPDATE ("created_at") ON TABLE {schema}.{_identifier(table)} TO {runtime};')
    return tuple(statements)


def preflight_sql(plan: RolePlan) -> str:
    schema = _identifier(plan.schema)
    return f"""DO $role_plan_guard$
BEGIN
    IF current_database() <> '{plan.database}' THEN
        RAISE EXCEPTION 'role_plan_database_mismatch';
    END IF;
    IF (SELECT version_num FROM {schema}."alembic_version") IS DISTINCT FROM '{EXPECTED_REVISION}' THEN
        RAISE EXCEPTION 'role_plan_schema_revision_mismatch';
    END IF;
END;
$role_plan_guard$;"""


def render_sql(plan: RolePlan) -> str:
    statements = (
        'BEGIN;', "SET LOCAL lock_timeout = '5s';", "SET LOCAL statement_timeout = '30s';",
        preflight_sql(plan), *bootstrap_sql(plan), *ownership_sql(plan), *runtime_grants_sql(plan), 'COMMIT;',
    )
    return '\n'.join(statements) + '\n'


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'invalid_role_plan_arguments\n')


def main(argv=None):
    parser = _SafeParser(description='Print a role-hardening SQL plan; does not connect or execute')
    parser.add_argument('--database', default='ai_soc')
    parser.add_argument('--schema', default='public')
    parser.add_argument('--owner-role', default='ai_soc_owner')
    parser.add_argument('--runtime-role', default='ai_soc_runtime')
    parser.add_argument('--migrator-role', default='ai_soc_migrator')
    args = parser.parse_args(argv)
    try:
        sql = render_sql(RolePlan(**vars(args)))
    except ValueError:
        print('invalid_database_role_plan')
        return 2
    print(sql, end='')
    return 0
