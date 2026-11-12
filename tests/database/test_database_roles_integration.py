from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.database.roles import RolePlan, bootstrap_sql, ownership_sql, runtime_grants_sql, preflight_sql
from app.db import engine, get_db
from app.main import app
from app.database.models import Base, AuditLog, EvidenceRecord, WazuhSyncCheckpoint
from app.audit.integrity import verify_audit_chain
from app.integrations.wazuh.sync import sync_wazuh
from tests.integrations.wazuh.test_wazuh_sync import owner, install


@pytest.fixture
def restricted_context(monkeypatch):
    from app.core.config import settings
    assert engine.url.database == 'ai_soc_test'
    monkeypatch.setattr(settings, 'wazuh_sync_scopes', {})
    suffix = uuid4().hex
    plan = RolePlan(database='ai_soc_test', schema=f'role_test_{suffix}',
                    owner_role=f'test_owner_{suffix}', runtime_role=f'test_runtime_{suffix}',
                    migrator_role=f'test_migrator_{suffix}')
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT current_database()')) == 'ai_soc_test'
        connection.rollback(); outer = connection.begin()
        overrides = app.dependency_overrides.copy()
        session = None
        try:
            for statement in bootstrap_sql(plan): connection.exec_driver_sql(statement)
            connection.exec_driver_sql(f'CREATE SCHEMA "{plan.schema}" AUTHORIZATION "{plan.owner_role}"')
            connection.exec_driver_sql(f'SET LOCAL search_path TO "{plan.schema}", pg_catalog')
            connection.exec_driver_sql(f'SET LOCAL ROLE "{plan.owner_role}"')
            Base.metadata.create_all(connection)
            connection.exec_driver_sql('CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY)')
            connection.exec_driver_sql("INSERT INTO alembic_version VALUES ('d93c6e4fb132')")
            connection.exec_driver_sql("CREATE FUNCTION prevent_audit_log_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; $$")
            connection.exec_driver_sql('CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_logs FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_log_mutation()')
            seed = Session(bind=connection, join_transaction_mode='create_savepoint')
            first = owner(seed); second = owner(seed)
            seed.close()
            connection.exec_driver_sql('RESET ROLE')
            # Seed accidental PUBLIC privileges; applying the profile must clear
            # both table-level and separately granted column-level capabilities.
            connection.exec_driver_sql(f'GRANT CREATE ON SCHEMA "{plan.schema}" TO PUBLIC')
            connection.exec_driver_sql(f'GRANT UPDATE (action) ON "{plan.schema}".audit_logs TO PUBLIC')
            for statement in ownership_sql(plan) + runtime_grants_sql(plan):
                connection.exec_driver_sql(statement)
            connection.exec_driver_sql(f'SET LOCAL ROLE "{plan.runtime_role}"')
            session = Session(bind=connection, join_transaction_mode='create_savepoint')
            app.dependency_overrides[get_db] = lambda: session
            with TestClient(app, raise_server_exceptions=False) as api:
                yield api, session, plan, first, second
        finally:
            app.dependency_overrides.clear(); app.dependency_overrides.update(overrides)
            if session is not None: session.close()
            outer.rollback()  # Includes CREATE ROLE: no persistent role or DROP cleanup.
            assert connection.scalar(text('SELECT to_regnamespace(:schema) IS NULL'),
                                     {'schema': plan.schema})
            assert connection.scalar(text('SELECT count(*) FROM pg_roles WHERE rolname IN (:owner,:runtime,:migrator)'),
                                     {'owner': plan.owner_role, 'runtime': plan.runtime_role,
                                      'migrator': plan.migrator_role}) == 0


def test_runtime_role_flags_ownership_and_membership(restricted_context):
    _, db, plan, _, _ = restricted_context
    assert db.scalar(text('SELECT current_user')) == plan.runtime_role
    flags = db.execute(text('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname=current_user')).one()
    assert not any(flags)
    assert db.scalar(text('SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)')) == 0
    assert db.scalar(text('SELECT count(*) FROM pg_class WHERE relnamespace=to_regnamespace(:schema) AND relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)'), {'schema': plan.schema}) == 0


def test_runtime_has_only_intended_dml_and_lock_column_permissions(restricted_context):
    _, db, plan, _, _ = restricted_context
    def privilege(table, operation):
        return db.scalar(text('SELECT has_table_privilege(current_user,:table,:operation)'),
                         {'table': f'{plan.schema}.{table}', 'operation': operation})
    for table in Base.metadata.tables:
        assert privilege(table, 'SELECT')
        assert not privilege(table, 'SELECT WITH GRANT OPTION')
        for denied in ('DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES'):
            assert not privilege(table, denied)
    for table in ('evidence_records', 'evidence_lineage', 'audit_logs'):
        assert privilege(table, 'INSERT') and not privilege(table, 'UPDATE')
        assert not db.scalar(text("SELECT has_any_column_privilege(current_user,:table,'UPDATE')"),
                             {'table': f'{plan.schema}.{table}'})
    assert not privilege('tenant_api_keys', 'INSERT') and not privilege('tenant_api_keys', 'UPDATE')
    assert not privilege('alembic_version', 'SELECT') and not privilege('alembic_version', 'UPDATE')
    for table in ('tenants', 'wazuh_integrations'):
        for column, expected in [('created_at', True), ('id', False), ('name', False)]:
            assert db.scalar(text('SELECT has_column_privilege(current_user,:table,:column,\'UPDATE\')'),
                             {'table': f'{plan.schema}.{table}', 'column': column}) is expected
    assert not db.scalar(text("SELECT has_schema_privilege(current_user,:schema,'CREATE')"), {'schema': plan.schema})
    assert not db.scalar(text("SELECT has_database_privilege(current_user,'ai_soc_test','CREATE')"))
    assert not db.scalar(text("SELECT has_database_privilege(current_user,'ai_soc_test','TEMPORARY')"))


def test_evidence_api_and_audit_work_under_restricted_role(restricted_context):
    api, db, plan, first, _ = restricted_context
    _, principal, key = first
    response = api.post('/v1/evidence', headers={'X-API-Key': key}, json={
        'evidence_type': 'observation', 'source_type': 'test', 'source_reference': 'role-test',
        'payload': {'observed': True}})
    assert response.status_code in (200, 201), response.text
    evidence_id = response.json()['id']
    assert api.get(f'/v1/evidence/{evidence_id}/verify', headers={'X-API-Key': key}).json()['integrity_valid']
    events = db.scalars(select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
                        .order_by(AuditLog.sequence_number)).all()
    assert events and verify_audit_chain(events)['valid']
    assert db.scalar(text('SELECT current_user')) == plan.runtime_role


def test_lineage_insert_and_reads_work_under_restricted_role(restricted_context):
    api, db, _, first, _ = restricted_context
    _, _, key = first
    headers = {'X-API-Key': key}
    ids = []
    for reference in ('parent', 'child'):
        response = api.post('/v1/evidence', headers=headers, json={
            'evidence_type': 'observation', 'source_type': 'test',
            'source_reference': reference, 'payload': {}})
        assert response.status_code == 201, response.text
        ids.append(response.json()['id'])
    response = api.post(f'/v1/evidence/{ids[0]}/lineage', headers=headers,
                        json={'child_evidence_id': ids[1], 'relationship_type': 'supports'})
    assert response.status_code == 201, response.text
    assert api.get(f'/v1/evidence/{ids[0]}/lineage', headers=headers).json()['total'] == 1


def test_legacy_ingestion_remains_usable_for_application_rollback(restricted_context, monkeypatch):
    from tests.api.test_wazuh_ingestion_api import install_fake_wazuh_client, make_alert
    api, db, _, first, _ = restricted_context
    identity, _, key = first
    install_fake_wazuh_client(monkeypatch, [make_alert()])
    response = api.post(f'/v1/integrations/wazuh/{identity}/ingest', headers={'X-API-Key': key})
    assert response.status_code == 200 and response.json()['imported'] == 1


def test_sync_checkpoint_and_lease_writes_work_without_history_update_grants(restricted_context, monkeypatch):
    _, db, plan, first, _ = restricted_context
    identity, principal, _ = first
    from app.core.config import settings
    # Keep this scope isolated from the independently seeded second tenant.
    settings.wazuh_sync_scopes = {str(identity): settings.wazuh_sync_scopes[str(identity)]}
    install(monkeypatch)
    assert sync_wazuh(db, principal, identity)['imported'] == 1
    assert db.get(WazuhSyncCheckpoint, identity).completed_window_end_ms == 2000
    assert db.scalar(text('SELECT current_user')) == plan.runtime_role


def test_api_tenant_isolation_remains_enforced_with_shared_runtime_role(restricted_context):
    api, db, _, first, second = restricted_context
    identity, _, first_key = first
    other_id, _, other_key = second
    assert api.get(f'/v1/integrations/wazuh/{identity}', headers={'X-API-Key': other_key}).status_code == 404
    assert api.get(f'/v1/integrations/wazuh/{other_id}/sync/status', headers={'X-API-Key': first_key}).status_code == 404


def test_migration_capability_can_set_owner_without_granting_runtime_membership(restricted_context):
    _, db, plan, _, _ = restricted_context
    db.rollback()
    connection = db.get_bind()
    # SET ROLE checks session_user (the test administrator), so this is effective
    # privilege testing, not proof of authentication as a production login.
    connection.exec_driver_sql(f'SET LOCAL ROLE "{plan.owner_role}"')
    connection.exec_driver_sql(f'CREATE TABLE "{plan.schema}".migration_permission_probe (id integer)')
    assert connection.scalar(text('SELECT current_user')) == plan.owner_role
    membership = connection.execute(text('SELECT inherit_option,set_option,admin_option FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname=:owner) AND member=(SELECT oid FROM pg_roles WHERE rolname=:migrator)'),
                                    {'owner': plan.owner_role, 'migrator': plan.migrator_role}).one()
    assert tuple(membership) == (False, True, False)
    connection.exec_driver_sql(f'SET LOCAL ROLE "{plan.runtime_role}"')


def test_role_plan_guard_rejects_wrong_database_before_any_change(restricted_context):
    _, db, plan, _, _ = restricted_context
    from dataclasses import replace
    with pytest.raises(DBAPIError, match='role_plan_database_mismatch'):
        with db.begin_nested():
            db.execute(text(preflight_sql(replace(plan, database='ai_soc'))))
    assert db.scalar(text('SELECT current_user')) == plan.runtime_role


def test_role_plan_guard_checks_current_migration_revision(restricted_context):
    _, db, plan, _, _ = restricted_context
    db.rollback(); connection = db.get_bind()
    connection.exec_driver_sql(f'SET LOCAL ROLE "{plan.owner_role}"')
    connection.exec_driver_sql(preflight_sql(plan))
    connection.exec_driver_sql("UPDATE alembic_version SET version_num='older-revision'")
    nested = connection.begin_nested()
    try:
        with pytest.raises(DBAPIError, match='role_plan_schema_revision_mismatch'):
            connection.exec_driver_sql(preflight_sql(plan))
    finally:
        nested.rollback()
    connection.exec_driver_sql(f'SET LOCAL ROLE "{plan.runtime_role}"')
