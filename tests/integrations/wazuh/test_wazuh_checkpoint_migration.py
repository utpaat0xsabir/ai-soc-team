from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from alembic.config import Config

from app.db import engine
from app.database.models import WazuhSyncCheckpoint


def test_checkpoint_migration_preserves_populated_integrations():
    if engine.url.database != 'ai_soc_test':
        pytest.fail('checkpoint_migration_requires_ai_soc_test')
    scripts = ScriptDirectory.from_config(Config('alembic.ini'))
    # Pin the historical upgrade; later migrations are tested separately.
    revision = scripts.get_revision('b71a4c2d9e10')
    assert revision.down_revision == '013505dd4ffd'
    schema = f'checkpoint_migration_{uuid4().hex}'
    with engine.connect() as connection:
        assert connection.scalar(sa.text('SELECT current_database()')) == 'ai_soc_test'
        connection.rollback()
        transaction = connection.begin()
        try:
            connection.execute(sa.schema.CreateSchema(schema))
            connection.execute(sa.text(f'SET LOCAL search_path TO "{schema}"'))
            # Representative pre-migration ownership schema, isolated from public.
            connection.execute(sa.text('CREATE TABLE tenants (id uuid PRIMARY KEY)'))
            connection.execute(sa.text('CREATE TABLE wazuh_integrations ('
                                       'id uuid PRIMARY KEY, tenant_id uuid NOT NULL '
                                       'REFERENCES tenants(id), name varchar(150) NOT NULL)'))
            tenant, integration = uuid4(), uuid4()
            connection.execute(sa.text('INSERT INTO tenants VALUES (:id)'), {'id': tenant})
            connection.execute(sa.text('INSERT INTO wazuh_integrations VALUES (:id,:tenant,:name)'),
                               {'id': integration, 'tenant': tenant, 'name': 'Existing integration'})
            context = MigrationContext.configure(connection)
            with Operations.context(context):
                revision.module.upgrade()
            assert connection.scalar(sa.text('SELECT count(*) FROM wazuh_integrations')) == 1
            assert connection.scalar(sa.text('SELECT count(*) FROM wazuh_sync_checkpoints')) == 0
            connection.execute(WazuhSyncCheckpoint.__table__.insert().values(
                integration_id=integration, tenant_id=tenant))
            assert connection.scalar(sa.text('SELECT status FROM wazuh_sync_checkpoints')) == 'uninitialized'
            inspector = sa.inspect(connection)
            columns = {c['name'] for c in inspector.get_columns('wazuh_sync_checkpoints', schema=schema)}
            assert columns == {
                'integration_id', 'tenant_id', 'status', 'generation', 'cursor_version',
                'completed_window_end_ms', 'window_start_ms', 'window_end_ms',
                'query_fingerprint', 'snapshot_id', 'index_manifest', 'cursor_sort',
                'last_attempt_at', 'last_success_at', 'safe_error_code', 'imported_count',
                'duplicate_count', 'created_at',
            }
            fks = inspector.get_foreign_keys('wazuh_sync_checkpoints', schema=schema)
            assert any(fk['constrained_columns'] == ['tenant_id', 'integration_id']
                       and fk['referred_columns'] == ['tenant_id', 'id']
                       and fk['options'].get('ondelete') == 'RESTRICT' for fk in fks)
            checks = {check['name'] for check in inspector.get_check_constraints(
                'wazuh_sync_checkpoints', schema=schema)}
            assert checks == {
                'ck_wazuh_checkpoint_status', 'ck_wazuh_checkpoint_counters',
                'ck_wazuh_checkpoint_cursor_version', 'ck_wazuh_checkpoint_completed_bounds',
                'ck_wazuh_checkpoint_fingerprint', 'ck_wazuh_checkpoint_safe_error',
                'ck_wazuh_checkpoint_active_fields', 'ck_wazuh_checkpoint_window',
                'ck_wazuh_checkpoint_completed_scope', 'ck_wazuh_checkpoint_manifest',
                'ck_wazuh_checkpoint_state', 'ck_wazuh_checkpoint_cursor_sort',
            }
            assert inspector.get_pk_constraint('wazuh_sync_checkpoints', schema=schema)[
                'constrained_columns'] == ['integration_id']
        finally:
            # Transactional DDL rollback: no DROP/DELETE/TRUNCATE cleanup.
            transaction.rollback()
