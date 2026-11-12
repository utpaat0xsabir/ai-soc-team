from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory

from app.db import engine
from app.database.models import WazuhSyncLease, WazuhSyncCheckpoint


@pytest.mark.parametrize('state', ['idle', 'syncing'])
def test_lease_upgrade_preserves_existing_checkpoint_progress(state):
    assert engine.url.database == 'ai_soc_test'
    scripts = ScriptDirectory.from_config(Config('alembic.ini'))
    revision = scripts.get_revision('c82b5d3ea021')
    assert revision.down_revision == 'b71a4c2d9e10'
    with engine.connect() as connection:
        assert connection.scalar(sa.text('SELECT current_database()')) == 'ai_soc_test'
        connection.rollback()
        transaction = connection.begin()
        try:
            schema = f'lease_migration_{uuid4().hex}'
            connection.execute(sa.schema.CreateSchema(schema))
            connection.execute(sa.text(f'SET LOCAL search_path TO "{schema}"'))
            connection.execute(sa.text('CREATE TABLE tenants (id uuid PRIMARY KEY)'))
            connection.execute(sa.text('CREATE TABLE wazuh_integrations ('
                                       'id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id))'))
            tenant, integration = uuid4(), uuid4()
            connection.execute(sa.text('INSERT INTO tenants VALUES (:id)'), {'id': tenant})
            connection.execute(sa.text('INSERT INTO wazuh_integrations VALUES (:id,:tenant)'),
                               {'id': integration, 'tenant': tenant})
            with Operations.context(MigrationContext.configure(connection)):
                scripts.get_revision('b71a4c2d9e10').module.upgrade()
            connection.execute(sa.text("INSERT INTO wazuh_sync_checkpoints "
                                       "(integration_id,tenant_id,status,completed_window_end_ms,query_fingerprint,generation,imported_count) "
                                       "VALUES (:id,:tenant,'idle',2000,:fingerprint,7,4)"),
                               {'id': integration, 'tenant': tenant, 'fingerprint': 'a' * 64})
            if state == 'syncing':
                connection.execute(sa.text("UPDATE wazuh_sync_checkpoints SET status='syncing', "
                                           "window_start_ms=1900,window_end_ms=3000,snapshot_id=:snapshot, "
                                           "index_manifest='{\"wazuh-alerts-test\":\"index-uuid\"}', "
                                           "cursor_sort='[2500,\"wazuh-alerts-test\",\"alert-a\"]'"),
                                   {'snapshot': uuid4()})
            before = dict(connection.execute(sa.text('SELECT * FROM wazuh_sync_checkpoints')).mappings().one())
            with Operations.context(MigrationContext.configure(connection)):
                revision.module.upgrade()
            row = connection.execute(sa.text('SELECT generation,imported_count,completed_window_end_ms,'
                                             'scope_fingerprint,source_manifest FROM wazuh_sync_checkpoints')).one()
            assert tuple(row) == (7, 4, 2000, None, None)
            after = connection.execute(sa.text('SELECT * FROM wazuh_sync_checkpoints')).mappings().one()
            assert all(after[key] == value for key, value in before.items())
            assert connection.scalar(sa.text('SELECT count(*) FROM wazuh_sync_leases')) == 0
            inspector = sa.inspect(connection)
            for model in (WazuhSyncLease, WazuhSyncCheckpoint):
                if model is WazuhSyncLease:
                    # Freeze this historical revision's contract; attempt
                    # columns/constraints belong to the next migration test.
                    expected_columns = {'integration_id', 'tenant_id', 'owner_token', 'fence', 'expires_at'}
                    expected_checks = {'ck_wazuh_lease_fence', 'ck_wazuh_lease_owner'}
                else:
                    expected_columns = set(model.__table__.columns.keys())
                    expected_checks = {c.name for c in model.__table__.constraints if isinstance(c, sa.CheckConstraint)}
                assert {c['name'] for c in inspector.get_columns(model.__tablename__, schema=schema)} == expected_columns
                assert {c['name'] for c in inspector.get_check_constraints(model.__tablename__, schema=schema)} == expected_checks
        finally:
            transaction.rollback()
