from uuid import uuid4

import sqlalchemy as sa
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory

from app.db import engine
from app.database.models import WazuhSyncLease


def test_attempt_migration_preserves_owner_and_leaves_historical_outcome_unknown():
    assert engine.url.database == 'ai_soc_test'
    scripts = ScriptDirectory.from_config(Config('alembic.ini'))
    revision = scripts.get_revision('d93c6e4fb132')
    assert revision.down_revision == 'c82b5d3ea021'
    with engine.connect() as connection:
        assert connection.scalar(sa.text('SELECT current_database()')) == 'ai_soc_test'
        connection.rollback(); transaction = connection.begin()
        try:
            schema = f'status_migration_{uuid4().hex}'
            connection.execute(sa.schema.CreateSchema(schema))
            connection.execute(sa.text(f'SET LOCAL search_path TO "{schema}"'))
            connection.execute(sa.text('CREATE TABLE tenants (id uuid PRIMARY KEY)'))
            connection.execute(sa.text('CREATE TABLE wazuh_integrations (id uuid PRIMARY KEY,'
                                       'tenant_id uuid NOT NULL REFERENCES tenants(id))'))
            tenant, integration, token = uuid4(), uuid4(), uuid4()
            connection.execute(sa.text('INSERT INTO tenants VALUES (:id)'), {'id': tenant})
            connection.execute(sa.text('INSERT INTO wazuh_integrations VALUES (:id,:tenant)'),
                               {'id': integration, 'tenant': tenant})
            with Operations.context(MigrationContext.configure(connection)):
                scripts.get_revision('b71a4c2d9e10').module.upgrade()
                scripts.get_revision('c82b5d3ea021').module.upgrade()
            connection.execute(sa.text('INSERT INTO wazuh_sync_leases '
                                       '(integration_id,tenant_id,owner_token,fence,expires_at) '
                                       "VALUES (:id,:tenant,:token,9,clock_timestamp() + interval '1 minute')"),
                               {'id': integration, 'tenant': tenant, 'token': token})
            before = dict(connection.execute(sa.text('SELECT * FROM wazuh_sync_leases')).mappings().one())
            with Operations.context(MigrationContext.configure(connection)):
                revision.module.upgrade()
            after = connection.execute(sa.text('SELECT * FROM wazuh_sync_leases')).mappings().one()
            assert all(after[key] == value for key, value in before.items())
            assert all(after[key] is None for key in ('last_attempt_at', 'last_finished_at', 'last_outcome', 'safe_error_code'))
            inspector = sa.inspect(connection)
            assert {c['name'] for c in inspector.get_columns('wazuh_sync_leases', schema=schema)} == set(WazuhSyncLease.__table__.columns.keys())
            assert {c['name'] for c in inspector.get_check_constraints('wazuh_sync_leases', schema=schema)} == {
                c.name for c in WazuhSyncLease.__table__.constraints if isinstance(c, sa.CheckConstraint)}
        finally:
            transaction.rollback()
