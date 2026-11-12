from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import engine
from app.database.models import Tenant, WazuhIntegration, WazuhSyncCheckpoint


@pytest.fixture
def checkpoint_session():
    # Guard before any writes; never rely on the application's default DB name.
    if engine.url.database != 'ai_soc_test':
        pytest.fail('checkpoint_tests_require_ai_soc_test')
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT current_database()')) == 'ai_soc_test'
        connection.rollback()
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode='create_savepoint')
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()


def integration(session):
    tenant = Tenant(name='Checkpoint test', slug=f'checkpoint-{uuid4().hex}')
    session.add(tenant)
    session.flush()
    value = WazuhIntegration(
        tenant_id=tenant.id, name='Checkpoint integration',
        base_url='https://127.0.0.1:9200', username='test',
        credential_reference='env:WAZUH_INDEXER_PASSWORD',
        ca_certificate_path='/test/ca.pem',
    )
    session.add(value)
    session.flush()
    return value


def checkpoint(session, owner, **changes):
    values = dict(integration_id=owner.id, tenant_id=owner.tenant_id)
    values.update(changes)
    row = WazuhSyncCheckpoint(**values)
    session.add(row)
    session.flush()
    return row


def active_values():
    return dict(
        status='syncing', query_fingerprint='a' * 64,
        window_start_ms=1000, window_end_ms=2000, snapshot_id=uuid4(),
        index_manifest={'wazuh-alerts-test': str(uuid4())},
    )


def test_checkpoint_defaults_and_existing_integration_compatibility(checkpoint_session):
    owner = integration(checkpoint_session)
    assert checkpoint_session.get(WazuhSyncCheckpoint, owner.id) is None
    row = checkpoint(checkpoint_session, owner)
    assert row.status == 'uninitialized'
    assert row.generation == row.imported_count == row.duplicate_count == 0
    assert row.completed_window_end_ms is None
    assert row.cursor_sort is row.snapshot_id is row.last_success_at is None
    assert row.created_at is not None


def test_independent_checkpoints_and_tenant_scoped_lookup(checkpoint_session):
    a, b = integration(checkpoint_session), integration(checkpoint_session)
    checkpoint(checkpoint_session, a)
    checkpoint(checkpoint_session, b)
    rows = checkpoint_session.scalars(select(WazuhSyncCheckpoint).where(
        WazuhSyncCheckpoint.tenant_id == a.tenant_id,
    )).all()
    assert [row.integration_id for row in rows] == [a.id]
    assert checkpoint_session.scalar(select(WazuhSyncCheckpoint).where(
        WazuhSyncCheckpoint.integration_id == b.id,
        WazuhSyncCheckpoint.tenant_id == a.tenant_id,
    )) is None


def test_two_integrations_of_same_tenant_have_independent_checkpoints(checkpoint_session):
    a = integration(checkpoint_session)
    b = WazuhIntegration(
        tenant_id=a.tenant_id, name='Second integration',
        base_url='https://127.0.0.1:9200', username='test',
        credential_reference='env:WAZUH_INDEXER_PASSWORD',
        ca_certificate_path='/test/ca.pem',
    )
    checkpoint_session.add(b)
    checkpoint_session.flush()
    first = checkpoint(checkpoint_session, a, **active_values())
    second = checkpoint(checkpoint_session, b)
    assert first.integration_id != second.integration_id
    assert second.snapshot_id is None
    assert second.completed_window_end_ms is None


@pytest.mark.parametrize('case', ['duplicate', 'wrong_tenant', 'missing_integration'])
def test_ownership_constraints(checkpoint_session, case):
    a, b = integration(checkpoint_session), integration(checkpoint_session)
    checkpoint(checkpoint_session, a)
    values = dict(integration_id=a.id, tenant_id=a.tenant_id)
    if case == 'wrong_tenant':
        values = dict(integration_id=b.id, tenant_id=a.tenant_id)
    elif case == 'missing_integration':
        values['integration_id'] = uuid4()
    with pytest.raises(IntegrityError):
        with checkpoint_session.begin_nested():
            checkpoint_session.execute(WazuhSyncCheckpoint.__table__.insert().values(**values))


@pytest.mark.parametrize('changes', [
    {'generation': -1}, {'imported_count': -1}, {'duplicate_count': -1},
    {'status': 'invented'}, {'cursor_version': 2},
    {'completed_window_end_ms': -1}, {'completed_window_end_ms': 253402300800000},
    {'safe_error_code': 'password=secret'}, {'query_fingerprint': 'bad'},
    {'window_start_ms': 1000}, {'cursor_sort': [1500, 'index', 'id']},
    {'status': 'idle'}, {'status': 'syncing'},
    {'completed_window_end_ms': 1500},
])
def test_invalid_initial_state_rejected_by_database(checkpoint_session, changes):
    owner = integration(checkpoint_session)
    with pytest.raises(IntegrityError):
        with checkpoint_session.begin_nested():
            checkpoint(checkpoint_session, owner, **changes)


@pytest.mark.parametrize('changes', [
    {'window_end_ms': 1000}, {'window_start_ms': -1},
    {'window_end_ms': 253402300800000}, {'query_fingerprint': None},
    {'snapshot_id': None}, {'index_manifest': None},
    {'index_manifest': []}, {'index_manifest': {}},
    {'index_manifest': {'index': 'x' * 65536}},
    {'cursor_sort': [2000, 'index', 'id']},
    {'cursor_sort': [999, 'index', 'id']},
    {'cursor_sort': [1500, 'index']}, {'cursor_sort': {}},
    {'cursor_sort': [True, 'index', 'id']},
    {'cursor_sort': [1500.5, 'index', 'id']},
    {'cursor_sort': [1500, '', 'id']},
    {'cursor_sort': [1500, 'index', '']},
    {'cursor_sort': [1500, 'index', None]},
    {'cursor_sort': [1500, 'index', 'x' * 513]},
    {'status': 'idle'}, {'status': 'uninitialized'},
])
def test_invalid_active_state_rejected_by_database(checkpoint_session, changes):
    owner = integration(checkpoint_session)
    values = active_values()
    values.update(changes)
    with pytest.raises(IntegrityError):
        with checkpoint_session.begin_nested():
            checkpoint(checkpoint_session, owner, **values)


@pytest.mark.parametrize('status', ['syncing', 'error', 'gap'])
@pytest.mark.parametrize('position', [None, [1500, 'index', 'id']])
def test_active_window_with_optional_committed_cursor(checkpoint_session, status, position):
    values = active_values()
    values.update(status=status, cursor_sort=position)
    row = checkpoint(checkpoint_session, integration(checkpoint_session), **values)
    assert row.cursor_sort == position
    assert row.completed_window_end_ms is None


def test_completed_checkpoint_can_start_overlapping_window(checkpoint_session):
    values = active_values()
    values['completed_window_end_ms'] = 1800
    row = checkpoint(checkpoint_session, integration(checkpoint_session), **values)
    assert row.window_start_ms < row.completed_window_end_ms


def test_idle_completed_state(checkpoint_session):
    row = checkpoint(checkpoint_session, integration(checkpoint_session),
                     status='idle', completed_window_end_ms=2000,
                     query_fingerprint='b' * 64)
    assert row.window_start_ms is row.cursor_sort is None


def test_checkpoint_schema_has_no_connection_secrets():
    names = set(WazuhSyncCheckpoint.__table__.columns.keys())
    assert not names.intersection({'password', 'username', 'credential_reference',
                                   'base_url', 'pit_id', 'ca_certificate_path'})


@pytest.mark.parametrize('field', ['tenant_id', 'integration_id', 'status',
                                  'generation', 'cursor_version', 'imported_count',
                                  'duplicate_count'])
def test_required_fields_reject_explicit_null(checkpoint_session, field):
    owner = integration(checkpoint_session)
    values = dict(integration_id=owner.id, tenant_id=owner.tenant_id)
    values[field] = None
    with pytest.raises(IntegrityError):
        with checkpoint_session.begin_nested():
            # ORM None on a server-default column means "use the default".
            # Core INSERT sends an actual SQL NULL to test the DB boundary.
            checkpoint_session.execute(WazuhSyncCheckpoint.__table__.insert().values(**values))


def test_integration_composite_ownership_key_exists():
    keys = [tuple(column.name for column in constraint.columns)
            for constraint in WazuhIntegration.__table__.constraints]
    assert ('tenant_id', 'id') in keys
