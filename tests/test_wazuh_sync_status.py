from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError

from app.models import WazuhIntegration, WazuhSyncCheckpoint, WazuhSyncLease
from app.wazuh_leases import claim_lease, release_lease
from app.wazuh_sync import sync_wazuh, WazuhSyncError
from app.wazuh_status import safe_sync_error
from test_wazuh_sync import context, owner, install, doc


FIELDS = {'integration_id', 'integration_active', 'checkpoint_status', 'completed_window_end_ms',
          'generation', 'imported_count', 'duplicate_count', 'has_committed_cursor',
          'last_success_at', 'last_attempt_at', 'last_finished_at', 'last_attempt_outcome',
          'safe_error_code', 'sync_lock_active'}


def status(api, identity, key):
    return api.get(f'/v1/integrations/wazuh/{identity}/sync/status', headers={'X-API-Key': key})


def test_uninitialized_status_is_safe_and_does_not_require_scope(context):
    api, db = context; identity, _, key = owner(db)
    from app.config import settings
    settings.wazuh_sync_scopes.clear()
    response = status(api, identity, key)
    assert response.status_code == 200, response.text
    data = response.json()
    assert set(data) == FIELDS
    assert data['checkpoint_status'] == 'uninitialized'
    assert data['last_attempt_at'] is data['last_success_at'] is data['safe_error_code'] is None
    assert data['last_attempt_outcome'] is None and not data['sync_lock_active']
    assert data['imported_count'] == data['duplicate_count'] == data['generation'] == 0
    assert db.get(WazuhSyncCheckpoint, identity) is db.get(WazuhSyncLease, identity) is None


def test_completed_sync_exposes_only_committed_status(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db); install(monkeypatch)
    sync_wazuh(db, principal, identity)
    response = status(api, identity, key); data = response.json()
    assert response.status_code == 200 and set(data) == FIELDS
    assert data['checkpoint_status'] == 'idle' and data['completed_window_end_ms'] == 2000
    assert data['last_attempt_outcome'] == 'succeeded'
    assert data['last_attempt_at'] and data['last_finished_at'] and data['last_success_at']
    assert data['imported_count'] == 1 and not data['has_committed_cursor']
    assert data['safe_error_code'] is None and not data['sync_lock_active']
    forbidden = ('private-token', 'index-uuid', 'source_manifest', 'query_fingerprint',
                 'owner_token', 'credential_reference', 'indexer.test', '/test/ca')
    assert not any(value in response.text for value in forbidden)


def test_failed_first_attempt_records_no_checkpoint_progress(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db); server = install(monkeypatch)
    server['fetch_error'] = True
    with pytest.raises(WazuhSyncError):
        sync_wazuh(db, principal, identity)
    data = status(api, identity, key).json()
    assert data['last_attempt_outcome'] == 'failed' and data['safe_error_code'] == 'indexer_unavailable'
    assert data['last_attempt_at'] and data['last_finished_at']
    assert data['checkpoint_status'] == 'uninitialized' and data['generation'] == 0
    assert data['last_success_at'] is None and db.get(WazuhSyncCheckpoint, identity) is None


def test_failure_preserves_success_time_and_committed_counters(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db); server = install(monkeypatch)
    sync_wazuh(db, principal, identity)
    before = status(api, identity, key).json(); db.rollback()
    server['fetch_error'] = True
    with pytest.raises(WazuhSyncError):
        sync_wazuh(db, principal, identity)
    after = status(api, identity, key).json()
    for field in ('generation', 'completed_window_end_ms', 'imported_count', 'duplicate_count', 'last_success_at'):
        assert after[field] == before[field]
    assert after['last_attempt_outcome'] == 'failed' and after['safe_error_code'] == 'indexer_unavailable'


def test_partial_window_reports_cursor_without_disclosing_it(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db)
    server = install(monkeypatch, [doc('a'), doc('b')]); server['fail_on_search'] = 2
    with pytest.raises(WazuhSyncError):
        sync_wazuh(db, principal, identity, page_size=1)
    data = status(api, identity, key).json()
    assert data['checkpoint_status'] == 'syncing' and data['has_committed_cursor']
    assert data['generation'] == data['imported_count'] == 1
    assert data['completed_window_end_ms'] is data['last_success_at'] is None
    assert data['last_attempt_outcome'] == 'failed' and set(data) == FIELDS


def test_busy_attempt_does_not_overwrite_owner_state(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db); install(monkeypatch)
    handle = claim_lease(db, principal.tenant_id, identity)
    before = status(api, identity, key).json(); db.rollback()
    with pytest.raises(WazuhSyncError, match='wazuh_sync_busy'):
        sync_wazuh(db, principal, identity)
    after = status(api, identity, key).json()
    assert before == after and after['last_attempt_outcome'] == 'running' and after['sync_lock_active']
    db.rollback(); release_lease(db, handle)


def test_expired_running_attempt_is_reported_as_interrupted_without_writes(context):
    api, db = context; identity, principal, key = owner(db)
    handle = claim_lease(db, principal.tenant_id, identity)
    db.get(WazuhSyncLease, identity).expires_at = db.scalar(select(func.clock_timestamp())) - timedelta(seconds=1)
    db.commit()
    data = status(api, identity, key).json()
    assert data['last_attempt_outcome'] == 'interrupted' and data['safe_error_code'] == 'lease_lost'
    assert not data['sync_lock_active'] and data['last_finished_at'] is None
    db.rollback()
    assert db.get(WazuhSyncLease, identity).last_outcome == 'running'
    db.rollback(); release_lease(db, handle)


def test_stale_finalization_cannot_overwrite_successor(context):
    api, db = context; identity, principal, key = owner(db)
    old = claim_lease(db, principal.tenant_id, identity)
    db.get(WazuhSyncLease, identity).expires_at = db.scalar(select(func.clock_timestamp())) - timedelta(seconds=1)
    db.commit()
    current = claim_lease(db, principal.tenant_id, identity)
    assert not release_lease(db, old, outcome='failed', error_code='processing_failed')
    assert status(api, identity, key).json()['last_attempt_outcome'] == 'running'
    db.rollback(); release_lease(db, current, outcome='succeeded')


@pytest.mark.parametrize('case,status_code', [('foreign', 404), ('missing', 404),
                                            ('bad_uuid', 422), ('no_key', 401)])
def test_status_access_boundaries(context, case, status_code):
    api, db = context; identity, _, key = owner(db)
    if case == 'foreign': identity, _, _ = owner(db)
    elif case == 'missing': identity = uuid4()
    elif case == 'bad_uuid': identity = 'invalid'
    response = api.get(f'/v1/integrations/wazuh/{identity}/sync/status',
                       headers={} if case == 'no_key' else {'X-API-Key': key})
    assert response.status_code == status_code
    if status_code == 404:
        assert response.json() == {'detail': 'wazuh_integration_not_found'}


def test_inactive_integration_status_remains_visible_to_owner(context):
    api, db = context; identity, _, key = owner(db)
    db.get(WazuhIntegration, identity).is_active = False; db.commit()
    response = status(api, identity, key)
    assert response.status_code == 200 and response.json()['integration_active'] is False


def test_status_get_never_writes_or_calls_indexer(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db); install(monkeypatch)
    sync_wazuh(db, principal, identity)
    def no_indexer(*args, **kwargs):
        raise AssertionError('GET must not open Indexer')
    monkeypatch.setattr('app.wazuh_sync.open_wazuh_client', no_indexer)
    statements = []
    connection = db.get_bind()
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.strip().upper())
    event.listen(connection, 'before_cursor_execute', capture)
    try:
        assert status(api, identity, key).status_code == 200
    finally:
        event.remove(connection, 'before_cursor_execute', capture)
    reads = [sql for sql in statements if not sql.startswith(
        ('SAVEPOINT ', 'RELEASE SAVEPOINT ', 'ROLLBACK TO SAVEPOINT '))]
    assert reads and all(sql.startswith('SELECT') for sql in reads)
    assert all('FOR UPDATE' not in sql and 'FOR NO KEY UPDATE' not in sql for sql in reads)


def test_not_due_outcome_is_not_a_successful_sync(context, monkeypatch):
    from datetime import datetime, timezone
    api, db = context; identity, principal, key = owner(db); install(monkeypatch)
    monkeypatch.setattr('app.wazuh_sync.utcnow', lambda: datetime.fromtimestamp(0.5, timezone.utc))
    sync_wazuh(db, principal, identity)
    data = status(api, identity, key).json()
    assert data['last_attempt_outcome'] == 'not_due' and data['last_success_at'] is None


@pytest.mark.parametrize('message,expected', [('wazuh_sync_retention_gap', 'retention_gap'),
                                            ('wazuh_sync_identity_conflict', 'identity_conflict'),
                                            ('password=must-not-leak', 'processing_failed')])
def test_error_classification_never_echoes_unrecognized_text(message, expected):
    assert safe_sync_error(message) == expected


@pytest.mark.parametrize('changes', [
    {'safe_error_code': 'password=must-not-leak'},
    {'last_outcome': 'invented'},
    {'last_finished_at': None},
    {'last_attempt_at': None},
])
def test_database_rejects_invalid_attempt_metadata(context, changes):
    _, db = context; identity, principal, _ = owner(db)
    now = db.scalar(select(func.clock_timestamp()))
    values = dict(integration_id=identity, tenant_id=principal.tenant_id, fence=1,
                  last_attempt_at=now, last_finished_at=now,
                  last_outcome='failed', safe_error_code='processing_failed')
    values.update(changes)
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.execute(WazuhSyncLease.__table__.insert().values(**values))


def test_legacy_progress_has_unknown_attempt_outcome(context):
    from datetime import datetime, timezone
    api, db = context; identity, principal, key = owner(db)
    old_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db.add(WazuhSyncCheckpoint(integration_id=identity, tenant_id=principal.tenant_id,
                              status='idle', completed_window_end_ms=2000,
                              query_fingerprint='a' * 64, last_attempt_at=old_time,
                              last_success_at=old_time, imported_count=4))
    db.commit()
    data = status(api, identity, key).json()
    assert data['imported_count'] == 4 and data['last_attempt_at'] is not None
    assert data['last_attempt_outcome'] is data['last_finished_at'] is data['safe_error_code'] is None


def test_metadata_write_failure_does_not_mask_processing_error(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); server = install(monkeypatch)
    server['fetch_error'] = True
    def fail_finalization(*args, **kwargs):
        raise RuntimeError('status-write-secret')
    monkeypatch.setattr('app.wazuh_sync.release_lease', fail_finalization)
    with pytest.raises(WazuhSyncError, match='wazuh_sync_indexer_unavailable') as error:
        sync_wazuh(db, principal, identity)
    assert 'status-write-secret' not in str(error.value)
    assert db.get(WazuhSyncCheckpoint, identity) is None


def test_response_schema_rejects_extra_fields_and_unsafe_error_codes():
    from pydantic import ValidationError
    from app.schemas import WazuhSyncStatusResponse
    data = dict(integration_id=uuid4(), integration_active=True, checkpoint_status='uninitialized',
                completed_window_end_ms=None, generation=0, imported_count=0, duplicate_count=0,
                has_committed_cursor=False, last_success_at=None, last_attempt_at=None,
                last_finished_at=None, last_attempt_outcome=None, safe_error_code=None,
                sync_lock_active=False)
    with pytest.raises(ValidationError):
        WazuhSyncStatusResponse(**data, password='must-not-leak')
    data['safe_error_code'] = 'arbitrary-secret'
    with pytest.raises(ValidationError):
        WazuhSyncStatusResponse(**data)


def test_success_after_failure_clears_attempt_error(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db); server = install(monkeypatch)
    server['fetch_error'] = True
    with pytest.raises(WazuhSyncError):
        sync_wazuh(db, principal, identity)
    assert status(api, identity, key).json()['safe_error_code'] == 'indexer_unavailable'
    db.rollback(); server['fetch_error'] = False
    sync_wazuh(db, principal, identity)
    data = status(api, identity, key).json()
    assert data['last_attempt_outcome'] == 'succeeded' and data['safe_error_code'] is None
    assert data['last_success_at'] is not None


def test_scope_rejection_does_not_replace_last_leased_attempt(context, monkeypatch):
    from app.config import settings
    api, db = context; identity, principal, key = owner(db); install(monkeypatch)
    sync_wazuh(db, principal, identity)
    before = status(api, identity, key).json(); db.rollback()
    settings.wazuh_sync_scopes.clear()
    with pytest.raises(WazuhSyncError, match='wazuh_sync_scope_unavailable'):
        sync_wazuh(db, principal, identity)
    assert status(api, identity, key).json() == before
