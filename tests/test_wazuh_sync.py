import copy
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

import certifi
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.audit import verify_audit_chain
from app.config import settings
from app.db import engine, get_db
from app.main import app
from app.models import AuditLog, EvidenceRecord, Tenant, TenantAPIKey, WazuhIntegration, WazuhSyncCheckpoint
from app.wazuh import WazuhIndexerClient
from app.wazuh_sync import sync_wazuh


INDEX = 'wazuh-alerts-test'
SHARDS = dict(total=1, successful=1, skipped=0, failed=0)
NOW = datetime(1970, 1, 1, 0, 0, 3, tzinfo=timezone.utc)


@pytest.fixture
def context(monkeypatch):
    assert engine.url.database == 'ai_soc_test', 'sync_tests_require_ai_soc_test'
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT current_database()')) == 'ai_soc_test'
        connection.rollback()
        outer = connection.begin()
        session = Session(bind=connection, join_transaction_mode='create_savepoint')
        original = app.dependency_overrides.copy()
        app.dependency_overrides[get_db] = lambda: session
        monkeypatch.setattr(settings, 'wazuh_sync_scopes', {})
        try:
            with TestClient(app, raise_server_exceptions=False) as api:
                yield api, session
        finally:
            app.dependency_overrides.clear(); app.dependency_overrides.update(original)
            session.close(); outer.rollback()


def owner(session):
    tenant = Tenant(name='Sync tenant', slug=f'sync-{uuid4().hex}')
    session.add(tenant); session.flush()
    key = generate_api_key()
    record = TenantAPIKey(tenant_id=tenant.id, name='Sync test', key_hash=hash_api_key(key))
    session.add(record)
    integration = WazuhIntegration(
        tenant_id=tenant.id, name='Sync integration', base_url='https://indexer.test',
        username='test', credential_reference='env:WAZUH_INDEXER_PASSWORD', ca_certificate_path='/test/ca')
    session.add(integration); session.commit()
    from app.auth import AuthenticatedPrincipal
    principal = AuthenticatedPrincipal(tenant.id, record.id)
    identity = integration.id
    settings.wazuh_sync_scopes[str(identity)] = dict(
        tenant_id=str(tenant.id), bootstrap_start_ms=1000, window_ms=1000,
        overlap_ms=600, safety_delay_ms=0, source_field='organization.id', source_value='org-a')
    return identity, principal, key


def doc(identifier='a', source_value='org-a'):
    return {'_index': INDEX, '_id': identifier, '_source': {
        'id': identifier, 'timestamp': '1970-01-01T00:00:01.500Z',
        'organization': {'id': source_value}}, 'sort': [1500, INDEX, identifier]}


def install(monkeypatch, documents=None):
    state = dict(documents=[doc()] if documents is None else documents,
                 metadata_error=False, audit_error=False, fetch_error=False, requests=[], uuid='index-uuid',
                 searches=0, fail_on_search=None, before_search=None, before_request=None)

    def handler(request):
        if state['before_request']:
            state['before_request']()
        state['requests'].append(request)
        if request.url.path.endswith('/_settings/index.uuid'):
            indices = {INDEX: {'settings': {'index': {'uuid': state['uuid']}}}}
            if state.get('extra_index'):
                indices[state['extra_index']] = {'settings': {'index': {'uuid': 'new-index-uuid'}}}
            return httpx.Response(403 if state['metadata_error'] else 200,
                                  json=indices)
        if '/_mapping/' in request.url.path:
            mapping = {'mappings': {
                field: {'mapping': {field: {'type': kind}}}
                for field, kind in [('timestamp', 'date'), ('id', 'keyword'), ('organization.id', 'keyword')]}}
            indices = {INDEX: mapping}
            if state.get('extra_index'):
                indices[state['extra_index']] = mapping
            return httpx.Response(200, json=indices)
        if request.method == 'DELETE':
            return httpx.Response(200, json={'pits': [{'pit_id': 'private-token', 'successful': True}]})
        if request.url.path.endswith('/_search/point_in_time'):
            return httpx.Response(200, json={'pit_id': 'private-token', '_shards': SHARDS})
        state['searches'] += 1
        if state['before_search']:
            state['before_search']()
        if state.get('timeout_on_search') == state['searches']:
            raise httpx.ReadTimeout('synthetic timeout')
        if state['fetch_error'] or state['fail_on_search'] == state['searches']:
            return httpx.Response(state.get('failure_status', 500), json={'secret': 'must-not-leak'})
        query = json.loads(request.content)
        after = query.get('search_after')
        hits = [copy.deepcopy(d) for d in state['documents']
                if state.get('repeat_page') or after is None or d['sort'] > after]
        return httpx.Response(200, json={'timed_out': False, '_shards': SHARDS,
                                       'hits': {'hits': hits[:query['size']]}})

    @contextmanager
    def open_client(integration):
        client = WazuhIndexerClient(base_url=integration.base_url, username='test', password='secret',
                                    ca_certificate=certifi.where())
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            yield client
        finally:
            client.close()
    monkeypatch.setattr('app.wazuh_sync.open_wazuh_client', open_client)
    monkeypatch.setattr('app.wazuh_sync.utcnow', lambda: NOW)
    return state


def counts(session):
    return tuple(session.scalar(select(func.count()).select_from(model))
                 for model in (EvidenceRecord, AuditLog, WazuhSyncCheckpoint))


def test_sync_commits_evidence_audit_and_checkpoint(context, monkeypatch):
    api, db = context; identity, principal, key = owner(db)
    install(monkeypatch)
    result = api.post(f'/v1/integrations/wazuh/{identity}/sync', headers={'X-API-Key': key})
    assert result.status_code == 200, result.text
    assert result.json()['imported'] == 1
    checkpoint = db.get(WazuhSyncCheckpoint, identity)
    assert checkpoint.status == 'idle' and checkpoint.completed_window_end_ms == 2000
    assert checkpoint.cursor_sort is checkpoint.snapshot_id is None
    assert checkpoint.imported_count == 1 and checkpoint.generation == 2
    events = db.scalars(select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
                        .order_by(AuditLog.sequence_number)).all()
    assert verify_audit_chain(events)['valid']
    evidence = db.scalar(select(EvidenceRecord).where(EvidenceRecord.tenant_id == principal.tenant_id))
    verified = api.get(f'/v1/evidence/{evidence.id}/verify', headers={'X-API-Key': key})
    assert verified.json()['integrity_valid']
    assert 'private-token' not in result.text and 'source_filter' not in result.text


def test_duplicate_replay_preserves_original_evidence(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db)
    state = install(monkeypatch)
    sync_wazuh(db, principal, identity, page_size=1)
    evidence = db.scalar(select(EvidenceRecord).where(EvidenceRecord.tenant_id == principal.tenant_id))
    original_hash = evidence.content_sha256
    state['documents'][0]['_score'] = 123  # Search metadata is not observed source content.
    result = sync_wazuh(db, principal, identity, page_size=1)
    assert result['duplicates'] == 1 and result['imported'] == 0
    db.refresh(evidence)
    assert evidence.content_sha256 == original_hash


def test_changed_source_conflicts_and_does_not_advance(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db)
    state = install(monkeypatch)
    sync_wazuh(db, principal, identity)
    before = db.get(WazuhSyncCheckpoint, identity).generation
    db.rollback()
    state['documents'][0]['_source']['message'] = 'changed'
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError, match='wazuh_sync_identity_conflict'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity).generation == before


@pytest.mark.parametrize('failure', ['evidence', 'audit', 'checkpoint', 'commit'])
def test_failed_batch_rolls_back_all_writes(context, monkeypatch, failure):
    _, db = context; identity, principal, _ = owner(db); install(monkeypatch)
    before = counts(db); db.rollback()
    if failure == 'evidence':
        monkeypatch.setattr('app.wazuh_sync.store_alert', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('secret')))
    elif failure == 'audit':
        monkeypatch.setattr('app.wazuh_sync.record_audit_event', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('secret')))
    elif failure == 'checkpoint':
        from sqlalchemy import event
        def fail(mapper, connection, target):
            raise RuntimeError('secret')
        event.listen(WazuhSyncCheckpoint, 'before_insert', fail)
    else:
        commit = db.commit
        def fail_page_commit():
            # Lease commits are independent; fail the evidence/audit/checkpoint
            # commit after record_audit_event has flushed the pending page.
            pending = db.scalar(select(WazuhSyncCheckpoint.generation).where(
                WazuhSyncCheckpoint.integration_id == identity))
            if pending is not None:
                raise RuntimeError('secret')
            commit()
        monkeypatch.setattr(db, 'commit', fail_page_commit)
    from app.wazuh_sync import WazuhSyncError
    try:
        with pytest.raises(WazuhSyncError):
            sync_wazuh(db, principal, identity)
        assert counts(db) == before
    finally:
        if failure == 'checkpoint':
            event.remove(WazuhSyncCheckpoint, 'before_insert', fail)


def test_empty_window_completes_without_evidence(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); install(monkeypatch, [])
    result = sync_wazuh(db, principal, identity)
    assert result['imported'] == result['duplicates'] == 0
    assert db.get(WazuhSyncCheckpoint, identity).completed_window_end_ms == 2000


@pytest.mark.parametrize('case,status', [('unauthenticated', 401), ('foreign', 404),
                                        ('missing', 404), ('inactive', 409), ('scope', 503),
                                        ('metadata', 502), ('fetch', 502)])
def test_api_failure_boundaries(context, monkeypatch, case, status):
    api, db = context; identity, principal, key = owner(db); state = install(monkeypatch)
    if case == 'foreign':
        identity, _, _ = owner(db)
    elif case == 'missing': identity = uuid4()
    elif case == 'inactive':
        db.get(WazuhIntegration, identity).is_active = False; db.commit()
    elif case == 'scope': settings.wazuh_sync_scopes.clear()
    elif case == 'metadata': state['metadata_error'] = True
    elif case == 'fetch': state['fetch_error'] = True
    before = counts(db); db.rollback()
    result = api.post(f'/v1/integrations/wazuh/{identity}/sync',
                      headers={} if case == 'unauthenticated' else {'X-API-Key': key})
    assert result.status_code == status, result.text
    assert counts(db) == before
    assert 'must-not-leak' not in result.text and 'private-token' not in result.text
    if case in ('foreign', 'missing', 'inactive', 'scope', 'unauthenticated'):
        assert not state['requests']


def test_source_scope_defense_in_depth(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db)
    install(monkeypatch, [doc(source_value='other-org')])
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError, match='wazuh_sync_scope_mismatch'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity) is None


def test_later_page_failure_keeps_committed_progress_and_replays_safely(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db)
    state = install(monkeypatch, [doc('a'), doc('b')]); state['fail_on_search'] = 2
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError):
        sync_wazuh(db, principal, identity, page_size=1)
    checkpoint = db.get(WazuhSyncCheckpoint, identity)
    assert checkpoint.generation == 1 and checkpoint.cursor_sort[-1] == 'a'
    assert checkpoint.completed_window_end_ms is None and checkpoint.imported_count == 1
    old_snapshot = checkpoint.snapshot_id
    db.rollback(); state['fail_on_search'] = None
    result = sync_wazuh(db, principal, identity, page_size=1)
    assert result['imported'] == 1 and result['duplicates'] == 1
    checkpoint = db.get(WazuhSyncCheckpoint, identity)
    assert checkpoint.completed_window_end_ms == 2000 and checkpoint.imported_count == 2
    assert checkpoint.snapshot_id is None and old_snapshot is not None
    events = db.scalars(select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
                        .order_by(AuditLog.sequence_number)).all()
    assert verify_audit_chain(events)['valid']


def test_stale_generation_rejected_before_writes(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    def competing_commit():
        state['before_search'] = None
        db.add(WazuhSyncCheckpoint(integration_id=identity, tenant_id=principal.tenant_id, generation=1))
        db.commit()
    state['before_search'] = competing_commit
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError, match='wazuh_sync_stale_generation'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity).generation == 1
    assert db.scalar(select(func.count()).select_from(EvidenceRecord).where(
        EvidenceRecord.tenant_id == principal.tenant_id)) == 0


def test_recreated_index_rejected_without_checkpoint_advancement(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    sync_wazuh(db, principal, identity)
    generation = db.get(WazuhSyncCheckpoint, identity).generation; db.rollback()
    state['uuid'] = 'recreated-index'
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError, match='wazuh_sync_source_changed'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity).generation == generation


def test_checkpoint_update_failure_rolls_back_replay_audit(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); install(monkeypatch)
    sync_wazuh(db, principal, identity)
    before = counts(db); generation = db.get(WazuhSyncCheckpoint, identity).generation; db.rollback()
    from sqlalchemy import event
    from app.wazuh_sync import WazuhSyncError
    def fail(mapper, connection, target):
        raise RuntimeError('checkpoint update failed')
    event.listen(WazuhSyncCheckpoint, 'before_update', fail)
    try:
        with pytest.raises(WazuhSyncError):
            sync_wazuh(db, principal, identity)
        assert counts(db) == before
        assert db.get(WazuhSyncCheckpoint, identity).generation == generation
    finally:
        event.remove(WazuhSyncCheckpoint, 'before_update', fail)


@pytest.mark.parametrize('limit', [0, 101, 'bad'])
def test_sync_rejects_invalid_api_limits(context, monkeypatch, limit):
    api, db = context; identity, _, key = owner(db); state = install(monkeypatch)
    result = api.post(f'/v1/integrations/wazuh/{identity}/sync?limit={limit}', headers={'X-API-Key': key})
    assert result.status_code == 422 and not state['requests']


@pytest.mark.parametrize('evidence_type,collector', [('interpretation', 'wazuh-indexer'),
                                                   ('observation', 'api-ingestion')])
def test_noncollector_or_interpretation_collision_is_not_an_observation_replay(
    context, monkeypatch, evidence_type, collector,
):
    _, db = context; identity, principal, _ = owner(db); install(monkeypatch)
    from app.wazuh import normalize_wazuh_alert
    from app.evidence import calculate_evidence_hash
    alert = normalize_wazuh_alert(doc())
    payload = dict(alert); payload['event_time'] = alert['event_time'].isoformat()
    envelope = dict(evidence_type=evidence_type, source_type='wazuh',
                    source_reference=f'integration:{identity}:{INDEX}/a',
                    collector_name=collector, collector_version='0.1.0', trust_level='unverified',
                    event_time=alert['event_time'], payload=payload)
    db.add(EvidenceRecord(**envelope, tenant_id=principal.tenant_id,
                          content_sha256=calculate_evidence_hash(**envelope)))
    db.commit()
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError, match='wazuh_sync_identity_conflict'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity) is None


def test_http_occurs_outside_database_transactions(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    def assert_no_transaction():
        assert not db.in_transaction()
    state['before_request'] = assert_no_transaction
    assert sync_wazuh(db, principal, identity)['status'] == 'completed'


def test_not_due_does_not_open_client_or_create_progress(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    monkeypatch.setattr('app.wazuh_sync.utcnow', lambda: datetime.fromtimestamp(0.5, timezone.utc))
    assert sync_wazuh(db, principal, identity)['status'] == 'not_due'
    assert not state['requests'] and db.get(WazuhSyncCheckpoint, identity) is None


def test_api_key_revoked_during_fetch_cannot_commit(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    def revoke():
        state['before_search'] = None
        db.get(TenantAPIKey, principal.api_key_id).revoked_at = NOW
        db.commit()
    state['before_search'] = revoke
    from app.wazuh_sync import WazuhSyncError
    with pytest.raises(WazuhSyncError, match='invalid_api_key'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity) is None
