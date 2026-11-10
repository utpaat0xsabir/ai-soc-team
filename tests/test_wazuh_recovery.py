from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app.models import AuditLog, EvidenceRecord, WazuhSyncCheckpoint, WazuhSyncLease
from app.audit import verify_audit_chain
from app.wazuh_sync import sync_wazuh, WazuhSyncError
from test_wazuh_sync import context, owner, install, doc


def test_retryable_read_failure_replays_committed_window(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db)
    state = install(monkeypatch, [doc('a'), doc('b')])
    state['fail_on_search'] = 2; state['failure_status'] = 503
    monkeypatch.setattr('app.wazuh_sync.retry_wait', lambda delay: None)
    result = sync_wazuh(db, principal, identity, page_size=1)
    assert result['imported'] == 2 and result['duplicates'] == 1
    assert db.get(WazuhSyncCheckpoint, identity).completed_window_end_ms == 2000
    events = db.scalars(select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
                        .order_by(AuditLog.sequence_number)).all()
    assert verify_audit_chain(events)['valid']


def test_ambiguous_commit_rereads_durable_progress(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); install(monkeypatch)
    monkeypatch.setattr('app.wazuh_sync.retry_wait', lambda delay: None)
    commit = db.commit
    lost = False
    def lose_acknowledgement():
        nonlocal lost
        pending_page = db.scalar(select(WazuhSyncCheckpoint.generation).where(
            WazuhSyncCheckpoint.integration_id == identity)) is not None
        commit()
        if pending_page and not lost:
            lost = True
            raise OperationalError('COMMIT', {}, OSError('connection lost'), connection_invalidated=True)
    monkeypatch.setattr(db, 'commit', lose_acknowledgement)
    result = sync_wazuh(db, principal, identity)
    assert lost and result['imported'] == 1
    assert db.scalar(select(func.count()).select_from(EvidenceRecord).where(
        EvidenceRecord.tenant_id == principal.tenant_id)) == 1
    assert db.get(WazuhSyncCheckpoint, identity).completed_window_end_ms == 2000


def test_expiry_during_fetch_prevents_page_commit(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    def expire():
        state['before_search'] = None
        db.get(WazuhSyncLease, identity).expires_at = db.scalar(select(func.clock_timestamp())) - timedelta(seconds=1)
        db.commit()
    state['before_search'] = expire
    with pytest.raises(WazuhSyncError, match='wazuh_sync_lease_lost'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity) is None


def test_normal_rollover_is_adopted_between_windows(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    sync_wazuh(db, principal, identity)
    state['extra_index'] = 'wazuh-alerts-new'
    result = sync_wazuh(db, principal, identity)
    assert result['status'] == 'completed'
    checkpoint = db.get(WazuhSyncCheckpoint, identity)
    assert checkpoint.source_manifest['wazuh-alerts-new'] == 'new-index-uuid'


def test_deleted_index_reports_gap_without_advancing(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    state['extra_index'] = 'wazuh-alerts-new'
    sync_wazuh(db, principal, identity)
    generation = db.get(WazuhSyncCheckpoint, identity).generation; db.rollback()
    state['extra_index'] = None
    with pytest.raises(WazuhSyncError, match='wazuh_sync_retention_gap'):
        sync_wazuh(db, principal, identity)
    assert db.get(WazuhSyncCheckpoint, identity).generation == generation


@pytest.mark.parametrize('failure', ['timeout', 'expired_snapshot'])
def test_timeout_or_snapshot_expiry_restarts_from_committed_state(context, monkeypatch, failure):
    _, db = context; identity, principal, _ = owner(db)
    state = install(monkeypatch, [doc('a'), doc('b')])
    if failure == 'timeout':
        state['timeout_on_search'] = 2
    else:
        state['fail_on_search'] = 2; state['failure_status'] = 404
    monkeypatch.setattr('app.wazuh_sync.retry_wait', lambda delay: None)
    result = sync_wazuh(db, principal, identity, page_size=1)
    assert result['imported'] == 2 and result['duplicates'] == 1
    assert db.get(WazuhSyncCheckpoint, identity).imported_count == 2


def test_persistent_retryable_failures_are_bounded_and_release_lease(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    state['fetch_error'] = True; state['failure_status'] = 503
    waits = []
    monkeypatch.setattr('app.wazuh_sync.retry_wait', waits.append)
    with pytest.raises(WazuhSyncError, match='wazuh_sync_indexer_unavailable'):
        sync_wazuh(db, principal, identity)
    assert state['searches'] == 3 and waits == [0.1, 0.2]
    assert db.get(WazuhSyncCheckpoint, identity) is None
    assert db.get(WazuhSyncLease, identity).owner_token is None


def test_repeated_page_stops_without_advancing_again(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    state['repeat_page'] = True
    with pytest.raises(WazuhSyncError, match='wazuh_sync_indexer_unavailable'):
        sync_wazuh(db, principal, identity, page_size=1)
    checkpoint = db.get(WazuhSyncCheckpoint, identity)
    assert checkpoint.imported_count == 1 and checkpoint.generation == 1
    assert checkpoint.completed_window_end_ms is None


def test_rollover_during_scan_is_deferred_until_next_window(context, monkeypatch):
    _, db = context; identity, principal, _ = owner(db); state = install(monkeypatch)
    def rollover():
        state['before_search'] = None
        state['extra_index'] = 'wazuh-alerts-new'
    state['before_search'] = rollover
    sync_wazuh(db, principal, identity)
    assert 'wazuh-alerts-new' not in db.get(WazuhSyncCheckpoint, identity).source_manifest
    db.rollback()
    sync_wazuh(db, principal, identity)
    assert 'wazuh-alerts-new' in db.get(WazuhSyncCheckpoint, identity).source_manifest
