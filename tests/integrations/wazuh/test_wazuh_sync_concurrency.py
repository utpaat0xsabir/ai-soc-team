from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Barrier, Event, local

import pytest
from sqlalchemy import func, select, text

from app.audit.integrity import verify_audit_chain
from app.core.config import settings
from app.db import SessionLocal, engine
from app.database.models import AuditLog, EvidenceRecord, WazuhIntegration, WazuhSyncCheckpoint, WazuhSyncLease
from app.integrations.wazuh.sync import sync_wazuh, WazuhSyncError
from tests.integrations.wazuh.test_wazuh_sync import owner, install, doc


@pytest.fixture
def committed_context(monkeypatch):
    assert engine.url.database == 'ai_soc_test'
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT current_database()')) == 'ai_soc_test'
    monkeypatch.setattr(settings, 'wazuh_sync_scopes', {})
    with SessionLocal() as db:
        identity, principal, _ = owner(db)
    return identity, principal


def assert_consistent(principal, expected_evidence):
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EvidenceRecord).where(
            EvidenceRecord.tenant_id == principal.tenant_id)) == expected_evidence
        events = db.scalars(select(AuditLog).where(AuditLog.tenant_id == principal.tenant_id)
                            .order_by(AuditLog.sequence_number)).all()
        assert verify_audit_chain(events)['valid']


def test_competing_worker_is_rejected_before_indexer_access(committed_context, monkeypatch):
    identity, principal = committed_context
    state = install(monkeypatch)
    entered, proceed = Event(), Event()
    def pause():
        state['before_search'] = None
        entered.set()
        assert proceed.wait(timeout=15)
    state['before_search'] = pause
    def run():
        with SessionLocal() as db:
            return sync_wazuh(db, principal, identity)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(run)
        try:
            assert entered.wait(timeout=15)
            request_count = len(state['requests'])
            competing = executor.submit(run)
            with pytest.raises(WazuhSyncError, match='wazuh_sync_busy'):
                competing.result(timeout=10)
            assert len(state['requests']) == request_count
        finally:
            proceed.set()
        assert first.result(timeout=15)['imported'] == 1
    assert_consistent(principal, 1)


def test_paused_expired_worker_cannot_commit_after_takeover(committed_context, monkeypatch):
    identity, principal = committed_context; state = install(monkeypatch, [doc('a'), doc('b')])
    entered, proceed = Event(), Event()
    def pause():
        if state['searches'] != 2:
            return
        state['before_search'] = None
        entered.set()
        assert proceed.wait(timeout=15)
    state['before_search'] = pause
    def run():
        with SessionLocal() as db:
            return sync_wazuh(db, principal, identity, page_size=1)
    with ThreadPoolExecutor(max_workers=2) as executor:
        old = executor.submit(run)
        try:
            assert entered.wait(timeout=15)
            with SessionLocal() as db:
                row = db.get(WazuhSyncLease, identity)
                old_fence = row.fence
                row.expires_at = db.scalar(select(func.clock_timestamp())) - timedelta(seconds=1)
                db.commit()
            assert executor.submit(run).result(timeout=10)['imported'] == 1
        finally:
            proceed.set()
        with pytest.raises(WazuhSyncError, match='wazuh_sync_lease_lost'):
            old.result(timeout=15)
    with SessionLocal() as db:
        row = db.get(WazuhSyncLease, identity)
        assert row.fence > old_fence and row.owner_token is None
        assert db.get(WazuhSyncCheckpoint, identity).imported_count == 2
    assert_consistent(principal, 2)


def test_different_integrations_preserve_shared_tenant_audit_chain(committed_context, monkeypatch):
    identity, principal = committed_context
    with SessionLocal() as db:
        second = WazuhIntegration(
            tenant_id=principal.tenant_id, name='Second concurrent integration',
            base_url='https://indexer.test', username='test',
            credential_reference='env:WAZUH_INDEXER_PASSWORD', ca_certificate_path='/test/ca')
        db.add(second); db.commit(); other_id = second.id
    settings.wazuh_sync_scopes[str(other_id)] = deepcopy(settings.wazuh_sync_scopes[str(identity)])
    state = install(monkeypatch)
    ready = Barrier(2); thread = local()
    def align():
        if not getattr(thread, 'aligned', False):
            thread.aligned = True
            ready.wait(timeout=15)
    state['before_search'] = align
    def run(integration_id):
        with SessionLocal() as db:
            return sync_wazuh(db, principal, integration_id)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run, current) for current in (identity, other_id)]
        assert [future.result(timeout=20)['imported'] for future in futures] == [1, 1]
    assert_consistent(principal, 2)
