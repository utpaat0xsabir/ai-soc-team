from contextlib import contextmanager
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models import TenantAPIKey, WazuhSyncCheckpoint, WazuhSyncLease
from app.wazuh_leases import claim_lease, release_lease
from app.wazuh_scheduler import ScheduledJob, run_scheduled_job
from app.wazuh_sync import WazuhSyncError, WazuhSyncStopped
from test_wazuh_sync import context, owner, install, doc, NOW


def setup(context, monkeypatch):
    _, db = context; identity, principal, key = owner(db); state = install(monkeypatch, [doc('a'), doc('b')])
    monkeypatch.setenv('AI_SOC_WORKER_TEST_API_KEY', key)
    @contextmanager
    def factory(): yield db
    job = ScheduledJob(integration_id=identity, tenant_id=principal.tenant_id,
                       api_key_env='AI_SOC_WORKER_TEST_API_KEY', interval_seconds=10, page_size=1)
    return db, identity, principal, state, factory, job


def test_scheduled_run_uses_existing_authorization_and_checkpoint_path(context, monkeypatch):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    result = run_scheduled_job(job, Event(), session_factory=factory)
    assert result['imported'] == 2
    assert db.get(WazuhSyncCheckpoint, identity).completed_window_end_ms == 2000


@pytest.mark.parametrize('case', ['missing_key', 'revoked', 'wrong_tenant', 'foreign_integration'])
def test_worker_authentication_boundaries(context, monkeypatch, case):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    if case == 'missing_key': monkeypatch.delenv('AI_SOC_WORKER_TEST_API_KEY')
    elif case == 'revoked':
        db.get(TenantAPIKey, principal.api_key_id).revoked_at = NOW; db.commit()
    elif case == 'wrong_tenant': job = job.model_copy(update={'tenant_id': uuid4()})
    else: job = job.model_copy(update={'integration_id': uuid4()})
    with pytest.raises(WazuhSyncError): run_scheduled_job(job, Event(), session_factory=factory)
    assert not state['requests'] and db.get(WazuhSyncCheckpoint, identity) is None


def test_scheduled_worker_cannot_bypass_live_lease(context, monkeypatch):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    handle = claim_lease(db, principal.tenant_id, identity)
    with pytest.raises(WazuhSyncError, match='wazuh_sync_busy'):
        run_scheduled_job(job, Event(), session_factory=factory)
    assert not state['requests']
    release_lease(db, handle)


def test_stop_during_fetch_commits_current_page_and_resumes_later(context, monkeypatch):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    stop = Event(); state['before_search'] = stop.set
    with pytest.raises(WazuhSyncStopped):
        run_scheduled_job(job, stop, session_factory=factory)
    checkpoint = db.get(WazuhSyncCheckpoint, identity)
    assert checkpoint.imported_count == 1 and checkpoint.generation == 1
    assert checkpoint.completed_window_end_ms is None
    lease = db.get(WazuhSyncLease, identity)
    assert lease.owner_token is None and lease.last_outcome == 'interrupted'
    db.rollback(); state['before_search'] = None
    result = run_scheduled_job(job, Event(), session_factory=factory)
    assert result['imported'] == 1 and result['duplicates'] == 1
    assert db.get(WazuhSyncCheckpoint, identity).completed_window_end_ms == 2000


def test_stop_before_start_does_not_create_lease_or_progress(context, monkeypatch):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    stop = Event(); stop.set()
    with pytest.raises(WazuhSyncStopped): run_scheduled_job(job, stop, session_factory=factory)
    assert not state['requests'] and db.get(WazuhSyncLease, identity) is None


def test_shutdown_interrupts_retry_wait_without_replaying(context, monkeypatch):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    state['fetch_error'] = True; state['failure_status'] = 503
    class StopOnWait(Event):
        def wait(self, timeout=None): self.set(); return True
    with pytest.raises(WazuhSyncStopped):
        run_scheduled_job(job, StopOnWait(), session_factory=factory)
    assert state['searches'] == 1
    assert db.get(WazuhSyncCheckpoint, identity) is None
    lease = db.get(WazuhSyncLease, identity)
    assert lease.owner_token is None and lease.last_outcome == 'interrupted'


def test_stop_during_metadata_prevents_snapshot_creation(context, monkeypatch):
    db, identity, principal, state, factory, job = setup(context, monkeypatch)
    stop = Event(); state['before_request'] = stop.set
    with pytest.raises(WazuhSyncStopped):
        run_scheduled_job(job, stop, session_factory=factory)
    assert state['requests'] and all(request.method == 'GET' for request in state['requests'])
    assert db.get(WazuhSyncCheckpoint, identity) is None
