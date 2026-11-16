"""Integration checks for the private advisory audit-lock candidate.

This module runs only with the exact run-scoped disposable-target opt-in. All
committed rows are confined to that disposable PostgreSQL volume.
"""
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import monotonic, sleep
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

if not os.environ.get('AI_SOC_ADVISORY_RUN_ID'):
    pytest.skip('requires run-scoped advisory PostgreSQL target', allow_module_level=True)

from app.api_keys import generate_api_key, hash_api_key  # noqa: E402
from app.audit.integrity import (  # noqa: E402
    _audit_advisory_lock_key,
    _record_audit_event_advisory_candidate,
    verify_audit_chain,
)
from app.database.models import AuditLog, EvidenceRecord, Tenant, TenantAPIKey  # noqa: E402
from app.db import SessionLocal, engine, get_db  # noqa: E402
from app.main import app  # noqa: E402


def create_tenant():
    with SessionLocal() as session:
        tenant = Tenant(name='Advisory integration', slug=f'advisory-{uuid4().hex}')
        session.add(tenant)
        session.commit()
        return tenant.id


def append_event(session, tenant_id, action='advisory.integration'):
    return _record_audit_event_advisory_candidate(
        session,
        tenant_id=tenant_id,
        actor_type='service',
        actor_id=None,
        action=action,
        resource_type='test',
    )


def wait_for_advisory_wait(pid):
    deadline = monotonic() + 5
    with SessionLocal() as observer:
        while monotonic() < deadline:
            waiting = observer.scalar(
                text("SELECT EXISTS (SELECT 1 FROM pg_locks "
                     "WHERE pid = :pid AND locktype = 'advisory' AND NOT granted)"),
                {'pid': pid},
            )
            if waiting:
                return
            sleep(0.01)
    raise AssertionError('writer did not wait for the tenant advisory lock')


def test_same_tenant_simultaneous_first_events_are_serialized_and_chain_valid():
    tenant_id = create_tenant()
    worker_count = 6
    barrier = Barrier(worker_count)

    def write_event(_):
        with SessionLocal() as session:
            barrier.wait(timeout=15)
            event = append_event(session, tenant_id)
            session.commit()
            return event.sequence_number

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        sequences = list(pool.map(write_event, range(worker_count)))
    with SessionLocal() as session:
        events = session.scalars(
            select(AuditLog).where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.sequence_number)
        ).all()
        assert sorted(sequences) == list(range(1, worker_count + 1))
        assert [event.sequence_number for event in events] == list(range(1, worker_count + 1))
        assert verify_audit_chain(events)['valid'] is True


def test_different_tenants_sequence_independently():
    tenant_ids = [create_tenant(), create_tenant()]
    barrier = Barrier(2)

    def write_event(tenant_id):
        with SessionLocal() as session:
            barrier.wait(timeout=15)
            event = append_event(session, tenant_id)
            session.commit()
            return event.sequence_number

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(write_event, tenant_ids)) == [1, 1]
    with SessionLocal() as session:
        for tenant_id in tenant_ids:
            events = session.scalars(
                select(AuditLog).where(AuditLog.tenant_id == tenant_id)
                .order_by(AuditLog.sequence_number)
            ).all()
            assert len(events) == 1
            assert verify_audit_chain(events)['valid'] is True


def test_rollback_releases_lock_and_reuses_uncommitted_sequence():
    tenant_id = create_tenant()
    with SessionLocal() as session:
        rolled_back = append_event(session, tenant_id)
        assert rolled_back.sequence_number == 1
        session.rollback()
    with SessionLocal() as session:
        committed = append_event(session, tenant_id)
        assert committed.sequence_number == 1
        session.commit()
    with SessionLocal() as session:
        events = session.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant_id)).all()
        assert [event.sequence_number for event in events] == [1]
        assert verify_audit_chain(events)['valid'] is True


def test_lock_timeout_fails_closed_without_appending():
    tenant_id = create_tenant()
    holder = SessionLocal()
    writer = SessionLocal()
    try:
        holder.execute(
            text('SELECT pg_advisory_xact_lock(:key)'),
            {'key': _audit_advisory_lock_key(tenant_id)},
        )
        writer.execute(text("SET LOCAL lock_timeout = '150ms'"))
        with pytest.raises(DBAPIError):
            append_event(writer, tenant_id)
        writer.rollback()
        assert writer.scalar(select(AuditLog.id).where(AuditLog.tenant_id == tenant_id)) is None
    finally:
        writer.close()
        holder.rollback()
        holder.close()
    with SessionLocal() as recovered:
        event = append_event(recovered, tenant_id)
        recovered.commit()
        assert event.sequence_number == 1
    with SessionLocal() as verify:
        events = verify.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant_id)).all()
        assert len(events) == 1
        assert verify_audit_chain(events)['valid'] is True


def test_read_committed_waiter_reads_new_chain_head_after_lock_release():
    tenant_id = create_tenant()
    holder = SessionLocal()
    waiter = SessionLocal()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        holder.execute(text('SET TRANSACTION ISOLATION LEVEL READ COMMITTED'))
        waiter.execute(text('SET TRANSACTION ISOLATION LEVEL READ COMMITTED'))
        first = append_event(holder, tenant_id)
        assert first.sequence_number == 1
        assert waiter.scalar(select(AuditLog.id).where(AuditLog.tenant_id == tenant_id)) is None
        waiter_pid = waiter.scalar(text('SELECT pg_backend_pid()'))
        future = executor.submit(lambda: append_event(waiter, tenant_id))
        wait_for_advisory_wait(waiter_pid)
        holder.commit()
        second = future.result(timeout=5)
        waiter.commit()
        assert second.sequence_number == 2
        assert second.previous_hash == first.entry_hash
    finally:
        holder.rollback()
        waiter.rollback()
        holder.close()
        waiter.close()
        executor.shutdown(wait=True, cancel_futures=True)
    with SessionLocal() as verify:
        events = verify.scalars(
            select(AuditLog).where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.sequence_number)
        ).all()
        assert [event.sequence_number for event in events] == [1, 2]
        assert verify_audit_chain(events)['valid'] is True


def test_repeatable_read_stale_snapshot_fails_closed_then_fresh_transaction_recovers():
    tenant_id = create_tenant()
    holder = SessionLocal()
    waiter = SessionLocal()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        first = append_event(holder, tenant_id)
        assert first.sequence_number == 1
        waiter.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'))
        assert waiter.scalar(select(AuditLog.id).where(AuditLog.tenant_id == tenant_id)) is None
        waiter_pid = waiter.scalar(text('SELECT pg_backend_pid()'))

        def stale_attempt():
            try:
                append_event(waiter, tenant_id)
                waiter.commit()
                return None
            except DBAPIError as exc:
                sqlstate = getattr(exc.orig, 'sqlstate', None)
                waiter.rollback()
                return sqlstate

        future = executor.submit(stale_attempt)
        wait_for_advisory_wait(waiter_pid)
        holder.commit()
        assert future.result(timeout=5) in {'23505', '40001'}
    finally:
        holder.rollback()
        waiter.rollback()
        holder.close()
        waiter.close()
        executor.shutdown(wait=True, cancel_futures=True)

    with SessionLocal() as recovered:
        second = append_event(recovered, tenant_id)
        recovered.commit()
        assert second.sequence_number == 2
    with SessionLocal() as verify:
        events = verify.scalars(
            select(AuditLog).where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.sequence_number)
        ).all()
        assert [event.sequence_number for event in events] == [1, 2]
        assert verify_audit_chain(events)['valid'] is True


def test_runtime_role_does_not_need_tenant_update():
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT NOT has_table_privilege(current_user, 'public.tenants', 'UPDATE')"))


@pytest.fixture
def api_context(monkeypatch):
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode='create_savepoint')
    original = app.dependency_overrides.copy()

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, session
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original)
        session.close()
        transaction.rollback()
        connection.close()


def create_key(session):
    tenant = Tenant(name='Advisory API', slug=f'advisory-api-{uuid4().hex}')
    api_key = generate_api_key()
    session.add(tenant)
    session.flush()
    session.add(TenantAPIKey(tenant_id=tenant.id, name='test', key_hash=hash_api_key(api_key)))
    session.commit()
    return tenant.id, api_key


def evidence_payload(reference):
    return {
        'evidence_type': 'observation',
        'source_type': 'test',
        'source_reference': reference,
        'payload': {'source': 'isolated-advisory-test'},
    }


def test_evidence_and_audit_commit_atomically_with_candidate(api_context, monkeypatch):
    from app.api.v1 import evidence as evidence_route

    monkeypatch.setattr(evidence_route, 'record_audit_event', _record_audit_event_advisory_candidate)
    client, session = api_context
    tenant_id, api_key = create_key(session)
    reference = f'advisory-success-{uuid4().hex}'
    response = client.post('/v1/evidence', json=evidence_payload(reference), headers={'X-API-Key': api_key})
    assert response.status_code == 201, response.text
    evidence = session.scalar(select(EvidenceRecord).where(EvidenceRecord.source_reference == reference))
    assert evidence.id is not None
    event = session.scalar(select(AuditLog).where(AuditLog.resource_id == evidence.id))
    assert event is not None
    assert evidence.tenant_id == tenant_id
    assert event.action == 'evidence.ingested'
    assert event.tenant_id == evidence.tenant_id
    assert verify_audit_chain([event])['valid'] is True


def test_evidence_and_audit_both_rollback_if_candidate_fails(api_context, monkeypatch):
    from app.api.v1 import evidence as evidence_route

    client, session = api_context
    tenant_id, api_key = create_key(session)
    reference = f'advisory-failure-{uuid4().hex}'

    def append_then_fail(db, **fields):
        _record_audit_event_advisory_candidate(db, **fields)
        raise RuntimeError('controlled advisory integration failure')

    monkeypatch.setattr(evidence_route, 'record_audit_event', append_then_fail)
    response = client.post('/v1/evidence', json=evidence_payload(reference), headers={'X-API-Key': api_key})
    assert response.status_code == 500
    assert session.scalar(select(EvidenceRecord.id).where(EvidenceRecord.source_reference == reference)) is None
    assert session.scalar(
        select(AuditLog.id).where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action == 'evidence.ingested',
        )
    ) is None


def test_lock_timeout_rolls_back_evidence_and_audit(api_context, monkeypatch):
    from app.api.v1 import evidence as evidence_route

    monkeypatch.setattr(evidence_route, 'record_audit_event', _record_audit_event_advisory_candidate)
    client, session = api_context
    tenant_id, api_key = create_key(session)
    reference = f'advisory-timeout-{uuid4().hex}'
    holder = SessionLocal()
    try:
        holder.execute(
            text('SELECT pg_advisory_xact_lock(:key)'),
            {'key': _audit_advisory_lock_key(tenant_id)},
        )
        session.execute(text("SET LOCAL lock_timeout = '150ms'"))
        response = client.post(
            '/v1/evidence',
            json=evidence_payload(reference),
            headers={'X-API-Key': api_key},
        )
        assert response.status_code == 500
        assert session.scalar(
            select(EvidenceRecord.id).where(EvidenceRecord.source_reference == reference)
        ) is None
        assert session.scalar(
            select(AuditLog.id).where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.action == 'evidence.ingested',
            )
        ) is None
    finally:
        holder.rollback()
        holder.close()
