from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

from sqlalchemy import select

from app.audit.integrity import record_audit_event, verify_audit_chain
from app.db import SessionLocal
from app.database.models import AuditLog, Tenant


def test_concurrent_audit_writes_preserve_sequence_and_hash_chain():
    worker_count = 5
    barrier = Barrier(worker_count)

    # Create and commit a tenant before starting concurrent writers.
    with SessionLocal() as session:
        tenant = Tenant(
            name="Audit Concurrency Test",
            slug=f"audit-concurrency-{uuid4().hex}",
        )
        session.add(tenant)
        session.commit()
        tenant_id = tenant.id

    def write_audit_event(worker_number):
        # Each worker uses its own independent database session.
        with SessionLocal() as session:
            barrier.wait(timeout=15)

            event = record_audit_event(
                db=session,
                tenant_id=tenant_id,
                actor_type="service",
                actor_id=uuid4(),
                action="concurrency.test",
                resource_type="test_resource",
                resource_id=uuid4(),
                details={"worker": worker_number},
            )

            result = {
                "sequence_number": event.sequence_number,
                "entry_hash": event.entry_hash,
            }

            session.commit()
            return result

    # Start all writers concurrently.
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(write_audit_event, worker_number)
            for worker_number in range(worker_count)
        ]

        results = [future.result(timeout=30) for future in futures]

    # Read committed events after all writers have completed.
    with SessionLocal() as session:
        statement = (
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.sequence_number.asc())
        )
        events = session.scalars(statement).all()

        sequence_numbers = [
            event.sequence_number for event in events
        ]

        assert len(events) == worker_count
        assert sequence_numbers == list(range(1, worker_count + 1))

        integrity = verify_audit_chain(events)

        assert integrity["valid"] is True
        assert integrity["total"] == worker_count
        assert integrity["checked"] == worker_count
        assert integrity["first_invalid_sequence"] is None
        assert integrity["failure_reason"] is None

    assert len(results) == worker_count
    assert sorted(
        result["sequence_number"] for result in results
    ) == list(range(1, worker_count + 1))


def test_concurrent_evidence_foreign_keys_do_not_deadlock_audit_lock():
    from app.db import engine
    from app.evidence.hashing import calculate_evidence_hash
    from app.database.models import EvidenceRecord
    assert engine.url.database == 'ai_soc_test'
    with SessionLocal() as session:
        tenant = Tenant(name='Evidence audit concurrency', slug=f'evidence-audit-{uuid4().hex}')
        session.add(tenant); session.commit(); tenant_id = tenant.id
    ready = Barrier(2)
    def write(number):
        with SessionLocal() as session:
            envelope = dict(evidence_type='observation', source_type='test',
                            source_reference=f'concurrent-{uuid4().hex}',
                            collector_name='test', collector_version='1', trust_level='unverified', payload={})
            session.add(EvidenceRecord(**envelope, tenant_id=tenant_id,
                                       content_sha256=calculate_evidence_hash(**envelope)))
            session.flush()  # Both transactions now hold FK KEY SHARE on tenant.
            ready.wait(timeout=15)
            record_audit_event(session, tenant_id=tenant_id, actor_type='service',
                               actor_id=None, action='evidence.concurrent', resource_type='test')
            session.commit()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write, number) for number in range(2)]
        for future in futures:
            future.result(timeout=20)
    with SessionLocal() as session:
        events = session.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant_id)
                                 .order_by(AuditLog.sequence_number)).all()
        assert len(events) == 2 and verify_audit_chain(events)['valid']
