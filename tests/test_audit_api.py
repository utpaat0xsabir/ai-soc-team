
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.audit import GENESIS_HASH, record_audit_event
from app.db import engine, get_db
from app.main import app
from app.models import (
    AuditLog,
    EvidenceRecord,
    Tenant,
    TenantAPIKey,
)


@pytest.fixture
def audit_api_context():
    connection = engine.connect()
    transaction = connection.begin()

    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
    )

    original_overrides = app.dependency_overrides.copy()

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client, session
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)

        session.close()
        transaction.rollback()
        connection.close()


def create_tenant_and_key(session, name):
    tenant = Tenant(
        name=name,
        slug=f"audit-test-{uuid4().hex}",
    )

    api_key = generate_api_key()

    session.add(tenant)
    session.flush()

    session.add(
        TenantAPIKey(
            tenant_id=tenant.id,
            name="audit-integration-test",
            key_hash=hash_api_key(api_key),
        )
    )

    session.commit()
    session.refresh(tenant)

    return tenant, api_key


def create_audit_event(
    session,
    *,
    tenant_id,
    action,
):
    return record_audit_event(
        session,
        tenant_id=tenant_id,
        actor_type="api_key",
        actor_id=uuid4(),
        action=action,
        resource_type="evidence",
        resource_id=uuid4(),
        details={"test": True},
    )


def test_audit_list_returns_tenant_records(audit_api_context):
    client, session = audit_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Audit Owner Tenant",
    )

    event = create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.ingested",
    )

    response = client.get(
        "/v1/audit-logs",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == str(event.id)
    assert data["items"][0]["action"] == "evidence.ingested"
    assert data["items"][0]["actor_type"] == "api_key"
    assert data["items"][0]["details"] == {"test": True}


def test_audit_list_enforces_tenant_isolation(audit_api_context):
    client, session = audit_api_context

    tenant_a, api_key_a = create_tenant_and_key(
        session,
        "Audit Tenant A",
    )

    tenant_b, api_key_b = create_tenant_and_key(
        session,
        "Audit Tenant B",
    )

    event_a = create_audit_event(
        session,
        tenant_id=tenant_a.id,
        action="evidence.ingested",
    )

    event_b = create_audit_event(
        session,
        tenant_id=tenant_b.id,
        action="evidence.lineage_created",
    )

    response_a = client.get(
        "/v1/audit-logs",
        headers={"X-API-Key": api_key_a},
    )

    response_b = client.get(
        "/v1/audit-logs",
        headers={"X-API-Key": api_key_b},
    )

    assert response_a.status_code == 200, response_a.text
    assert response_b.status_code == 200, response_b.text

    data_a = response_a.json()
    data_b = response_b.json()

    assert data_a["total"] == 1
    assert data_b["total"] == 1

    assert data_a["items"][0]["id"] == str(event_a.id)
    assert data_b["items"][0]["id"] == str(event_b.id)

    assert all(
        item["id"] != str(event_b.id)
        for item in data_a["items"]
    )

    assert all(
        item["id"] != str(event_a.id)
        for item in data_b["items"]
    )


def test_audit_list_filters_by_action(audit_api_context):
    client, session = audit_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Audit Filter Tenant",
    )

    create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.ingested",
    )

    create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.lineage_created",
    )

    create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.ingested",
    )

    response = client.get(
        "/v1/audit-logs",
        params={"action": "evidence.ingested"},
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total"] == 2
    assert len(data["items"]) == 2

    assert all(
        item["action"] == "evidence.ingested"
        for item in data["items"]
    )


def test_audit_list_supports_pagination(audit_api_context):
    client, session = audit_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Audit Pagination Tenant",
    )

    for index in range(3):
        create_audit_event(
            session,
            tenant_id=tenant.id,
            action=f"audit.pagination.{index}",
        )

    response_first = client.get(
        "/v1/audit-logs",
        params={"limit": 2, "offset": 0},
        headers={"X-API-Key": api_key},
    )

    response_second = client.get(
        "/v1/audit-logs",
        params={"limit": 2, "offset": 2},
        headers={"X-API-Key": api_key},
    )

    assert response_first.status_code == 200, response_first.text
    assert response_second.status_code == 200, response_second.text

    first = response_first.json()
    second = response_second.json()

    assert first["total"] == 3
    assert first["limit"] == 2
    assert first["offset"] == 0
    assert len(first["items"]) == 2

    assert second["total"] == 3
    assert second["limit"] == 2
    assert second["offset"] == 2
    assert len(second["items"]) == 1

    first_ids = {item["id"] for item in first["items"]}
    second_ids = {item["id"] for item in second["items"]}

    assert first_ids.isdisjoint(second_ids)


def test_audit_list_returns_empty_result(audit_api_context):
    client, session = audit_api_context

    _, api_key = create_tenant_and_key(
        session,
        "Audit Empty Tenant",
    )

    response = client.get(
        "/v1/audit-logs",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["items"] == []
    assert data["total"] == 0
    assert data["limit"] == 50
    assert data["offset"] == 0


def test_audit_events_form_a_valid_hash_chain(audit_api_context):
    _, session = audit_api_context

    tenant, _ = create_tenant_and_key(
        session,
        "Audit Hash Chain Tenant",
    )

    first = create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.ingested",
    )

    second = create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.lineage_created",
    )

    assert first.sequence_number == 1
    assert first.previous_hash == GENESIS_HASH
    assert len(first.entry_hash) == 64

    assert second.sequence_number == 2
    assert second.previous_hash == first.entry_hash
    assert len(second.entry_hash) == 64

    assert first.entry_hash != second.entry_hash


def test_audit_hash_chains_are_independent_per_tenant(audit_api_context):
    _, session = audit_api_context

    tenant_a, _ = create_tenant_and_key(
        session,
        "Audit Chain Tenant A",
    )

    tenant_b, _ = create_tenant_and_key(
        session,
        "Audit Chain Tenant B",
    )

    event_a = create_audit_event(
        session,
        tenant_id=tenant_a.id,
        action="evidence.ingested",
    )

    event_b = create_audit_event(
        session,
        tenant_id=tenant_b.id,
        action="evidence.ingested",
    )

    assert event_a.sequence_number == 1
    assert event_b.sequence_number == 1

    assert event_a.previous_hash == GENESIS_HASH
    assert event_b.previous_hash == GENESIS_HASH

    assert event_a.tenant_id != event_b.tenant_id


def test_audit_verification_endpoint_accepts_valid_chain(audit_api_context):
    client, session = audit_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Audit Verification Tenant",
    )

    create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.ingested",
    )

    create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.lineage_created",
    )

    response = client.get(
        "/v1/audit-logs/verify",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["valid"] is True
    assert data["total"] == 2
    assert data["checked"] == 2
    assert data["first_invalid_sequence"] is None
    assert data["failure_reason"] is None
    assert data["verified_at"] is not None


def test_audit_verification_endpoint_accepts_empty_chain(audit_api_context):
    client, session = audit_api_context

    _, api_key = create_tenant_and_key(
        session,
        "Audit Empty Verification Tenant",
    )

    response = client.get(
        "/v1/audit-logs/verify",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["valid"] is True
    assert data["total"] == 0
    assert data["checked"] == 0
    assert data["first_invalid_sequence"] is None
    assert data["failure_reason"] is None


def test_audit_verification_endpoint_is_tenant_scoped(audit_api_context):
    client, session = audit_api_context

    tenant_a, api_key_a = create_tenant_and_key(
        session,
        "Audit Verification Tenant A",
    )

    tenant_b, _ = create_tenant_and_key(
        session,
        "Audit Verification Tenant B",
    )

    create_audit_event(
        session,
        tenant_id=tenant_a.id,
        action="evidence.ingested",
    )

    create_audit_event(
        session,
        tenant_id=tenant_b.id,
        action="evidence.ingested",
    )

    create_audit_event(
        session,
        tenant_id=tenant_b.id,
        action="evidence.lineage_created",
    )

    response = client.get(
        "/v1/audit-logs/verify",
        headers={"X-API-Key": api_key_a},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["valid"] is True
    assert data["total"] == 1
    assert data["checked"] == 1


@pytest.mark.parametrize(
    "operation",
    ["update", "delete", "truncate"],
)
def test_audit_logs_reject_mutations(
    audit_api_context,
    operation,
):
    _, session = audit_api_context

    tenant, _ = create_tenant_and_key(
        session,
        f"Audit Mutation Tenant {operation}",
    )

    event = create_audit_event(
        session,
        tenant_id=tenant.id,
        action="evidence.ingested",
    )

    if operation == "update":
        statement = text(
            """
            UPDATE audit_logs
            SET action = 'tampered.action'
            WHERE id = :event_id
            """
        )
        parameters = {"event_id": event.id}

    elif operation == "delete":
        statement = text(
            """
            DELETE FROM audit_logs
            WHERE id = :event_id
            """
        )
        parameters = {"event_id": event.id}

    else:
        statement = text("TRUNCATE TABLE audit_logs")
        parameters = {}

    with pytest.raises(DBAPIError):
        with session.begin_nested():
            session.execute(statement, parameters)

    result = session.execute(
        text(
            """
            SELECT action
            FROM audit_logs
            WHERE id = :event_id
            """
        ),
        {"event_id": event.id},
    ).scalar_one()

    assert result == "evidence.ingested"


def test_evidence_and_audit_roll_back_together_when_commit_fails(
    audit_api_context,
    monkeypatch,
):
    client, session = audit_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Audit Atomicity Tenant",
    )

    def fail_commit(self):
        raise RuntimeError("simulated_commit_failure")

    # Simulate failure after both records have been flushed.
    monkeypatch.setattr(Session, "commit", fail_commit)

    payload = {
        "evidence_type": "observation",
        "source_type": "wazuh",
        "source_reference": "agent-atomicity/alert-001",
        "event_time": "2026-11-09T08:00:00Z",
        "payload": {
            "rule_id": "752",
            "description": "Atomicity test event",
        },
    }

    with pytest.raises(
        RuntimeError,
        match="simulated_commit_failure",
    ):
        client.post(
            "/v1/evidence",
            json=payload,
            headers={"X-API-Key": api_key},
        )

    evidence_count = session.query(EvidenceRecord).filter(
        EvidenceRecord.tenant_id == tenant.id,
        EvidenceRecord.source_reference == "agent-atomicity/alert-001",
    ).count()

    audit_count = session.query(AuditLog).filter(
        AuditLog.tenant_id == tenant.id,
        AuditLog.action == "evidence.ingested",
    ).count()

    assert evidence_count == 0
    assert audit_count == 0
