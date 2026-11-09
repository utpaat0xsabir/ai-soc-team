
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.db import engine, get_db
from app.evidence import calculate_evidence_hash
from app.main import app
from app.models import EvidenceRecord, Tenant, TenantAPIKey


@pytest.fixture
def api_context():
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
        slug=f"evidence-test-{uuid4().hex}",
    )

    api_key = generate_api_key()

    session.add(tenant)
    session.flush()

    session.add(
        TenantAPIKey(
            tenant_id=tenant.id,
            name="evidence-integration-test",
            key_hash=hash_api_key(api_key),
        )
    )

    session.commit()
    session.refresh(tenant)

    return tenant, api_key


def evidence_payload():
    return {
        "evidence_type": "observation",
        "source_type": "wazuh",
        "source_reference": "agent-001/alert-123",
        "event_time": "2026-11-09T08:00:00Z",
        "payload": {
            "rule_id": "752",
            "description": "Example security event",
        },
    }


def test_ingestion_saves_evidence_with_server_metadata(api_context):
    client, session = api_context
    tenant, api_key = create_tenant_and_key(
        session,
        "Evidence Integration Tenant",
    )

    response = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 201

    data = response.json()

    assert data["evidence_type"] == "observation"
    assert data["source_type"] == "wazuh"
    assert data["source_reference"] == "agent-001/alert-123"

    assert data["trust_level"] == "unverified"
    assert data["collector_name"] == "api-ingestion"
    assert data["collector_version"] == "0.1.0"
    assert data["schema_version"] == "1.0"

    assert len(data["content_sha256"]) == 64
    assert data["id"]

    record = session.scalar(
        select(EvidenceRecord).where(
            EvidenceRecord.id == data["id"]
        )
    )

    assert record is not None
    assert record.tenant_id == tenant.id
    assert record.content_sha256 == data["content_sha256"]

    expected_hash = calculate_evidence_hash(
        evidence_type="observation",
        source_type="wazuh",
        source_reference="agent-001/alert-123",
        collector_name="api-ingestion",
        collector_version="0.1.0",
        trust_level="unverified",
        event_time=record.event_time,
        payload={
            "rule_id": "752",
            "description": "Example security event",
        },
    )

    assert record.content_sha256 == expected_hash


@pytest.mark.parametrize(
    "extra_fields",
    [
        {"tenant_id": str(uuid4())},
        {"trust_level": "system_verified"},
        {"collector_name": "attacker"},
        {"content_sha256": "a" * 64},
    ],
)
def test_ingestion_rejects_client_controlled_fields(
    api_context,
    extra_fields,
):
    client, session = api_context
    _, api_key = create_tenant_and_key(
        session,
        "Evidence Security Test Tenant",
    )

    payload = evidence_payload()
    payload.update(extra_fields)

    response = client.post(
        "/v1/evidence",
        json=payload,
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 422


def test_ingestion_rejects_missing_api_key(api_context):
    client, _ = api_context

    response = client.post(
        "/v1/evidence",
        json=evidence_payload(),
    )

    assert response.status_code == 401


def test_ingestion_assigns_authenticated_tenant(api_context):
    client, session = api_context

    tenant_a, key_a = create_tenant_and_key(
        session,
        "Tenant A",
    )

    tenant_b, key_b = create_tenant_and_key(
        session,
        "Tenant B",
    )

    response_a = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_a},
    )

    response_b = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_b},
    )

    assert response_a.status_code == 201
    assert response_b.status_code == 201

    record_a = session.get(
        EvidenceRecord,
        response_a.json()["id"],
    )

    record_b = session.get(
        EvidenceRecord,
        response_b.json()["id"],
    )

    assert record_a.tenant_id == tenant_a.id
    assert record_b.tenant_id == tenant_b.id
    assert record_a.tenant_id != record_b.tenant_id
