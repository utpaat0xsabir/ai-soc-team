from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.audit import verify_audit_chain
from app.db import engine, get_db
from app.main import app
from app.models import (
    AuditLog,
    EvidenceRecord,
    Tenant,
    TenantAPIKey,
    WazuhIntegration,
)
from app.wazuh import WazuhIndexerError


@pytest.fixture
def ingestion_api_context():
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
        slug=f"wazuh-ingestion-test-{uuid4().hex}",
    )

    api_key = generate_api_key()

    session.add(tenant)
    session.flush()

    session.add(
        TenantAPIKey(
            tenant_id=tenant.id,
            name="wazuh-ingestion-test",
            key_hash=hash_api_key(api_key),
        )
    )

    session.commit()
    session.refresh(tenant)

    return tenant, api_key


def create_integration(session, tenant_id, *, active=True):
    integration = WazuhIntegration(
        tenant_id=tenant_id,
        name="Test Wazuh",
        base_url="https://127.0.0.1:9200",
        username="ai_soc_ingest",
        credential_reference="env:WAZUH_INDEXER_PASSWORD",
        ca_certificate_path="/etc/ai-soc/certs/wazuh-root-ca.pem",
        is_active=active,
    )

    session.add(integration)
    session.commit()
    session.refresh(integration)

    return integration


def make_alert(document_id="test-document-001"):
    event_time = datetime(
        2026, 11, 9, 12, 30, tzinfo=timezone.utc
    )

    return {
        "source_type": "wazuh",
        "source_reference": (
            f"wazuh-alerts-4.x-2026.11.09/{document_id}"
        ),
        "event_time": event_time,
        "rule": {
            "id": "5502",
            "level": 3,
            "description": "Test alert",
            "groups": ["authentication"],
        },
        "agent": {
            "id": "001",
            "name": "test-agent",
            "ip": "192.0.2.10",
        },
        "manager": {"name": "test-manager"},
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
        "full_log": "Test authentication event",
        "raw_document": {
            "_index": "wazuh-alerts-4.x-2026.11.09",
            "_id": document_id,
            "_source": {
                "timestamp": "2026-11-09T12:30:00Z",
                "rule": {"id": "5502"},
            },
        },
    }


def install_fake_wazuh_client(monkeypatch, alerts=None, *, error=None):
    class FakeWazuhClient:
        def search_alerts(self, *, size, offset):
            if error is not None:
                raise error

            return {
                "items": alerts or [],
                "total": len(alerts or []),
                "size": size,
                "offset": offset,
            }

    @contextmanager
    def fake_open_wazuh_client(integration):
        yield FakeWazuhClient()

    monkeypatch.setattr(
        "app.main.open_wazuh_client",
        fake_open_wazuh_client,
    )


def count_evidence(session, tenant_id):
    return session.scalar(
        select(func.count())
        .select_from(EvidenceRecord)
        .where(EvidenceRecord.tenant_id == tenant_id)
    )


def count_ingestion_audits(session, tenant_id):
    return session.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action == "wazuh.alerts_ingested",
        )
    )


def test_ingestion_imports_alert_and_records_audit_atomically(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Ingestion Success Tenant"
    )
    integration = create_integration(session, tenant.id)
    install_fake_wazuh_client(monkeypatch, [make_alert()])

    response = client.post(
        f"/v1/integrations/wazuh/{integration.id}/ingest",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["integration_id"] == str(integration.id)
    assert data["requested"] == 50
    assert data["fetched"] == 1
    assert data["imported"] == 1
    assert data["duplicates"] == 0
    assert data["total_available"] == 1
    assert data["offset"] == 0

    evidence = session.scalar(
        select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant.id
        )
    )

    assert evidence is not None
    assert evidence.evidence_type == "observation"
    assert evidence.source_type == "wazuh"
    assert evidence.source_reference == (
        f"integration:{integration.id}:"
        "wazuh-alerts-4.x-2026.11.09/test-document-001"
    )
    assert evidence.trust_level == "unverified"
    assert evidence.payload["raw_document"]["_id"] == "test-document-001"
    assert evidence.payload["event_time"] == (
        "2026-11-09T12:30:00+00:00"
    )

    audit = session.scalar(
        select(AuditLog).where(
            AuditLog.tenant_id == tenant.id,
            AuditLog.action == "wazuh.alerts_ingested",
        )
    )

    assert audit is not None
    assert audit.actor_type == "api_key"
    assert audit.actor_id is not None
    assert audit.resource_id == integration.id
    assert audit.details["imported"] == 1
    assert audit.details["duplicates"] == 0

    chain = verify_audit_chain(
        session.scalars(
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant.id)
            .order_by(AuditLog.sequence_number.asc())
        ).all()
    )
    assert chain["valid"] is True

    verify_response = client.get(
        f"/v1/evidence/{evidence.id}/verify",
        headers={"X-API-Key": api_key},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["integrity_valid"] is True


def test_repeated_ingestion_counts_duplicate_without_duplicate_evidence(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Ingestion Duplicate Tenant"
    )
    integration = create_integration(session, tenant.id)
    install_fake_wazuh_client(monkeypatch, [make_alert()])

    path = f"/v1/integrations/wazuh/{integration.id}/ingest"
    headers = {"X-API-Key": api_key}

    first = client.post(path, headers=headers)
    second = client.post(path, headers=headers)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text

    assert first.json()["imported"] == 1
    assert first.json()["duplicates"] == 0
    assert second.json()["imported"] == 0
    assert second.json()["duplicates"] == 1

    assert count_evidence(session, tenant.id) == 1
    assert count_ingestion_audits(session, tenant.id) == 2

    events = session.scalars(
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant.id)
        .order_by(AuditLog.sequence_number.asc())
    ).all()
    assert verify_audit_chain(events)["valid"] is True


def test_tenant_cannot_ingest_from_another_tenants_integration(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant_a, key_a = create_tenant_and_key(
        session, "Wazuh Ingestion Tenant A"
    )
    tenant_b, _ = create_tenant_and_key(
        session, "Wazuh Ingestion Tenant B"
    )
    integration_b = create_integration(session, tenant_b.id)

    def unexpected_client(_integration):
        raise AssertionError("Wazuh client must not be opened")

    monkeypatch.setattr(
        "app.main.open_wazuh_client",
        unexpected_client,
    )

    response = client.post(
        f"/v1/integrations/wazuh/{integration_b.id}/ingest",
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "wazuh_integration_not_found"
    assert count_evidence(session, tenant_a.id) == 0
    assert count_evidence(session, tenant_b.id) == 0


def test_inactive_integration_is_rejected_without_opening_client(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Inactive Integration Tenant"
    )
    integration = create_integration(
        session, tenant.id, active=False
    )

    def unexpected_client(_integration):
        raise AssertionError("Inactive integration must not be opened")

    monkeypatch.setattr(
        "app.main.open_wazuh_client",
        unexpected_client,
    )

    response = client.post(
        f"/v1/integrations/wazuh/{integration.id}/ingest",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "wazuh_integration_inactive"
    assert count_evidence(session, tenant.id) == 0
    assert count_ingestion_audits(session, tenant.id) == 0


def test_indexer_failure_returns_safe_error_without_writing(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Indexer Failure Tenant"
    )
    integration = create_integration(session, tenant.id)

    install_fake_wazuh_client(
        monkeypatch,
        error=WazuhIndexerError(
            "private-password-must-not-appear"
        ),
    )

    response = client.post(
        f"/v1/integrations/wazuh/{integration.id}/ingest",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 502
    assert response.json()["detail"] == "wazuh_indexer_request_failed"
    assert "private-password" not in response.text
    assert count_evidence(session, tenant.id) == 0
    assert count_ingestion_audits(session, tenant.id) == 0


def test_malformed_alert_rolls_back_prior_inserts_and_audit(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Ingestion Rollback Tenant"
    )
    integration = create_integration(session, tenant.id)

    valid_alert = make_alert("valid-first-alert")
    invalid_alert = make_alert("invalid-second-alert")
    invalid_alert["event_time"] = datetime(2026, 11, 9, 12, 30)

    install_fake_wazuh_client(
        monkeypatch,
        [valid_alert, invalid_alert],
    )

    with pytest.raises(ValueError, match="invalid_wazuh_event_time"):
        client.post(
            f"/v1/integrations/wazuh/{integration.id}/ingest",
            headers={"X-API-Key": api_key},
        )

    assert count_evidence(session, tenant.id) == 0
    assert count_ingestion_audits(session, tenant.id) == 0


def test_indexer_response_larger_than_requested_page_is_rejected(
    ingestion_api_context,
    monkeypatch,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Oversized Response Tenant"
    )
    integration = create_integration(session, tenant.id)
    install_fake_wazuh_client(
        monkeypatch,
        [make_alert("first"), make_alert("second")],
    )

    response = client.post(
        f"/v1/integrations/wazuh/{integration.id}/ingest?limit=1",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 502
    assert response.json()["detail"] == "wazuh_indexer_invalid_response"
    assert count_evidence(session, tenant.id) == 0
    assert count_ingestion_audits(session, tenant.id) == 0


@pytest.mark.parametrize(
    "query",
    ["?limit=0", "?limit=101", "?offset=-1", "?offset=9901"],
)
def test_ingestion_rejects_out_of_range_pagination(
    ingestion_api_context,
    query,
):
    client, session = ingestion_api_context
    tenant, api_key = create_tenant_and_key(
        session, "Wazuh Pagination Validation Tenant"
    )
    integration = create_integration(session, tenant.id)

    response = client.post(
        f"/v1/integrations/wazuh/{integration.id}/ingest{query}",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 422
    assert count_evidence(session, tenant.id) == 0
    assert count_ingestion_audits(session, tenant.id) == 0


def test_ingestion_requires_authentication(ingestion_api_context):
    client, _ = ingestion_api_context

    response = client.post(
        f"/v1/integrations/wazuh/{uuid4()}/ingest"
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_api_key"
