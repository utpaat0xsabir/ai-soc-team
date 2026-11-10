
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.db import engine, get_db
from app.evidence import calculate_evidence_hash
from app.main import app
from app.models import (
    EvidenceLineage,
    EvidenceRecord,
    Tenant,
    TenantAPIKey,
)


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


def evidence_payload(source_reference=None):
    return {
        "evidence_type": "observation",
        "source_type": "wazuh",
        "source_reference": source_reference or f"agent-001/{uuid4()}",
        "event_time": "2026-11-09T08:00:00Z",
        "payload": {
            "rule_id": "752",
            "description": "Example security event",
        },
    }


# ============================================================
# EVIDENCE INGESTION
# ============================================================


def test_ingestion_saves_evidence_with_server_metadata(api_context):
    client, session = api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Evidence Integration Tenant",
    )

    response = client.post(
        "/v1/evidence",
        json=evidence_payload(
            source_reference="agent-001/alert-123",
        ),
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 201, response.text

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

    assert response.status_code == 422, response.text


def test_ingestion_rejects_missing_api_key(api_context):
    client, _ = api_context

    response = client.post(
        "/v1/evidence",
        json=evidence_payload(),
    )

    assert response.status_code == 401, response.text


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

    assert response_a.status_code == 201, response_a.text
    assert response_b.status_code == 201, response_b.text

    record_a = session.get(
        EvidenceRecord,
        response_a.json()["id"],
    )

    record_b = session.get(
        EvidenceRecord,
        response_b.json()["id"],
    )

    assert record_a is not None
    assert record_b is not None

    assert record_a.tenant_id == tenant_a.id
    assert record_b.tenant_id == tenant_b.id
    assert record_a.tenant_id != record_b.tenant_id


# ============================================================
# EVIDENCE RETRIEVAL
# ============================================================


def test_list_evidence_is_tenant_scoped(api_context):
    client, session = api_context

    _, key_a = create_tenant_and_key(
        session,
        "List Tenant A",
    )

    _, key_b = create_tenant_and_key(
        session,
        "List Tenant B",
    )

    response_a1 = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_a},
    )

    response_a2 = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_a},
    )

    response_b = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_b},
    )

    assert response_a1.status_code == 201, response_a1.text
    assert response_a2.status_code == 201, response_a2.text
    assert response_b.status_code == 201, response_b.text

    response = client.get(
        "/v1/evidence",
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total"] == 2
    assert data["limit"] == 50
    assert data["offset"] == 0

    returned_ids = {
        item["id"] for item in data["items"]
    }

    expected_ids = {
        response_a1.json()["id"],
        response_a2.json()["id"],
    }

    assert returned_ids == expected_ids
    assert response_b.json()["id"] not in returned_ids


def test_list_evidence_pagination(api_context):
    client, session = api_context

    _, api_key = create_tenant_and_key(
        session,
        "Pagination Tenant",
    )

    created_ids = set()

    for _ in range(3):
        response = client.post(
            "/v1/evidence",
            json=evidence_payload(),
            headers={"X-API-Key": api_key},
        )

        assert response.status_code == 201, response.text
        created_ids.add(response.json()["id"])

    first_page = client.get(
        "/v1/evidence?limit=2&offset=0",
        headers={"X-API-Key": api_key},
    )

    second_page = client.get(
        "/v1/evidence?limit=2&offset=2",
        headers={"X-API-Key": api_key},
    )

    assert first_page.status_code == 200, first_page.text
    assert second_page.status_code == 200, second_page.text

    first_data = first_page.json()
    second_data = second_page.json()

    assert first_data["total"] == 3
    assert len(first_data["items"]) == 2

    assert second_data["total"] == 3
    assert len(second_data["items"]) == 1

    first_ids = {
        item["id"] for item in first_data["items"]
    }

    second_ids = {
        item["id"] for item in second_data["items"]
    }

    assert first_ids.isdisjoint(second_ids)
    assert first_ids | second_ids == created_ids


def test_get_evidence_enforces_tenant_isolation(api_context):
    client, session = api_context

    _, key_a = create_tenant_and_key(
        session,
        "Detail Tenant A",
    )

    _, key_b = create_tenant_and_key(
        session,
        "Detail Tenant B",
    )

    created = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_a},
    )

    assert created.status_code == 201, created.text

    evidence_id = created.json()["id"]

    own_response = client.get(
        f"/v1/evidence/{evidence_id}",
        headers={"X-API-Key": key_a},
    )

    foreign_response = client.get(
        f"/v1/evidence/{evidence_id}",
        headers={"X-API-Key": key_b},
    )

    missing_response = client.get(
        f"/v1/evidence/{uuid4()}",
        headers={"X-API-Key": key_a},
    )

    assert own_response.status_code == 200, own_response.text
    assert own_response.json()["id"] == evidence_id

    assert foreign_response.status_code == 404
    assert foreign_response.json()["detail"] == "evidence_not_found"

    assert missing_response.status_code == 404


# ============================================================
# EVIDENCE INTEGRITY VERIFICATION
# ============================================================


def test_evidence_integrity_verification_succeeds(api_context):
    client, session = api_context

    _, api_key = create_tenant_and_key(
        session,
        "Integrity Tenant",
    )

    created = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    assert created.status_code == 201, created.text

    evidence_id = created.json()["id"]

    response = client.get(
        f"/v1/evidence/{evidence_id}/verify",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["evidence_id"] == evidence_id
    assert data["integrity_valid"] is True
    assert data["stored_sha256"] == data["calculated_sha256"]
    assert len(data["stored_sha256"]) == 64
    assert data["verified_at"]


def test_evidence_integrity_verification_detects_tampering(api_context):
    client, session = api_context

    _, api_key = create_tenant_and_key(
        session,
        "Tamper Test Tenant",
    )

    created = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    assert created.status_code == 201, created.text

    evidence_id = created.json()["id"]

    record = session.get(EvidenceRecord, evidence_id)

    assert record is not None

    # Simulate unauthorized modification of the stored hash.
    record.content_sha256 = "0" * 64
    session.flush()

    response = client.get(
        f"/v1/evidence/{evidence_id}/verify",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["integrity_valid"] is False
    assert data["stored_sha256"] == "0" * 64
    assert data["stored_sha256"] != data["calculated_sha256"]


# ============================================================
# EVIDENCE LINEAGE CREATION
# ============================================================


def test_create_evidence_lineage(api_context):
    client, session = api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Lineage Creation Tenant",
    )

    parent = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    child = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    assert parent.status_code == 201, parent.text
    assert child.status_code == 201, child.text

    parent_id = parent.json()["id"]
    child_id = child.json()["id"]

    response = client.post(
        f"/v1/evidence/{parent_id}/lineage",
        json={
            "child_evidence_id": child_id,
            "relationship_type": "derived_from",
        },
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 201, response.text

    data = response.json()

    assert data["parent_evidence_id"] == parent_id
    assert data["child_evidence_id"] == child_id
    assert data["relationship_type"] == "derived_from"
    assert data["created_at"]

    lineage = session.get(
        EvidenceLineage,
        (
            tenant.id,
            parent_id,
            child_id,
            "derived_from",
        ),
    )

    assert lineage is not None


def test_create_evidence_lineage_rejects_duplicate(api_context):
    client, session = api_context

    _, api_key = create_tenant_and_key(
        session,
        "Duplicate Lineage Tenant",
    )

    parent = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    child = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    assert parent.status_code == 201, parent.text
    assert child.status_code == 201, child.text

    parent_id = parent.json()["id"]
    child_id = child.json()["id"]

    payload = {
        "child_evidence_id": child_id,
        "relationship_type": "supports",
    }

    headers = {"X-API-Key": api_key}

    first = client.post(
        f"/v1/evidence/{parent_id}/lineage",
        json=payload,
        headers=headers,
    )

    duplicate = client.post(
        f"/v1/evidence/{parent_id}/lineage",
        json=payload,
        headers=headers,
    )

    assert first.status_code == 201, first.text
    assert duplicate.status_code == 409, duplicate.text

    assert duplicate.json()["detail"] == (
        "evidence_lineage_already_exists"
    )


def test_create_evidence_lineage_rejects_self_reference(api_context):
    client, session = api_context

    _, api_key = create_tenant_and_key(
        session,
        "Self Lineage Tenant",
    )

    evidence = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": api_key},
    )

    assert evidence.status_code == 201, evidence.text

    evidence_id = evidence.json()["id"]

    response = client.post(
        f"/v1/evidence/{evidence_id}/lineage",
        json={
            "child_evidence_id": evidence_id,
            "relationship_type": "references",
        },
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 422, response.text

    assert response.json()["detail"] == (
        "evidence_cannot_reference_itself"
    )


def test_create_evidence_lineage_rejects_cross_tenant_link(api_context):
    client, session = api_context

    _, key_a = create_tenant_and_key(
        session,
        "Lineage Tenant A",
    )

    _, key_b = create_tenant_and_key(
        session,
        "Lineage Tenant B",
    )

    parent = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_a},
    )

    child = client.post(
        "/v1/evidence",
        json=evidence_payload(),
        headers={"X-API-Key": key_b},
    )

    assert parent.status_code == 201, parent.text
    assert child.status_code == 201, child.text

    response = client.post(
        f"/v1/evidence/{parent.json()['id']}/lineage",
        json={
            "child_evidence_id": child.json()["id"],
            "relationship_type": "derived_from",
        },
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "evidence_not_found"


# ============================================================
# EVIDENCE LINEAGE RETRIEVAL
# ============================================================


def test_list_evidence_lineage_returns_both_directions(api_context):
    client, session = api_context

    _, api_key = create_tenant_and_key(
        session,
        "Lineage Retrieval Tenant",
    )

    headers = {"X-API-Key": api_key}

    evidence_ids = []

    for _ in range(3):
        response = client.post(
            "/v1/evidence",
            json=evidence_payload(),
            headers=headers,
        )

        assert response.status_code == 201, response.text
        evidence_ids.append(response.json()["id"])

    first_id, second_id, third_id = evidence_ids

    outgoing = client.post(
        f"/v1/evidence/{first_id}/lineage",
        json={
            "child_evidence_id": second_id,
            "relationship_type": "supports",
        },
        headers=headers,
    )

    incoming = client.post(
        f"/v1/evidence/{third_id}/lineage",
        json={
            "child_evidence_id": first_id,
            "relationship_type": "derived_from",
        },
        headers=headers,
    )

    assert outgoing.status_code == 201, outgoing.text
    assert incoming.status_code == 201, incoming.text

    response = client.get(
        f"/v1/evidence/{first_id}/lineage",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total"] == 2
    assert len(data["items"]) == 2

    relationships = {
        (
            item["parent_evidence_id"],
            item["child_evidence_id"],
            item["relationship_type"],
        )
        for item in data["items"]
    }

    assert relationships == {
        (first_id, second_id, "supports"),
        (third_id, first_id, "derived_from"),
    }
