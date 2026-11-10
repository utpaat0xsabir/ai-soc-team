from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key, hash_api_key
from app.db import engine, get_db
from app.main import app
from app.models import Tenant, TenantAPIKey, WazuhIntegration


@pytest.fixture
def wazuh_api_context():
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
        slug=f"wazuh-api-test-{uuid4().hex}",
    )

    api_key = generate_api_key()

    session.add(tenant)
    session.flush()

    session.add(
        TenantAPIKey(
            tenant_id=tenant.id,
            name="wazuh-api-test",
            key_hash=hash_api_key(api_key),
        )
    )

    session.commit()
    session.refresh(tenant)

    return tenant, api_key


def create_integration(session, tenant_id, name="Production Wazuh"):
    integration = WazuhIntegration(
        tenant_id=tenant_id,
        name=name,
        base_url="https://127.0.0.1:9200",
        username="ai_soc_ingest",
        credential_reference="env:WAZUH_INDEXER_PASSWORD",
        ca_certificate_path="/etc/ai-soc/certs/wazuh-root-ca.pem",
        is_active=True,
    )

    session.add(integration)
    session.commit()
    session.refresh(integration)

    return integration


def test_list_integrations_returns_only_authenticated_tenant(
    wazuh_api_context,
):
    client, session = wazuh_api_context

    tenant_a, key_a = create_tenant_and_key(
        session,
        "Wazuh API Tenant A",
    )
    tenant_b, key_b = create_tenant_and_key(
        session,
        "Wazuh API Tenant B",
    )

    integration_a = create_integration(
        session,
        tenant_a.id,
        "Tenant A Wazuh",
    )

    create_integration(
        session,
        tenant_b.id,
        "Tenant B Wazuh",
    )

    response = client.get(
        "/v1/integrations/wazuh",
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == str(integration_a.id)
    assert data["items"][0]["name"] == "Tenant A Wazuh"


def test_tenant_cannot_retrieve_another_tenants_integration(
    wazuh_api_context,
):
    client, session = wazuh_api_context

    tenant_a, key_a = create_tenant_and_key(
        session,
        "Wazuh Detail Tenant A",
    )
    tenant_b, key_b = create_tenant_and_key(
        session,
        "Wazuh Detail Tenant B",
    )

    integration_b = create_integration(
        session,
        tenant_b.id,
        "Private Tenant B Wazuh",
    )

    response = client.get(
        f"/v1/integrations/wazuh/{integration_b.id}",
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "wazuh_integration_not_found"


def test_tenant_can_retrieve_its_own_integration(
    wazuh_api_context,
):
    client, session = wazuh_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Wazuh Own Detail Tenant",
    )

    integration = create_integration(
        session,
        tenant.id,
    )

    response = client.get(
        f"/v1/integrations/wazuh/{integration.id}",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["id"] == str(integration.id)
    assert data["name"] == "Production Wazuh"
    assert data["base_url"] == "https://127.0.0.1:9200"
    assert data["is_active"] is True


def test_integration_responses_do_not_expose_internal_credentials(
    wazuh_api_context,
):
    client, session = wazuh_api_context

    tenant, api_key = create_tenant_and_key(
        session,
        "Wazuh Credential Privacy Tenant",
    )

    integration = create_integration(
        session,
        tenant.id,
    )

    response = client.get(
        f"/v1/integrations/wazuh/{integration.id}",
        headers={"X-API-Key": api_key},
    )

    assert response.status_code == 200, response.text

    data = response.json()

    forbidden_fields = {
        "tenant_id",
        "username",
        "credential_reference",
        "ca_certificate_path",
        "password",
        "secret",
    }

    assert forbidden_fields.isdisjoint(data.keys())


@pytest.mark.parametrize(
    "path",
    [
        "/v1/integrations/wazuh",
        f"/v1/integrations/wazuh/{uuid4()}",
    ],
)
def test_integration_endpoints_reject_unauthenticated_requests(
    wazuh_api_context,
    path,
):
    client, session = wazuh_api_context

    response = client.get(path)

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_api_key"
