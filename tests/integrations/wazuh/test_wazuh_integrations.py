from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import engine
from app.database.models import Tenant, WazuhIntegration


@pytest.fixture
def integration_session():
    connection = engine.connect()
    transaction = connection.begin()

    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
    )

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


def create_tenant(session, name):
    tenant = Tenant(
        name=name,
        slug=f"wazuh-test-{uuid4().hex}",
    )

    session.add(tenant)
    session.flush()

    return tenant


def create_integration(
    session,
    *,
    tenant_id,
    name="Primary Wazuh",
    base_url="https://127.0.0.1:9200",
):
    integration = WazuhIntegration(
        tenant_id=tenant_id,
        name=name,
        base_url=base_url,
        username="ai_soc_ingest",
        credential_reference="env:WAZUH_INDEXER_PASSWORD",
        ca_certificate_path="/etc/ai-soc/certs/wazuh-root-ca.pem",
        is_active=True,
    )

    session.add(integration)
    session.flush()

    return integration


def test_integration_belongs_to_owning_tenant(integration_session):
    tenant = create_tenant(
        integration_session,
        "Wazuh Owner Tenant",
    )

    integration = create_integration(
        integration_session,
        tenant_id=tenant.id,
    )

    stored = integration_session.get(
        WazuhIntegration,
        integration.id,
    )

    assert stored is not None
    assert stored.tenant_id == tenant.id
    assert stored.name == "Primary Wazuh"


def test_tenant_query_returns_only_its_integrations(integration_session):
    tenant_a = create_tenant(integration_session, "Wazuh Tenant A")
    tenant_b = create_tenant(integration_session, "Wazuh Tenant B")

    integration_a = create_integration(
        integration_session,
        tenant_id=tenant_a.id,
    )

    create_integration(
        integration_session,
        tenant_id=tenant_b.id,
    )

    tenant_a_integrations = integration_session.scalars(
        select(WazuhIntegration).where(
            WazuhIntegration.tenant_id == tenant_a.id
        )
    ).all()

    assert len(tenant_a_integrations) == 1
    assert tenant_a_integrations[0].id == integration_a.id
    assert tenant_a_integrations[0].tenant_id == tenant_a.id


def test_same_integration_name_allowed_for_different_tenants(
    integration_session,
):
    tenant_a = create_tenant(integration_session, "Wazuh Tenant A")
    tenant_b = create_tenant(integration_session, "Wazuh Tenant B")

    integration_a = create_integration(
        integration_session,
        tenant_id=tenant_a.id,
        name="Production Wazuh",
    )

    integration_b = create_integration(
        integration_session,
        tenant_id=tenant_b.id,
        name="Production Wazuh",
    )

    assert integration_a.id != integration_b.id
    assert integration_a.tenant_id != integration_b.tenant_id


def test_duplicate_integration_name_rejected_within_tenant(
    integration_session,
):
    tenant = create_tenant(
        integration_session,
        "Duplicate Integration Tenant",
    )

    create_integration(
        integration_session,
        tenant_id=tenant.id,
        name="Production Wazuh",
    )

    duplicate = WazuhIntegration(
        tenant_id=tenant.id,
        name="Production Wazuh",
        base_url="https://127.0.0.1:9201",
        username="another_user",
        credential_reference="env:ANOTHER_PASSWORD",
        ca_certificate_path="/etc/ai-soc/certs/wazuh-root-ca.pem",
        is_active=True,
    )

    integration_session.add(duplicate)

    with pytest.raises(IntegrityError):
        integration_session.flush()

    integration_session.rollback()


def test_http_url_rejected_by_database(integration_session):
    tenant = create_tenant(
        integration_session,
        "Invalid URL Tenant",
    )

    integration = WazuhIntegration(
        tenant_id=tenant.id,
        name="Insecure Wazuh",
        base_url="http://127.0.0.1:9200",
        username="ai_soc_ingest",
        credential_reference="env:WAZUH_INDEXER_PASSWORD",
        ca_certificate_path="/etc/ai-soc/certs/wazuh-root-ca.pem",
        is_active=True,
    )

    integration_session.add(integration)

    with pytest.raises(IntegrityError):
        integration_session.flush()

    integration_session.rollback()


def test_nonexistent_tenant_rejected_by_database(integration_session):
    integration = WazuhIntegration(
        tenant_id=uuid4(),
        name="Orphan Integration",
        base_url="https://127.0.0.1:9200",
        username="ai_soc_ingest",
        credential_reference="env:WAZUH_INDEXER_PASSWORD",
        ca_certificate_path="/etc/ai-soc/certs/wazuh-root-ca.pem",
        is_active=True,
    )

    integration_session.add(integration)

    with pytest.raises(IntegrityError):
        integration_session.flush()

    integration_session.rollback()
