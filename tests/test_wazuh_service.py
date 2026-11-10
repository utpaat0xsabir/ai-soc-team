from types import SimpleNamespace

import pytest

from app.config import settings
from app.wazuh_service import (
    WazuhIntegrationError,
    open_wazuh_client,
)


@pytest.fixture
def configured_integration(monkeypatch, tmp_path):
    ca_file = tmp_path / "root-ca.pem"
    ca_file.write_text("test certificate placeholder")

    monkeypatch.setattr(
        settings,
        "wazuh_indexer_url",
        "https://127.0.0.1:9200",
    )
    monkeypatch.setattr(
        settings,
        "wazuh_indexer_username",
        "ai_soc_ingest",
    )
    monkeypatch.setattr(
        settings,
        "wazuh_indexer_password",
        "test-password",
    )
    monkeypatch.setattr(
        settings,
        "wazuh_indexer_ca",
        str(ca_file),
    )
    monkeypatch.setattr(
        settings,
        "wazuh_indexer_timeout",
        15.0,
    )

    integration = SimpleNamespace(
        is_active=True,
        credential_reference="env:WAZUH_INDEXER_PASSWORD",
        base_url="https://127.0.0.1:9200",
        username="ai_soc_ingest",
        ca_certificate_path=str(ca_file),
    )

    return integration


def test_rejects_inactive_integration(configured_integration):
    configured_integration.is_active = False

    with pytest.raises(
        WazuhIntegrationError,
        match="wazuh_integration_inactive",
    ):
        with open_wazuh_client(configured_integration):
            pass


def test_rejects_unsupported_credential_reference(
    configured_integration,
):
    configured_integration.credential_reference = (
        "env:ARBITRARY_SECRET"
    )

    with pytest.raises(
        WazuhIntegrationError,
        match="wazuh_credential_reference_not_allowed",
    ):
        with open_wazuh_client(configured_integration):
            pass


def test_rejects_missing_connection_configuration(
    configured_integration,
    monkeypatch,
):
    monkeypatch.setattr(
        settings,
        "wazuh_indexer_password",
        None,
    )

    with pytest.raises(
        WazuhIntegrationError,
        match="wazuh_connection_configuration_missing",
    ):
        with open_wazuh_client(configured_integration):
            pass


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_url", "https://another-indexer:9200"),
        ("username", "another-user"),
    ],
)
def test_rejects_connection_configuration_mismatch(
    configured_integration,
    field,
    value,
):
    setattr(configured_integration, field, value)

    with pytest.raises(
        WazuhIntegrationError,
        match="wazuh_integration_configuration_mismatch",
    ):
        with open_wazuh_client(configured_integration):
            pass


def test_rejects_ca_certificate_mismatch(
    configured_integration,
    tmp_path,
):
    configured_integration.ca_certificate_path = str(
        tmp_path / "another-ca.pem"
    )

    with pytest.raises(
        WazuhIntegrationError,
        match="wazuh_integration_configuration_mismatch",
    ):
        with open_wazuh_client(configured_integration):
            pass


def test_opens_and_closes_wazuh_client(
    configured_integration,
    monkeypatch,
):
    created = {}

    class FakeWazuhClient:
        def __init__(self, **kwargs):
            created["kwargs"] = kwargs
            created["closed"] = False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            created["closed"] = True

    monkeypatch.setattr(
        "app.wazuh_service.WazuhIndexerClient",
        FakeWazuhClient,
    )

    with open_wazuh_client(configured_integration) as client:
        assert isinstance(client, FakeWazuhClient)
        assert created["closed"] is False

    assert created["closed"] is True
    assert created["kwargs"]["username"] == "ai_soc_ingest"
    assert created["kwargs"]["password"] == "test-password"
    assert created["kwargs"]["max_page_size"] == 100
    assert created["kwargs"]["base_url"] == (
        "https://127.0.0.1:9200"
    )
