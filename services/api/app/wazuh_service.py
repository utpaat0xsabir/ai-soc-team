from contextlib import contextmanager
from pathlib import Path

from app.config import settings
from app.models import WazuhIntegration
from app.wazuh import WazuhIndexerClient


class WazuhIntegrationError(Exception):
    """Raised when a tenant Wazuh integration cannot be used safely."""


@contextmanager
def open_wazuh_client(integration: WazuhIntegration):
    """
    Open a read-only Wazuh client for an authorized integration.

    Only the explicitly approved environment credential reference is
    supported during the initial single-customer deployment.
    """

    if not integration.is_active:
        raise WazuhIntegrationError(
            "wazuh_integration_inactive"
        )

    if integration.credential_reference != (
        "env:WAZUH_INDEXER_PASSWORD"
    ):
        raise WazuhIntegrationError(
            "wazuh_credential_reference_not_allowed"
        )

    if not all((
        settings.wazuh_indexer_url,
        settings.wazuh_indexer_username,
        settings.wazuh_indexer_password,
        settings.wazuh_indexer_ca,
    )):
        raise WazuhIntegrationError(
            "wazuh_connection_configuration_missing"
        )

    configured_url = settings.wazuh_indexer_url.rstrip("/")
    integration_url = integration.base_url.rstrip("/")

    if integration_url != configured_url:
        raise WazuhIntegrationError(
            "wazuh_integration_configuration_mismatch"
        )

    if integration.username != settings.wazuh_indexer_username:
        raise WazuhIntegrationError(
            "wazuh_integration_configuration_mismatch"
        )

    configured_ca = Path(
        settings.wazuh_indexer_ca
    ).resolve()

    integration_ca = Path(
        integration.ca_certificate_path
    ).resolve()

    if integration_ca != configured_ca:
        raise WazuhIntegrationError(
            "wazuh_integration_configuration_mismatch"
        )

    password = settings.wazuh_indexer_password

    client = WazuhIndexerClient(
        base_url=integration_url,
        username=integration.username,
        password=password,
        ca_certificate=str(configured_ca),
        timeout=settings.wazuh_indexer_timeout,
        max_page_size=100,
    )

    with client:
        yield client
