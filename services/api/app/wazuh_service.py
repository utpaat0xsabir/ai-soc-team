"""Deprecated compatibility import; use app.integrations.wazuh.service. Retire separately."""

from app.integrations.wazuh.service import (
    Path as Path,
    WazuhIndexerClient as WazuhIndexerClient,
    WazuhIntegration as WazuhIntegration,
    WazuhIntegrationError as WazuhIntegrationError,
    contextmanager as contextmanager,
    open_wazuh_client as open_wazuh_client,
    settings as settings,
)
