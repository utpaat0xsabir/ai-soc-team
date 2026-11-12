import os
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select, text

from app.audit.integrity import record_audit_event
from app.core.config import settings
from app.db import SessionLocal
from app.database.models import Tenant, WazuhIntegration
from app.integrations.wazuh.client import WazuhIndexerClient, WazuhIndexerError


TENANT_SLUG = "acme-security-lab"
INTEGRATION_NAME = "Acme Production Wazuh"

# Fixed transitional reference for the first, internally provisioned tenant.
# This is not a general-purpose customer credential resolver.
CREDENTIAL_REFERENCE = "env:WAZUH_INDEXER_PASSWORD"


def validate_configuration() -> dict:
    """Validate Wazuh configuration without displaying secrets."""

    required = {
        "url": settings.wazuh_indexer_url,
        "username": settings.wazuh_indexer_username,
        "password": settings.wazuh_indexer_password,
        "ca": settings.wazuh_indexer_ca,
    }

    if not all(required.values()):
        raise RuntimeError("wazuh_configuration_incomplete")

    parsed_url = urlparse(settings.wazuh_indexer_url)

    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise RuntimeError("invalid_wazuh_indexer_url")

    ca_path = Path(settings.wazuh_indexer_ca)

    if not ca_path.is_file() or not os.access(ca_path, os.R_OK):
        raise RuntimeError("wazuh_ca_certificate_unavailable")

    return {
        "base_url": settings.wazuh_indexer_url.rstrip("/"),
        "username": settings.wazuh_indexer_username,
        "credential_reference": CREDENTIAL_REFERENCE,
        "ca_certificate_path": str(ca_path.resolve()),
    }



def verify_wazuh_connectivity(configuration: dict) -> None:
    """Verify authenticated, TLS-protected, read-only Indexer access."""

    try:
        with WazuhIndexerClient(
            base_url=configuration["base_url"],
            username=configuration["username"],
            password=settings.wazuh_indexer_password,
            ca_certificate=configuration["ca_certificate_path"],
            timeout=settings.wazuh_indexer_timeout,
            max_page_size=100,
        ) as client:
            result = client.search_alerts(size=1, offset=0)

        if not isinstance(result, dict) or not isinstance(
            result.get("items"), list
        ):
            raise RuntimeError("wazuh_connectivity_check_failed")

        print("Wazuh Indexer connectivity: verified")
        print("Authenticated read-only search: successful")
        print("Alerts retrieved for connectivity check:", len(result["items"]))

    except (WazuhIndexerError, ValueError, OSError):
        raise RuntimeError(
            "wazuh_connectivity_check_failed; no database changes made"
        ) from None


def provision() -> None:
    configuration = validate_configuration()
    verify_wazuh_connectivity(configuration)

    with SessionLocal.begin() as db:
        database_name = db.execute(
            text("SELECT current_database()")
        ).scalar_one()

        if database_name != "ai_soc":
            raise RuntimeError(
                "refusing_to_provision_outside_ai_soc"
            )

        tenant = db.scalar(
            select(Tenant).where(Tenant.slug == TENANT_SLUG)
        )

        if tenant is None:
            raise RuntimeError("acme_tenant_not_found")

        existing = db.scalar(
            select(WazuhIntegration).where(
                WazuhIntegration.tenant_id == tenant.id,
                WazuhIntegration.name == INTEGRATION_NAME,
            )
        )

        if existing is not None:
            existing_configuration = {
                "base_url": existing.base_url,
                "username": existing.username,
                "credential_reference": existing.credential_reference,
                "ca_certificate_path": existing.ca_certificate_path,
            }

            if existing_configuration != configuration:
                raise RuntimeError(
                    "existing_integration_configuration_conflict"
                )

            if not existing.is_active:
                raise RuntimeError(
                    "existing_integration_is_inactive"
                )

            integration_id = existing.id
            already_exists = True

        else:
            integration = WazuhIntegration(
                tenant_id=tenant.id,
                name=INTEGRATION_NAME,
                base_url=configuration["base_url"],
                username=configuration["username"],
                credential_reference=configuration[
                    "credential_reference"
                ],
                ca_certificate_path=configuration[
                    "ca_certificate_path"
                ],
                is_active=True,
            )

            db.add(integration)
            db.flush()

            record_audit_event(
                db,
                tenant_id=tenant.id,
                actor_type="system",
                actor_id=None,
                action="wazuh.integration_provisioned",
                resource_type="wazuh_integration",
                resource_id=integration.id,
                details={
                    "integration_name": INTEGRATION_NAME,
                    "base_url": configuration["base_url"],
                    "username": configuration["username"],
                    "credential_reference": CREDENTIAL_REFERENCE,
                },
            )

            integration_id = integration.id
            already_exists = False

    if already_exists:
        print("Wazuh integration already exists with matching settings.")
        print("No database changes were made.")
    else:
        print("Wazuh integration provisioned successfully.")
        print("Hash-chained audit event committed in the same transaction.")

    print(f"Tenant: {TENANT_SLUG}")
    print(f"Integration: {INTEGRATION_NAME}")
    print(f"Integration ID: {integration_id}")
    print("Credential reference: configured (value not displayed)")


if __name__ == "__main__":
    provision()
