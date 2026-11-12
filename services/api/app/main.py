import hmac
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.audit.integrity import record_audit_event, verify_audit_chain
from app.iam.auth import (
    AuthenticatedPrincipal,
    get_current_principal,
    get_current_tenant,
)
from app.db import engine, get_db
from app.evidence.hashing import calculate_evidence_hash
from app.integrations.wazuh.client import WazuhIndexerError
from app.integrations.wazuh.sync import WazuhSyncError, sync_wazuh
from app.integrations.wazuh.status import read_sync_status
from app.integrations.wazuh.service import WazuhIntegrationError, open_wazuh_client
from app.database.models import AuditLog, EvidenceLineage, EvidenceRecord, Tenant, WazuhIntegration
from app.schemas import (
    AuditIntegrityResponse,
    AuditLogListResponse,
    AuditLogResponse,
    EvidenceCreate,
    EvidenceIntegrityResponse,
    EvidenceLineageCreate,
    EvidenceLineageListResponse,
    EvidenceLineageResponse,
    EvidenceListResponse,
    EvidenceResponse,
    TenantResponse,
    WazuhIntegrationListResponse,
    WazuhIntegrationResponse,
    WazuhIngestionResponse,
    WazuhSyncResponse,
    WazuhSyncStatusResponse,
)

# Preserve app.main handler imports while routers own the extracted globals.
from app.api.v1.tenant import (
    get_tenant,
    router as tenant_router,
)
from app.api.v1.evidence import (
    ingest_evidence,
    list_evidence,
    get_evidence,
    verify_evidence_integrity,
    create_evidence_lineage,
    list_evidence_lineage,
    router as evidence_router,
)
from app.api.v1.audit import (
    list_audit_logs,
    verify_audit_logs,
    router as audit_router,
)
from app.api.v1.wazuh import (
    synchronize_wazuh,
    get_wazuh_sync_status,
    list_wazuh_integrations,
    get_wazuh_integration,
    router as wazuh_router,
    sync_router as wazuh_sync_router,
)

app = FastAPI(
    title="AI SOC Team API",
    description="Foundation API for a local-first AI Security Operations Center.",
    version="0.1.0",
)


app.include_router(wazuh_sync_router)


@app.get("/health", tags=["System"])
def health():
    """Check whether the API process is responding."""
    return {
        "status": "ok",
        "service": "ai-soc-api",
    }


@app.get("/ready", tags=["System"])
def readiness():
    """Check whether the API can communicate with PostgreSQL."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="database_unavailable",
        ) from exc

    return {
        "status": "ready",
        "database": "available",
    }


app.include_router(tenant_router)


app.include_router(evidence_router)


app.include_router(audit_router)


app.include_router(wazuh_router)


@app.post(
    "/v1/integrations/wazuh/{integration_id}/ingest",
    response_model=WazuhIngestionResponse,
    tags=["Wazuh Integrations"],
)
def ingest_wazuh_alerts(
    integration_id: UUID,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=9900),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """
    Import one bounded page of alerts from a tenant-owned Wazuh integration.

    Evidence records and the hash-chained audit event are committed atomically.
    """

    integration = db.scalar(
        select(WazuhIntegration).where(
            WazuhIntegration.id == integration_id,
            WazuhIntegration.tenant_id == principal.tenant_id,
        )
    )

    if integration is None:
        raise HTTPException(
            status_code=404,
            detail="wazuh_integration_not_found",
        )

    if not integration.is_active:
        raise HTTPException(
            status_code=409,
            detail="wazuh_integration_inactive",
        )

    # Fetch alerts before writing anything to the evidence database.
    try:
        with open_wazuh_client(integration) as client:
            result = client.search_alerts(
                size=limit,
                offset=offset,
            )

    except WazuhIntegrationError as exc:
        raise HTTPException(
            status_code=503,
            detail="wazuh_integration_configuration_unavailable",
        ) from exc

    except WazuhIndexerError as exc:
        raise HTTPException(
            status_code=502,
            detail="wazuh_indexer_request_failed",
        ) from exc

    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="wazuh_integration_configuration_unavailable",
        ) from exc

    items = result.get("items") if isinstance(result, dict) else None
    total_available = result.get("total") if isinstance(result, dict) else None

    if (
        not isinstance(items, list)
        or not isinstance(total_available, int)
        or isinstance(total_available, bool)
        or total_available < 0
        or len(items) > limit
    ):
        raise HTTPException(
            status_code=502,
            detail="wazuh_indexer_invalid_response",
        )

    imported = 0
    duplicates = 0

    try:
        for alert in items:
            if not isinstance(alert, dict):
                raise ValueError("invalid_wazuh_alert")

            original_reference = alert.get("source_reference")

            if (
                not isinstance(original_reference, str)
                or not original_reference.strip()
            ):
                raise ValueError("invalid_wazuh_source_reference")

            source_reference = (
                f"integration:{integration.id}:{original_reference}"
            )

            if len(source_reference) > 500:
                raise ValueError("wazuh_source_reference_too_long")

            event_time = alert.get("event_time")

            if event_time is not None:
                if (
                    not isinstance(event_time, datetime)
                    or event_time.tzinfo is None
                    or event_time.utcoffset() is None
                ):
                    raise ValueError("invalid_wazuh_event_time")

            # JSONB cannot store Python datetime objects. Preserve the
            # normalized timestamp as ISO-8601 while storing event_time
            # separately in the evidence envelope.
            payload = dict(alert)
            payload["event_time"] = (
                event_time.isoformat()
                if event_time is not None
                else None
            )

            collector_name = "wazuh-indexer"
            collector_version = "0.1.0"
            trust_level = "unverified"

            content_sha256 = calculate_evidence_hash(
                evidence_type="observation",
                source_type="wazuh",
                source_reference=source_reference,
                collector_name=collector_name,
                collector_version=collector_version,
                trust_level=trust_level,
                event_time=event_time,
                payload=payload,
            )

            statement = (
                pg_insert(EvidenceRecord)
                .values(
                    tenant_id=principal.tenant_id,
                    evidence_type="observation",
                    source_type="wazuh",
                    source_reference=source_reference,
                    event_time=event_time,
                    collector_name=collector_name,
                    collector_version=collector_version,
                    trust_level=trust_level,
                    schema_version="1.0",
                    payload=payload,
                    content_sha256=content_sha256,
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        EvidenceRecord.tenant_id,
                        EvidenceRecord.source_reference,
                    ],
                    index_where=(
                        EvidenceRecord.source_type == "wazuh"
                    ),
                )
                .returning(EvidenceRecord.id)
            )

            inserted_id = db.execute(statement).scalar_one_or_none()

            if inserted_id is None:
                duplicates += 1
            else:
                imported += 1

        record_audit_event(
            db,
            tenant_id=principal.tenant_id,
            actor_type="api_key",
            actor_id=principal.api_key_id,
            action="wazuh.alerts_ingested",
            resource_type="wazuh_integration",
            resource_id=integration.id,
            details={
                "integration_id": str(integration.id),
                "requested_limit": limit,
                "offset": offset,
                "fetched": len(items),
                "imported": imported,
                "duplicates": duplicates,
                "total_available": total_available,
            },
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return WazuhIngestionResponse(
        integration_id=integration.id,
        requested=limit,
        fetched=len(items),
        imported=imported,
        duplicates=duplicates,
        total_available=total_available,
        offset=offset,
    )
