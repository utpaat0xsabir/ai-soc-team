import hmac
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.audit import record_audit_event, verify_audit_chain
from app.auth import (
    AuthenticatedPrincipal,
    get_current_principal,
    get_current_tenant,
)
from app.db import engine, get_db
from app.evidence import calculate_evidence_hash
from app.wazuh import WazuhIndexerError
from app.wazuh_sync import WazuhSyncError, sync_wazuh
from app.wazuh_status import read_sync_status
from app.wazuh_service import (
    WazuhIntegrationError,
    open_wazuh_client,
)
from app.models import (
    AuditLog,
    EvidenceLineage,
    EvidenceRecord,
    Tenant,
    WazuhIntegration,
)
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

app = FastAPI(
    title="AI SOC Team API",
    description="Foundation API for a local-first AI Security Operations Center.",
    version="0.1.0",
)


@app.post('/v1/integrations/wazuh/{integration_id}/sync',
          response_model=WazuhSyncResponse, tags=['Wazuh Integrations'])
def synchronize_wazuh(
    integration_id: UUID,
    limit: int = Query(default=50, ge=1, le=100),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    try:
        return sync_wazuh(db, principal, integration_id, page_size=limit)
    except WazuhSyncError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from None


@app.get('/v1/integrations/wazuh/{integration_id}/sync/status',
         response_model=WazuhSyncStatusResponse, tags=['Wazuh Integrations'])
def get_wazuh_sync_status(
    integration_id: UUID,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    try:
        result = read_sync_status(db, principal.tenant_id, integration_id)
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail='wazuh_sync_status_unavailable') from None
    if result is None:
        raise HTTPException(status_code=404, detail='wazuh_integration_not_found')
    return result


# ============================================================
# SYSTEM ENDPOINTS
# ============================================================

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


# ============================================================
# TENANT ENDPOINTS
# ============================================================

@app.get(
    "/v1/tenant",
    response_model=TenantResponse,
    tags=["Tenant"],
)
def get_tenant(
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Return the tenant associated with the authenticated API key."""

    statement = select(Tenant).where(Tenant.id == tenant_id)
    tenant = db.scalar(statement)

    if tenant is None:
        raise HTTPException(
            status_code=404,
            detail="tenant_not_found",
        )

    return tenant


# ============================================================
# EVIDENCE INGESTION
# ============================================================

@app.post(
    "/v1/evidence",
    response_model=EvidenceResponse,
    status_code=201,
    tags=["Evidence"],
)
def ingest_evidence(
    data: EvidenceCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Store evidence and its audit event in one transaction."""

    tenant_id = principal.tenant_id

    collector_name = "api-ingestion"
    collector_version = "0.1.0"
    trust_level = "unverified"
    schema_version = "1.0"

    try:
        content_sha256 = calculate_evidence_hash(
            evidence_type=data.evidence_type,
            source_type=data.source_type,
            source_reference=data.source_reference,
            collector_name=collector_name,
            collector_version=collector_version,
            trust_level=trust_level,
            event_time=data.event_time,
            payload=data.payload,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="invalid_evidence_payload",
        ) from exc

    record = EvidenceRecord(
        tenant_id=tenant_id,
        evidence_type=data.evidence_type,
        source_type=data.source_type,
        source_reference=data.source_reference,
        event_time=data.event_time,
        collector_name=collector_name,
        collector_version=collector_version,
        trust_level=trust_level,
        schema_version=schema_version,
        payload=data.payload,
        content_sha256=content_sha256,
    )

    try:
        db.add(record)

        record_audit_event(
            db,
            tenant_id=principal.tenant_id,
            actor_type="api_key",
            actor_id=principal.api_key_id,
            action="evidence.ingested",
            resource_type="evidence",
            resource_id=record.id,
            details={
                "evidence_type": record.evidence_type,
                "source_type": record.source_type,
            },
        )

        db.commit()
        db.refresh(record)

    except Exception:
        db.rollback()
        raise

    return record


# ============================================================
# EVIDENCE RETRIEVAL
# ============================================================

@app.get(
    "/v1/evidence",
    response_model=EvidenceListResponse,
    tags=["Evidence"],
)
def list_evidence(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """List evidence belonging only to the authenticated tenant."""

    tenant_filter = EvidenceRecord.tenant_id == tenant_id

    total = db.scalar(
        select(func.count())
        .select_from(EvidenceRecord)
        .where(tenant_filter)
    ) or 0

    statement = (
        select(EvidenceRecord)
        .where(tenant_filter)
        .order_by(
            EvidenceRecord.collected_at.desc(),
            EvidenceRecord.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    )

    records = db.scalars(statement).all()

    return EvidenceListResponse(
        items=records,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/v1/evidence/{evidence_id}",
    response_model=EvidenceResponse,
    tags=["Evidence"],
)
def get_evidence(
    evidence_id: UUID,
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Retrieve one evidence record belonging to the authenticated tenant."""

    statement = select(EvidenceRecord).where(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.tenant_id == tenant_id,
    )

    record = db.scalar(statement)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="evidence_not_found",
        )

    return record


# ============================================================
# EVIDENCE INTEGRITY VERIFICATION
# ============================================================

@app.get(
    "/v1/evidence/{evidence_id}/verify",
    response_model=EvidenceIntegrityResponse,
    tags=["Evidence"],
)
def verify_evidence_integrity(
    evidence_id: UUID,
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Verify the stored evidence against its SHA-256 hash."""

    statement = select(EvidenceRecord).where(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.tenant_id == tenant_id,
    )

    record = db.scalar(statement)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="evidence_not_found",
        )

    try:
        calculated_sha256 = calculate_evidence_hash(
            evidence_type=record.evidence_type,
            source_type=record.source_type,
            source_reference=record.source_reference,
            collector_name=record.collector_name,
            collector_version=record.collector_version,
            trust_level=record.trust_level,
            event_time=record.event_time,
            payload=record.payload,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail="evidence_integrity_check_failed",
        ) from exc

    integrity_valid = hmac.compare_digest(
        record.content_sha256,
        calculated_sha256,
    )

    return EvidenceIntegrityResponse(
        evidence_id=record.id,
        integrity_valid=integrity_valid,
        stored_sha256=record.content_sha256,
        calculated_sha256=calculated_sha256,
        verified_at=datetime.now(timezone.utc),
    )


# ============================================================
# EVIDENCE LINEAGE CREATION
# ============================================================

@app.post(
    "/v1/evidence/{parent_evidence_id}/lineage",
    response_model=EvidenceLineageResponse,
    status_code=201,
    tags=["Evidence Lineage"],
)
def create_evidence_lineage(
    parent_evidence_id: UUID,
    data: EvidenceLineageCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Create a relationship and its audit event atomically."""

    tenant_id = principal.tenant_id

    if parent_evidence_id == data.child_evidence_id:
        raise HTTPException(
            status_code=422,
            detail="evidence_cannot_reference_itself",
        )

    evidence_ids = {
        parent_evidence_id,
        data.child_evidence_id,
    }

    statement = select(EvidenceRecord.id).where(
        EvidenceRecord.tenant_id == tenant_id,
        EvidenceRecord.id.in_(evidence_ids),
    )

    existing_ids = set(db.scalars(statement).all())

    if existing_ids != evidence_ids:
        raise HTTPException(
            status_code=404,
            detail="evidence_not_found",
        )

    existing_lineage = db.get(
        EvidenceLineage,
        (
            tenant_id,
            parent_evidence_id,
            data.child_evidence_id,
            data.relationship_type,
        ),
    )

    if existing_lineage is not None:
        raise HTTPException(
            status_code=409,
            detail="evidence_lineage_already_exists",
        )

    lineage = EvidenceLineage(
        tenant_id=tenant_id,
        parent_evidence_id=parent_evidence_id,
        child_evidence_id=data.child_evidence_id,
        relationship_type=data.relationship_type,
    )

    try:
        db.add(lineage)

        record_audit_event(
            db,
            tenant_id=principal.tenant_id,
            actor_type="api_key",
            actor_id=principal.api_key_id,
            action="evidence.lineage_created",
            resource_type="evidence_lineage",
            resource_id=None,
            details={
                "parent_evidence_id": str(parent_evidence_id),
                "child_evidence_id": str(data.child_evidence_id),
                "relationship_type": data.relationship_type,
            },
        )

        db.commit()
        db.refresh(lineage)

    except Exception:
        db.rollback()
        raise

    return lineage


# ============================================================
# EVIDENCE LINEAGE RETRIEVAL
# ============================================================

@app.get(
    "/v1/evidence/{evidence_id}/lineage",
    response_model=EvidenceLineageListResponse,
    tags=["Evidence Lineage"],
)
def list_evidence_lineage(
    evidence_id: UUID,
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Retrieve incoming and outgoing lineage for tenant-owned evidence."""

    evidence_statement = select(EvidenceRecord.id).where(
        EvidenceRecord.id == evidence_id,
        EvidenceRecord.tenant_id == tenant_id,
    )

    evidence_exists = db.scalar(evidence_statement)

    if evidence_exists is None:
        raise HTTPException(
            status_code=404,
            detail="evidence_not_found",
        )

    lineage_filter = (
        EvidenceLineage.tenant_id == tenant_id,
        or_(
            EvidenceLineage.parent_evidence_id == evidence_id,
            EvidenceLineage.child_evidence_id == evidence_id,
        ),
    )

    total = db.scalar(
        select(func.count())
        .select_from(EvidenceLineage)
        .where(*lineage_filter)
    ) or 0

    statement = (
        select(EvidenceLineage)
        .where(*lineage_filter)
        .order_by(
            EvidenceLineage.created_at.desc(),
            EvidenceLineage.parent_evidence_id,
            EvidenceLineage.child_evidence_id,
        )
    )

    records = db.scalars(statement).all()

    return EvidenceLineageListResponse(
        items=records,
        total=total,
    )


# ============================================================
# AUDIT LOG RETRIEVAL
# ============================================================

@app.get(
    "/v1/audit-logs",
    response_model=AuditLogListResponse,
    tags=["Audit"],
)
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
    ),
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Retrieve audit events belonging only to the authenticated tenant."""

    tenant_filter = AuditLog.tenant_id == tenant_id

    filters = [tenant_filter]

    if action is not None:
        normalized_action = action.strip()

        if not normalized_action:
            raise HTTPException(
                status_code=422,
                detail="invalid_audit_action_filter",
            )

        filters.append(AuditLog.action == normalized_action)

    total = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(*filters)
    ) or 0

    statement = (
        select(AuditLog)
        .where(*filters)
        .order_by(
            AuditLog.created_at.desc(),
            AuditLog.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    )

    records = db.scalars(statement).all()

    return AuditLogListResponse(
        items=records,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/v1/audit-logs/verify",
    response_model=AuditIntegrityResponse,
    tags=["Audit"],
)
def verify_audit_logs(
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Verify the authenticated tenant's complete audit hash chain."""

    statement = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.sequence_number.asc())
    )

    events = db.scalars(statement).all()

    result = verify_audit_chain(events)

    return AuditIntegrityResponse(
        **result,
        verified_at=datetime.now(timezone.utc),
    )


# ============================================================
# WAZUH INTEGRATION RETRIEVAL
# ============================================================

@app.get(
    "/v1/integrations/wazuh",
    response_model=WazuhIntegrationListResponse,
    tags=["Wazuh Integrations"],
)
def list_wazuh_integrations(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """List Wazuh integrations belonging to the authenticated tenant."""

    tenant_filter = (
        WazuhIntegration.tenant_id == principal.tenant_id
    )

    total = db.scalar(
        select(func.count())
        .select_from(WazuhIntegration)
        .where(tenant_filter)
    ) or 0

    statement = (
        select(WazuhIntegration)
        .where(tenant_filter)
        .order_by(WazuhIntegration.created_at.desc())
    )

    integrations = db.scalars(statement).all()

    return WazuhIntegrationListResponse(
        items=integrations,
        total=total,
    )


@app.get(
    "/v1/integrations/wazuh/{integration_id}",
    response_model=WazuhIntegrationResponse,
    tags=["Wazuh Integrations"],
)
def get_wazuh_integration(
    integration_id: UUID,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    """Retrieve one integration belonging to the authenticated tenant."""

    statement = select(WazuhIntegration).where(
        WazuhIntegration.id == integration_id,
        WazuhIntegration.tenant_id == principal.tenant_id,
    )

    integration = db.scalar(statement)

    if integration is None:
        raise HTTPException(
            status_code=404,
            detail="wazuh_integration_not_found",
        )

    return integration


# ============================================================
# WAZUH ALERT INGESTION
# ============================================================

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
