"""Existing evidence HTTP handlers; domain behavior remains unchanged."""

from fastapi import APIRouter
import hmac
from datetime import datetime, timezone
from uuid import UUID
from fastapi import Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from app.audit.integrity import record_audit_event
from app.iam.auth import AuthenticatedPrincipal, get_current_principal, get_current_tenant
from app.db import get_db
from app.evidence.hashing import calculate_evidence_hash
from app.database.models import EvidenceLineage, EvidenceRecord
from app.schemas import EvidenceCreate, EvidenceIntegrityResponse, EvidenceLineageCreate, EvidenceLineageListResponse, EvidenceLineageResponse, EvidenceListResponse, EvidenceResponse


router = APIRouter()


@router.post(
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



@router.get(
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



@router.get(
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



@router.get(
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



@router.post(
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



@router.get(
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
