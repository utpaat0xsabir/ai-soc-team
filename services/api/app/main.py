
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth import get_current_tenant
from app.db import engine, get_db
from app.evidence import calculate_evidence_hash
from app.models import EvidenceRecord, Tenant
from app.schemas import EvidenceCreate, EvidenceResponse, TenantResponse


app = FastAPI(
    title="AI SOC Team API",
    description="Foundation API for a local-first AI Security Operations Center.",
    version="0.1.0",
)


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


@app.get("/v1/tenant", response_model=TenantResponse, tags=["Tenant"])
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


@app.post(
    "/v1/evidence",
    response_model=EvidenceResponse,
    status_code=201,
    tags=["Evidence"],
)
def ingest_evidence(
    data: EvidenceCreate,
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Store evidence under the authenticated tenant with server-generated provenance."""

    # Server-controlled metadata prevents clients from self-assigning trust.
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
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()
        raise

    return record
