"""Existing audit HTTP handlers; domain behavior remains unchanged."""

from fastapi import APIRouter
from datetime import datetime, timezone
from uuid import UUID
from fastapi import Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.audit.integrity import verify_audit_chain
from app.iam.auth import get_current_tenant
from app.db import get_db
from app.database.models import AuditLog
from app.schemas import AuditIntegrityResponse, AuditLogListResponse


router = APIRouter()


@router.get(
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



@router.get(
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
