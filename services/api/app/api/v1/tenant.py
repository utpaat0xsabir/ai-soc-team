"""Existing tenant HTTP handlers; domain behavior remains unchanged."""

from fastapi import APIRouter
from uuid import UUID
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.iam.auth import get_current_tenant
from app.db import get_db
from app.database.models import Tenant
from app.schemas import TenantResponse


router = APIRouter()


@router.get(
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
