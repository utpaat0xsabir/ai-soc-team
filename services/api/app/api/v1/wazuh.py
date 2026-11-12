"""Existing wazuh HTTP handlers; domain behavior remains unchanged."""

from fastapi import APIRouter
from uuid import UUID
from fastapi import Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from app.iam.auth import AuthenticatedPrincipal, get_current_principal
from app.db import get_db
from app.integrations.wazuh.sync import WazuhSyncError, sync_wazuh
from app.integrations.wazuh.status import read_sync_status
from app.database.models import WazuhIntegration
from app.schemas import WazuhIntegrationListResponse, WazuhIntegrationResponse, WazuhSyncResponse, WazuhSyncStatusResponse


router = APIRouter()
sync_router = APIRouter()


@sync_router.post('/v1/integrations/wazuh/{integration_id}/sync',
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



@sync_router.get('/v1/integrations/wazuh/{integration_id}/sync/status',
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



@router.get(
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



@router.get(
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
