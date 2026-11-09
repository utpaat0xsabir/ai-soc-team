from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth import get_current_tenant
from app.db import engine, get_db
from app.models import Tenant
from app.schemas import TenantResponse

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
