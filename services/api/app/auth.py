from uuid import UUID

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api_keys import hash_api_key
from app.db import get_db
from app.models import TenantAPIKey


def get_current_tenant(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> UUID:
    """Authenticate an API key and return its associated tenant ID."""

    if not x_api_key or len(x_api_key) > 128:
        raise HTTPException(
            status_code=401,
            detail="invalid_api_key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    try:
        key_hash = hash_api_key(x_api_key)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="invalid_api_key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    statement = select(TenantAPIKey.tenant_id).where(
        TenantAPIKey.key_hash == key_hash,
        TenantAPIKey.revoked_at.is_(None),
    )

    tenant_id = db.scalar(statement)

    if tenant_id is None:
        raise HTTPException(
            status_code=401,
            detail="invalid_api_key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return tenant_id
