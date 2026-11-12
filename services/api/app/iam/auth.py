from dataclasses import dataclass
from uuid import UUID

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.iam.api_keys import hash_api_key
from app.db import get_db
from app.database.models import TenantAPIKey


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Identity of the API key authenticated for this request."""

    tenant_id: UUID
    api_key_id: UUID


def _validated_key_hash(x_api_key: str | None) -> str:
    """Validate an API key and return its hash."""

    if not x_api_key or len(x_api_key) > 128:
        raise HTTPException(
            status_code=401,
            detail="invalid_api_key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    try:
        return hash_api_key(x_api_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail="invalid_api_key",
            headers={"WWW-Authenticate": "ApiKey"},
        ) from exc


def get_current_principal(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> AuthenticatedPrincipal:
    """Authenticate an API key and return its tenant and key identity."""

    key_hash = _validated_key_hash(x_api_key)

    statement = select(TenantAPIKey).where(
        TenantAPIKey.key_hash == key_hash,
        TenantAPIKey.revoked_at.is_(None),
    )

    api_key = db.scalar(statement)

    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="invalid_api_key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return AuthenticatedPrincipal(
        tenant_id=api_key.tenant_id,
        api_key_id=api_key.id,
    )


def get_current_tenant(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> UUID:
    """Authenticate an API key and return its associated tenant ID."""

    key_hash = _validated_key_hash(x_api_key)

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
