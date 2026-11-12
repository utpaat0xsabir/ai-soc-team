"""Deprecated compatibility import; use app.iam.auth. Retire separately."""

from app.iam.auth import (
    AuthenticatedPrincipal as AuthenticatedPrincipal,
    Depends as Depends,
    HTTPException as HTTPException,
    Header as Header,
    Session as Session,
    TenantAPIKey as TenantAPIKey,
    UUID as UUID,
    _validated_key_hash as _validated_key_hash,
    dataclass as dataclass,
    get_current_principal as get_current_principal,
    get_current_tenant as get_current_tenant,
    get_db as get_db,
    hash_api_key as hash_api_key,
    select as select,
)
