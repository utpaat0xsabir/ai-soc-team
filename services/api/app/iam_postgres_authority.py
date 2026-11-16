"""Deprecated compatibility import; use app.iam.postgres_authority. Retire separately."""

from app.iam.postgres_authority import (
    AuthorityReadError as AuthorityReadError,
    ErrorCode as ErrorCode,
    InjectedReadSession as InjectedReadSession,
    Literal as Literal,
    Mapping as Mapping,
    PostgresAuthorityProvider as PostgresAuthorityProvider,
    Protocol as Protocol,
    SCHEMA_GAPS as SCHEMA_GAPS,
    Tenant as Tenant,
    TenantAPIKey as TenantAPIKey,
    TransactionObservation as TransactionObservation,
    TrustedContext as TrustedContext,
    UUID as UUID,
    dataclass as dataclass,
    datetime as datetime,
    field_validator as field_validator,
    iam as iam,
    policy as policy,
    providers as providers,
    select as select,
)
