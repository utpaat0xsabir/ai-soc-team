"""IAM-03C offline PostgreSQL query foundation; existing schema cannot authorize.

No engine/config/session factory. Only trusted injected fake sessions are tested.
No complete IAM snapshot or operational policy allowance can be produced here.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import field_validator
from sqlalchemy import select
from app.database.models import Tenant, TenantAPIKey
from app.iam import contracts as iam
from app.iam import policy as policy
from app.iam import authority_provider as providers
from app.gateway.contracts import TrustedContext

SCHEMA_GAPS = ('tenant_status','principal_state','role_assignments','team_memberships','team_status',
    'resource_classification','resource_assignment','issuer_authority','approval_state','policy_version','revocation_state')
ErrorCode = Literal['SESSION_UNAVAILABLE','IDENTITY_MISMATCH','INVALID_REQUEST','TRANSACTION_UNVERIFIED',
    'RECORDS_INVALID','READ_FAILED','CLEANUP_FAILED','SCHEMA_INCOMPLETE']


class AuthorityReadError(ValueError):
    """Public errors contain only stable categories, never driver errors or rows."""
    def __init__(self,code: ErrorCode):
        self.code=code
        super().__init__(code)


class TransactionObservation(iam.IAMContract):
    transaction_id: UUID
    read_epoch: UUID
    source_ref: iam.TenantReference
    evaluated_at: datetime
    observed_at: datetime
    read_only: Literal[True]
    isolation: Literal['REPEATABLE READ']
    _times = field_validator('evaluated_at','observed_at')(iam._utc)


class InjectedReadSession(Protocol):
    """Dedicated already-open read transaction; observations are not source proofs."""
    def observe_transaction(self) -> TransactionObservation: ...
    def execute(self,statement): ...
    def rollback(self) -> None: ...


@dataclass(frozen=True)
class PostgresAuthorityProvider:
    """AuthorityProvider v1.0 fail-closed skeleton; intentionally not bridge-eligible.

    Session/identity/context/source are protected composition inputs. A bare
    SQLAlchemy Session lacks the required transaction-observation interface.
    """
    session: InjectedReadSession | None
    authenticated: object
    context: TrustedContext
    source_ref: iam.TenantReference

    def is_current(self,epoch: UUID) -> bool:
        # No authoritative IAM revocation generation exists in the current schema.
        return False

    def read(self,authenticated,request: policy.AuthorizationRequest,*,at: datetime) -> providers.ProviderSnapshot:
        if self.session is None:
            raise AuthorityReadError('SESSION_UNAVAILABLE')
        try:
            context=iam._checked(self.context,TrustedContext)
            source=iam._checked(self.source_ref,iam.TenantReference)
            if (authenticated is None or authenticated is not self.authenticated
                    or type(authenticated.tenant_id) is not UUID or type(authenticated.api_key_id) is not UUID
                    or authenticated.tenant_id!=context.tenant_id or authenticated.api_key_id!=context.principal_id
                    or source.tenant_id!=context.tenant_id):
                raise ValueError()
        except Exception:
            raise AuthorityReadError('IDENTITY_MISMATCH') from None
        try:
            request=iam._checked(request,policy.AuthorizationRequest); at=iam._utc(at)
        except Exception:
            raise AuthorityReadError('INVALID_REQUEST') from None
        if (request.resource_ref.tenant_id!=context.tenant_id or request.executor_ref.tenant_id!=context.tenant_id
                or request.executor_ref.reference_id!=context.principal_id):
            raise AuthorityReadError('IDENTITY_MISMATCH')

        code='TRANSACTION_UNVERIFIED'
        try:
            def observation():
                value=iam._checked(self.session.observe_transaction(),TransactionObservation)
                if (value.source_ref!=source or value.evaluated_at!=at
                        or not 0<=(at-value.observed_at).total_seconds()<=15):
                    raise ValueError()
                return value
            before=observation()
            # Explicit projected columns avoid credentials and accidental ORM lazy reads.
            statements=(select(Tenant.id).where(Tenant.id==context.tenant_id).limit(2),
                select(TenantAPIKey.id,TenantAPIKey.tenant_id,TenantAPIKey.revoked_at)
                    .where(TenantAPIKey.tenant_id==context.tenant_id,TenantAPIKey.id==context.principal_id).limit(2))
            expected_fields=({'id'},{'id','tenant_id','revoked_at'})
            records=[]
            for statement,fields in zip(statements,expected_fields):
                code='READ_FAILED'
                rows=self.session.execute(statement).mappings().fetchmany(2)
                code='RECORDS_INVALID'
                if type(rows) not in (list,tuple) or len(rows)!=1 or set(rows[0])!=fields:
                    raise ValueError()
                row=rows[0]
                if any(type(row[name]) is not UUID for name in fields if name!='revoked_at'):
                    raise ValueError()
                records.append(row)
            code='IDENTITY_MISMATCH'
            tenant,key=records
            if (tenant['id']!=context.tenant_id or key['id']!=context.principal_id
                    or key['tenant_id']!=context.tenant_id or key['revoked_at'] is not None):
                raise ValueError()
            code='TRANSACTION_UNVERIFIED'
            after=observation()
            if after!=before: raise ValueError()
            # Existing ID/key rows are insufficient: never synthesize roles, active
            # tenant status, classification, policy, issuer trust or revocation state.
            code='SCHEMA_INCOMPLETE'
        except Exception:
            pass
        finally:
            try:
                # The injected session must own only this dedicated read transaction.
                self.session.rollback()
            except Exception:
                code='CLEANUP_FAILED'
        raise AuthorityReadError(code) from None
