"""IAM-03B: explicit synthetic provider registration, never operational IAM access."""
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal, Protocol, get_args
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from app.iam import contracts as iam
from app.iam import policy as policy
from app.iam import admission as admission

Component = Literal['tenant','api_key','principals','roles','memberships','resources',
    'policy','revocations','issuance','approval']


class ComponentEpoch(iam.IAMContract):
    component: Component
    epoch: UUID


class ProviderSnapshot(iam.IAMContract):
    provider_id: UUID
    read_epoch: UUID
    component_epochs: Annotated[tuple[ComponentEpoch,...],Field(min_length=10,max_length=10)]
    state: admission.AuthoritySnapshot
    classification: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'

    @model_validator(mode='after')
    def consistent_read(self):
        epochs=iam._unique(self.component_epochs,key=lambda e:e.component)
        if ({e.component for e in epochs}!=set(get_args(Component))
                or any(e.epoch!=self.read_epoch for e in epochs)):
            raise ValueError('inconsistent_provider_read')
        object.__setattr__(self,'component_epochs',epochs)
        return self


class AuthorityProvider(Protocol):
    """Version 1.0 read-only interface; implementations must provide coherent reads."""
    def read(self,authenticated,request: policy.AuthorizationRequest,*,at: datetime) -> ProviderSnapshot: ...
    def is_current(self,epoch: UUID) -> bool: ...


class ProviderAuthority(iam.Validity):
    provider_id: UUID
    source_ref: iam.TenantReference
    record_types: Annotated[tuple[admission.RecordType,...],Field(min_length=1,max_length=6)]
    _types = field_validator('record_types')(iam._unique)

    @model_validator(mode='after')
    def scope(self):
        iam._tenant(self.tenant_id,self.source_ref)
        if (self.valid_until-self.valid_from).total_seconds()>300:
            raise ValueError('provider_authority_window_limit')
        return self


@dataclass
class SyntheticProvider:
    """Explicit test double; mutable epoch/failure fixtures simulate authority changes."""
    response: ProviderSnapshot
    epochs: tuple = ()
    failure: Literal['FAILURE','TIMEOUT'] | None = None
    reads: int = 0
    epoch_checks: int = 0

    @classmethod
    def for_tests(cls,response):
        return cls(response)

    def read(self,authenticated,request,*,at):
        self.reads+=1
        if self.failure=='TIMEOUT': raise TimeoutError('synthetic_provider_timeout')
        if self.failure is not None: raise RuntimeError('synthetic_provider_failure')
        return self.response

    def is_current(self,epoch):
        current=(self.epochs[min(self.epoch_checks,len(self.epochs)-1)] if self.epochs else self.response.read_epoch)
        self.epoch_checks+=1
        return current==epoch


@dataclass(frozen=True)
class SyntheticProviderOrigins:
    """Independent source-registration fixture; metadata/digests cannot register origin."""
    provider: object
    responses: tuple

    @classmethod
    def for_tests(cls,provider,responses):
        if type(responses) is not tuple or len(responses)>16:
            raise ValueError('invalid_synthetic_provider_origins')
        return cls(provider,responses)

    def contains(self,provider,response):
        return self.provider is provider and any(response is registered for registered in self.responses)


@dataclass(frozen=True)
class ProviderRegistration:
    authority: ProviderAuthority
    provider: AuthorityProvider
    authenticated: object
    issuer_authorities: tuple


@dataclass(frozen=True)
class ProtectedAuthorityBridge:
    """Trusted test construction only. The request cannot select a provider or origins."""
    _registrations: tuple
    _origins: tuple

    @classmethod
    def for_tests(cls,registrations,origins):
        if (type(registrations) is not tuple or len(registrations)>16
                or type(origins) is not tuple or len(origins)>16):
            raise ValueError('invalid_synthetic_provider_configuration')
        return cls(registrations,origins)

    def authorize(self,authenticated,request,*,at) -> admission.AdmissionOutcome:
        tenant=principal=None; checked_request=None; checked_time=None
        reason='INVALID_INPUT'
        def denied():
            req=checked_request
            audit=admission.AdmissionAudit(tenant_id=tenant,principal_id=principal,
                correlation_id=None if req is None else req.correlation_id,
                resource_ref=None if req is None else req.resource_ref,
                resource_type=None if req is None else req.resource_type,
                action=None if req is None or req.action not in get_args(iam.Permission) else req.action,
                policy_version=None if req is None else req.policy_version,
                policy_sha256=None,snapshot_sha256=None,issuer_ref=None,verifier_ref=None,
                evaluated_at=checked_time,status='ADMISSION_DENIED',reason=reason,iam_decision=None)
            return admission.AdmissionOutcome(status='ADMISSION_DENIED',reason=reason,audit=audit)
        try:
            checked_time=iam._utc(at); checked_request=iam._checked(request,policy.AuthorizationRequest)
            reason='UNVERIFIED_ORIGIN'
            if any(type(r) is not ProviderRegistration for r in self._registrations): return denied()
            # Authenticate only an identity registered through the protected test channel.
            registrations=[r for r in self._registrations if r.authenticated is authenticated and authenticated is not None]
            if len(registrations)!=1: return denied()
            registration=registrations[0]
            candidate_tenant,candidate_principal=authenticated.tenant_id,authenticated.api_key_id
            if type(candidate_tenant) is not UUID or type(candidate_principal) is not UUID: return denied()
            tenant,principal=candidate_tenant,candidate_principal
            reason='TENANT_VIOLATION'
            for reference in (checked_request.resource_ref,checked_request.executor_ref):
                if reference.tenant_id!=tenant: return denied()
            reason='UNVERIFIED_ORIGIN'
            authorities=tuple(iam._checked(r.authority,ProviderAuthority) for r in self._registrations)
            # Complete authorization-state ownership has one provider per tenant in v1.0.
            if sum(a.tenant_id==tenant for a in authorities)!=1: return denied()
            authority=iam._checked(registration.authority,ProviderAuthority)
            iam._current(authority,checked_time)
            if authority.tenant_id!=tenant: return denied()
            provider=registration.provider
            # No live implementation is eligible in IAM-03B, even if it has these methods.
            if type(provider) is not SyntheticProvider: return denied()
            reason='RECORDS_INVALID'
            response=provider.read(authenticated,checked_request,at=checked_time)
            reason='UNVERIFIED_ORIGIN'
            origins=[o for o in self._origins if type(o) is SyntheticProviderOrigins and o.contains(provider,response)]
            if len(origins)!=1: return denied()
            response=iam._checked(response,ProviderSnapshot)
            state=response.state
            if response.provider_id!=authority.provider_id or state.source_ref!=authority.source_ref: return denied()
            needed={'SNAPSHOT','VERIFIER'}|{r.purpose for r in state.issuance_evidence}
            if state.approval is not None: needed.add('APPROVAL')
            if not needed<=set(authority.record_types): return denied()
            reason='REVOCATION_UNVERIFIED'
            if authority.provider_id in {r.reference_id for r in state.revocations.revoked_refs}: return denied()
            if provider.is_current(response.read_epoch) is not True: return denied()
            # Only the independently registered provider response can enter IAM-03A's
            # synthetic origin channel. Raw caller records never reach this adapter.
            source=admission.SyntheticAuthority.for_tests(authenticated,state,registration.issuer_authorities,
                admission.SyntheticOriginRegistry.for_tests((state,)))
            reason='POLICY_FAILURE'
            outcome=admission.admit(authenticated,checked_request,authority=source,at=checked_time)
            outcome=iam._checked(outcome,admission.AdmissionOutcome)
            reason='REVOCATION_UNVERIFIED'
            if provider.is_current(response.read_epoch) is not True: return denied()
            return outcome
        except Exception:
            return denied()
