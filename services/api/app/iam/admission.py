"""IAM-03A synthetic admission only; no operational authentication or enforcement."""
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from app.iam import contracts as iam
from app.iam import policy as policy
from app.gateway.contracts import TrustedContext

RecordType = Literal['SNAPSHOT','ROLE_ASSIGNMENT','TEAM_MEMBERSHIP','TEAM_SCOPE','APPROVAL','VERIFIER']
Reason = Literal['ADMITTED','UNVERIFIED_ORIGIN','INVALID_INPUT','TENANT_VIOLATION','IDENTITY_INVALID',
    'ISSUER_UNTRUSTED','STALE_SNAPSHOT','REVOCATION_UNVERIFIED','REQUEST_MISMATCH',
    'RECORDS_INVALID','POLICY_FAILURE']


class IssuerAuthority(iam.Validity):
    issuer_ref: iam.TenantReference
    source_ref: iam.TenantReference
    record_types: Annotated[tuple[RecordType,...],Field(min_length=1,max_length=6)]
    _types = field_validator('record_types')(iam._unique)

    @model_validator(mode='after')
    def scope(self):
        iam._tenant(self.tenant_id,self.issuer_ref,self.source_ref)
        if (self.valid_until-self.valid_from).total_seconds()>300:
            raise ValueError('issuer_window_limit')
        return self


class RevocationState(iam.TenantBound):
    state_id: UUID
    observed_at: datetime
    revoked_refs: iam.References
    _time = field_validator('observed_at')(iam._utc)
    _refs = field_validator('revoked_refs')(iam._refs)

    @model_validator(mode='after')
    def scope(self):
        iam._tenant(self.tenant_id,*self.revoked_refs)
        return self


class APIKeyState(iam.Validity):
    api_key_id: UUID
    principal_ref: iam.TenantReference
    active: bool

    @model_validator(mode='after')
    def mapping(self):
        iam._tenant(self.tenant_id,self.principal_ref)
        if self.principal_ref.reference_id!=self.api_key_id:
            raise ValueError('invalid_api_key_mapping')
        return self


class AuthoritySnapshot(iam.Validity):
    snapshot_id: UUID
    source_ref: iam.TenantReference
    issuer_ref: iam.TenantReference
    verifier_ref: iam.TenantReference
    evaluated_at: datetime
    request_sha256: iam.Digest
    operation_sha256: iam.Digest
    snapshot: iam.IAMSnapshot
    api_key_state: APIKeyState
    policy: policy.AuthorizationPolicy
    issuance_evidence: Annotated[tuple[iam.IssuanceEvidence,...],Field(max_length=64)]
    revocations: RevocationState
    approval: iam.ApprovalRecord | None = None
    classification: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    _time = field_validator('evaluated_at')(iam._utc)

    @model_validator(mode='after')
    def scope(self):
        iam._tenant(self.tenant_id,self.source_ref,self.issuer_ref,self.verifier_ref,self.revocations,self.approval,self.api_key_state)
        if self.snapshot.tenant.tenant_id!=self.tenant_id:
            raise ValueError('snapshot_tenant_mismatch')
        if (self.valid_until-self.valid_from).total_seconds()>60:
            raise ValueError('snapshot_window_limit')
        object.__setattr__(self,'issuance_evidence',iam._unique(self.issuance_evidence,key=lambda r:r.record_id))
        return self


@dataclass(frozen=True)
class SyntheticOriginRegistry:
    """Out-of-band synthetic origin channel; identity registration is not a signature."""
    _records: tuple

    @classmethod
    def for_tests(cls,records):
        if type(records) is not tuple or len(records)>16:
            raise ValueError('invalid_synthetic_registry')
        return cls(records)

    def contains(self,record):
        return any(record is registered for registered in self._records)


@dataclass(frozen=True)
class SyntheticAuthority:
    """Explicitly injected test source. Never registered by application configuration."""
    _authenticated: object
    _record: AuthoritySnapshot
    _anchors: tuple
    _origins: SyntheticOriginRegistry

    @classmethod
    def for_tests(cls,authenticated,record,anchors,origins):
        if type(origins) is not SyntheticOriginRegistry or type(anchors) is not tuple or len(anchors)>32:
            raise ValueError('invalid_synthetic_authority')
        return cls(authenticated,record,anchors,origins)


class AdmittedSnapshot(iam.Validity):
    principal_ref: iam.TenantReference
    authentication_ref: iam.AuthenticationReference
    issuer_ref: iam.TenantReference
    verifier_ref: iam.TenantReference
    source_ref: iam.TenantReference
    snapshot_id: UUID
    snapshot_sha256: iam.Digest
    authority_snapshot_sha256: iam.Digest
    policy_version: Literal['1.0']
    policy_sha256: iam.Digest
    request_sha256: iam.Digest
    operation_sha256: iam.Digest
    correlation_id: UUID
    evaluated_at: datetime
    assignment_refs: iam.References
    membership_refs: iam.References
    scope_refs: iam.References
    revocation_ref: iam.TenantReference
    approval_refs: iam.References
    resource: iam.Resource
    action: iam.Permission
    admission: Literal['ADMITTED'] = 'ADMITTED'
    classification: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    _time = field_validator('evaluated_at')(iam._utc)
    _refs = field_validator('assignment_refs','membership_refs','scope_refs','approval_refs')(iam._refs)

    @model_validator(mode='after')
    def scope(self):
        iam._tenant(self.tenant_id,self.principal_ref,self.authentication_ref,self.issuer_ref,self.verifier_ref,
            self.source_ref,self.revocation_ref,self.resource,*self.assignment_refs,*self.membership_refs,
            *self.scope_refs,*self.approval_refs)
        if not self.valid_from<=self.evaluated_at<self.valid_until:
            raise ValueError('invalid_admitted_window')
        return self


class AdmissionAudit(iam.IAMContract):
    tenant_id: UUID | None
    principal_id: UUID | None
    correlation_id: UUID | None
    resource_ref: iam.TenantReference | None
    resource_type: iam.ResourceType | None
    action: iam.Permission | None
    policy_version: policy.Version | None
    policy_sha256: iam.Digest | None
    snapshot_sha256: iam.Digest | None
    issuer_ref: iam.TenantReference | None
    verifier_ref: iam.TenantReference | None
    evaluated_at: datetime | None
    status: Literal['ADMISSION_DENIED','POLICY_DENY','POLICY_ALLOW']
    reason: Reason
    iam_decision: Literal['ALLOW','DENY'] | None


class AdmissionOutcome(iam.IAMContract):
    status: Literal['ADMISSION_DENIED','POLICY_DENY','POLICY_ALLOW']
    reason: Reason
    audit: AdmissionAudit
    admitted: AdmittedSnapshot | None = None
    policy_decision: policy.AuthorizationDecision | None = None
    classification: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'

    @model_validator(mode='after')
    def consistent(self):
        if (self.audit.status!=self.status or self.audit.reason!=self.reason
                or self.audit.iam_decision!=(None if self.policy_decision is None else self.policy_decision.outcome)):
            raise ValueError('inconsistent_admission_audit')
        if self.status=='ADMISSION_DENIED':
            if self.admitted is not None or self.policy_decision is not None or self.reason=='ADMITTED':
                raise ValueError('invalid_admission_outcome')
        else:
            if self.admitted is None or self.policy_decision is None or self.reason!='ADMITTED':
                raise ValueError('missing_admission_binding')
            a,d=self.admitted,self.policy_decision
            if ((self.status=='POLICY_ALLOW')!=(d.outcome=='ALLOW') or
                    (a.tenant_id,a.principal_ref.reference_id,a.correlation_id,a.evaluated_at,a.policy_sha256,
                     a.resource.resource_id,a.action)!=(d.tenant_id,d.principal_id,d.correlation_id,d.evaluated_at,
                     d.policy_sha256,d.resource_ref.reference_id,d.action)):
                raise ValueError('inconsistent_admission_binding')
        return self


class _Denied(Exception):
    pass


def admit(authenticated,request,*,authority,at) -> AdmissionOutcome:
    """Consume protected synthetic source records, then delegate all RBAC/ABAC to IAM-02.

    No caller-supplied records or verification flags are accepted by this entrypoint.
    The synthetic channel must never be mistaken for real-world authentication.
    """
    tenant=key=None; checked_request=None; checked_time=None; admitted=None
    def audit(status,reason,decision=None):
        req=checked_request
        return AdmissionAudit(tenant_id=tenant,principal_id=key,
            correlation_id=None if req is None else req.correlation_id,
            resource_ref=None if req is None else req.resource_ref,
            resource_type=None if req is None else req.resource_type,
            action=None if req is None or req.action not in policy.get_args(iam.Permission) else req.action,
            policy_version=None if req is None else req.policy_version,
            policy_sha256=None if admitted is None else admitted.policy_sha256,
            snapshot_sha256=None if admitted is None else admitted.snapshot_sha256,
            issuer_ref=None if admitted is None else admitted.issuer_ref,
            verifier_ref=None if admitted is None else admitted.verifier_ref,evaluated_at=checked_time,
            status=status,reason=reason,iam_decision=None if decision is None else decision.outcome)
    def deny(reason):
        return AdmissionOutcome(status='ADMISSION_DENIED',reason=reason,audit=audit('ADMISSION_DENIED',reason))
    reason='INVALID_INPUT'
    try:
        at=iam._utc(at); checked_time=at
        request=iam._checked(request,policy.AuthorizationRequest); checked_request=request
        reason='UNVERIFIED_ORIGIN'
        if (type(authority) is not SyntheticAuthority or type(authority._origins) is not SyntheticOriginRegistry
                or not authority._origins.contains(authority._record)):
            raise _Denied()
        reason='IDENTITY_INVALID'
        if authenticated is None or authenticated is not authority._authenticated:
            raise _Denied()
        candidate_tenant,candidate_key=authenticated.tenant_id,authenticated.api_key_id
        if type(candidate_tenant) is not UUID or type(candidate_key) is not UUID: raise _Denied()
        tenant,key=candidate_tenant,candidate_key
        context=TrustedContext(tenant_id=tenant,principal_id=key)
        reason='TENANT_VIOLATION'
        for value in (authority._record,request.resource_ref,request.executor_ref):
            iam._bounded(value)
            if policy._tenant_violation(tenant,value): raise _Denied()
        reason='RECORDS_INVALID'
        bundle=iam._checked(authority._record,AuthoritySnapshot)
        reason='STALE_SNAPSHOT'
        iam._current(bundle,at)
        if bundle.evaluated_at!=at or not 0<=(at-bundle.valid_from).total_seconds()<=60:
            raise _Denied()
        reason='REQUEST_MISMATCH'
        if bundle.request_sha256!=iam.contract_digest(request) or request.policy_version!=bundle.policy.policy_version:
            raise _Denied()
        reason='REVOCATION_UNVERIFIED'
        state=bundle.revocations
        if not 0<=(at-state.observed_at).total_seconds()<=15: raise _Denied()
        revoked={r.reference_id for r in state.revoked_refs}
        reason='ISSUER_UNTRUSTED'
        anchors=tuple(iam._checked(a,IssuerAuthority) for a in authority._anchors)
        keys=[(a.tenant_id,a.issuer_ref.reference_id,a.source_ref.reference_id,t) for a in anchors for t in a.record_types]
        if len(keys)!=len(set(keys)): raise _Denied()
        def issuer_allowed(reference,record_type):
            if reference.reference_id in revoked: raise _Denied()
            matches=[a for a in anchors if a.tenant_id==tenant and a.issuer_ref==reference
                and a.source_ref==bundle.source_ref and record_type in a.record_types]
            if len(matches)!=1: raise _Denied()
            iam._current(matches[0],at)
        issuer_allowed(bundle.issuer_ref,'SNAPSHOT')
        issuer_allowed(bundle.verifier_ref,'VERIFIER')
        if bundle.verifier_ref.reference_id in revoked or bundle.verifier_ref.reference_id==key:
            raise _Denied()
        for receipt in bundle.issuance_evidence:
            issuer_allowed(receipt.issuer_ref,receipt.purpose)
            if (receipt.valid_until-receipt.valid_from).total_seconds()>300: raise _Denied()
        if bundle.approval is not None: issuer_allowed(bundle.approval.provenance.issuer_ref,'APPROVAL')
        reason='IDENTITY_INVALID'
        key_state=bundle.api_key_state
        iam._current(key_state,at)
        if not key_state.active or key_state.api_key_id!=key or key_state.principal_ref.reference_id!=key:
            raise _Denied()
        actor=next(p for p in bundle.snapshot.principals if p.principal_id==key)
        iam._current(actor,at)
        if (actor.kind!='API_KEY_SERVICE' or actor.authentication.method!='API_KEY'
                or actor.authentication.reference_id!=key or key in revoked): raise _Denied()
        reason='REVOCATION_UNVERIFIED'
        relevant={p.principal_id for p in bundle.snapshot.principals}
        relevant.update(a.assignment_id for a in bundle.snapshot.assignments)
        relevant.update(m.membership_id for m in bundle.snapshot.memberships)
        relevant.update(r.record_id for r in bundle.issuance_evidence)
        relevant.update(s.scope_id for s in bundle.snapshot.scopes)
        if bundle.approval is not None: relevant.add(bundle.approval.approval_id)
        if relevant&revoked: raise _Denied()
        reason='RECORDS_INVALID'
        snapshot=iam.validate_snapshot(context,bundle.snapshot,at=at,trusted_issuance=bundle.issuance_evidence)
        resource=next(r for r in snapshot.resources if r.resource_id==request.resource_ref.reference_id
            and r.resource_type==request.resource_type)
        reason='REQUEST_MISMATCH'
        operation=iam.ProposedOperation(tenant_id=tenant,operation_id=request.operation_id,
            requester_ref=iam.TenantReference(tenant_id=tenant,reference_id=key),executor_ref=request.executor_ref,
            action=request.action,resource=resource,parameters_sha256=request.parameters_sha256)
        if iam.contract_digest(operation)!=bundle.operation_sha256: raise _Denied()
        if bundle.approval is not None:
            approver=next(p for p in snapshot.principals if p.principal_id==bundle.approval.approver.principal_id)
            iam.validate_approval(context,operation,bundle.approval,trusted_approver=approver,at=at)
            if bundle.approval.outcome!='APPROVED': raise _Denied()
        verification=policy.TrustedVerification(tenant_id=tenant,verifier_ref=bundle.verifier_ref,
            principal_sha256=iam.contract_digest(actor),authentication_sha256=iam.contract_digest(actor.authentication),
            snapshot_sha256=iam.contract_digest(snapshot),policy_sha256=iam.contract_digest(bundle.policy),
            verified_issuance_sha256=tuple(iam.contract_digest(r) for r in bundle.issuance_evidence),
            identity_authenticated=True,snapshot_authoritative=True,issuers_authenticated=True,
            issuance_authorized=True,policy_verified=True,approval_verified=bundle.approval is not None,
            approval_sha256=None if bundle.approval is None else iam.contract_digest(bundle.approval),
            valid_from=bundle.valid_from,valid_until=bundle.valid_until)
        admitted=AdmittedSnapshot(tenant_id=tenant,principal_ref=operation.requester_ref,
            authentication_ref=actor.authentication,issuer_ref=bundle.issuer_ref,verifier_ref=bundle.verifier_ref,
            source_ref=bundle.source_ref,snapshot_id=bundle.snapshot_id,snapshot_sha256=iam.contract_digest(snapshot),
            authority_snapshot_sha256=iam.contract_digest(bundle),policy_version=bundle.policy.policy_version,
            policy_sha256=iam.contract_digest(bundle.policy),request_sha256=iam.contract_digest(request),
            operation_sha256=bundle.operation_sha256,correlation_id=request.correlation_id,evaluated_at=at,
            assignment_refs=actor.role_assignment_refs,membership_refs=actor.team_membership_refs,
            scope_refs=resource.allowed_scope_refs,revocation_ref=iam.TenantReference(tenant_id=tenant,reference_id=state.state_id),
            approval_refs=() if bundle.approval is None else (iam.TenantReference(tenant_id=tenant,reference_id=bundle.approval.approval_id),),
            resource=resource,action=request.action,valid_from=bundle.valid_from,valid_until=bundle.valid_until)
        reason='POLICY_FAILURE'
        decision=policy.evaluate(context,snapshot,request,policy=bundle.policy,at=at,
            issuance_evidence=bundle.issuance_evidence,trusted_verification=verification,approval=bundle.approval)
        status='POLICY_ALLOW' if decision.outcome=='ALLOW' else 'POLICY_DENY'
        return AdmissionOutcome(status=status,reason='ADMITTED',audit=audit(status,'ADMITTED',decision),
            admitted=admitted,policy_decision=decision)
    except Exception:
        return deny(reason)
