"""IAM-01: immutable proposed IAM records and pure input-consistency checks.

No authentication, permission resolution, access decision, storage or execution.
Only application code supplies trusted context, records and issuance references.
"""
from datetime import datetime,timezone
import hashlib
import json
from typing import Annotated,Literal,get_args
from uuid import UUID

from pydantic import Field,field_validator,model_validator

from app.gateway.contracts import _Contract, TrustedContext


RoleID = Literal['org_admin','soc_manager','l1_analyst','l2_analyst','l3_threat_hunter',
    'read_only_auditor','service_integration','ai_l1_service','ai_l2_service','ai_l3_service']
Permission = Literal['alerts.read','alerts.triage','alerts.assign','evidence.metadata.read',
    'evidence.raw.read','evidence.export','evidence.lineage.read','cases.read','cases.create',
    'cases.assign','cases.investigate','cases.close','threat_intel.lookup','threat_intel.export',
    'tools.propose','tools.invoke.approved','response.propose','response.approve','response.execute',
    'models.read','models.configure','models.approve','knowledge.read','knowledge.update.propose',
    'knowledge.activate','detection_rules.read','detection_rules.update.propose','detection_rules.activate',
    'audit.read','audit.verify','users.manage','teams.manage','roles.assign','integrations.manage']
ResourceType = Literal['alert','evidence','case','threat_intel','tool','response','model','knowledge',
    'detection_rule','audit','user','team','role','integration','report','investigation_artifact']
Classification = Literal['PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED']
Identifier = Annotated[str,Field(pattern=r'^[a-z][a-z0-9_.:-]{0,95}$')]
Digest = Annotated[str,Field(pattern=r'^[0-9a-f]{64}$')]
_CATEGORIES = {'alerts':'alert','cases':'case','tools':'tool','models':'model',
    'detection_rules':'detection_rule','users':'user','teams':'team','roles':'role','integrations':'integration'}


def _resource_type(action):
    category = action.split('.')[0]
    return _CATEGORIES.get(category,category)


def _access_kind(action):
    if action=='evidence.raw.read': return 'RAW'
    if action.endswith('.export'): return 'EXPORT'
    if action.endswith('.read') or action=='audit.verify': return 'METADATA'
    return 'CONTROL'


def _utc(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('invalid_iam_time')
    return value.astimezone(timezone.utc)


def _unique(values,key=lambda item:item):
    keys = tuple(key(item) for item in values)
    if len(set(keys))!=len(keys):
        raise ValueError('duplicate_iam_reference')
    return tuple(sorted(values,key=lambda item:str(key(item))))


class IAMContract(_Contract):
    executable: Literal[False] = False


class TenantBound(IAMContract):
    tenant_id: UUID


def _tenant(tenant,*values):
    if any(value is not None and value.tenant_id!=tenant for value in values):
        raise ValueError('iam_tenant_mismatch')


class TenantReference(TenantBound):
    reference_id: UUID


References = Annotated[tuple[TenantReference,...],Field(max_length=64)]


def _refs(values):
    return _unique(values,key=lambda item:item.reference_id)


class TenantIdentity(TenantBound):
    status: Literal['ACTIVE','SUSPENDED']


class AuthenticationReference(TenantReference):
    method: Literal['SESSION','API_KEY','WORKLOAD','DELEGATION']
    origin: Literal['AUTHENTICATION_CONTROL_PLANE'] = 'AUTHENTICATION_CONTROL_PLANE'


class Validity(TenantBound):
    valid_from: datetime
    valid_until: datetime
    revoked_at: datetime | None = None
    revocation_reference: TenantReference | None = None

    _times = field_validator('valid_from','valid_until')(_utc)
    _revocation = field_validator('revoked_at')(lambda value:None if value is None else _utc(value))

    @model_validator(mode='after')
    def window(self):
        _tenant(self.tenant_id,self.revocation_reference)
        if (self.valid_from>=self.valid_until or (self.revoked_at is None)!=(self.revocation_reference is None)
                or (self.revoked_at is not None and self.revoked_at<self.valid_from)):
            raise ValueError('invalid_iam_validity')
        return self


class PrincipalIdentity(Validity):
    principal_id: UUID
    kind: Literal['HUMAN','API_KEY_SERVICE','SYSTEM_SERVICE','AI_ANALYST']
    authentication: AuthenticationReference
    status: Literal['ACTIVE','SUSPENDED','REVOKED']
    analyst_tier: Literal['L1','L2','L3'] | None = None
    role_assignment_refs: References = ()
    team_membership_refs: References = ()

    _assignments = field_validator('role_assignment_refs')(_refs)
    _memberships = field_validator('team_membership_refs')(_refs)

    @model_validator(mode='after')
    def identity(self):
        _tenant(self.tenant_id,self.authentication,*self.role_assignment_refs,*self.team_membership_refs)
        method = {'HUMAN':'SESSION','API_KEY_SERVICE':'API_KEY','SYSTEM_SERVICE':'WORKLOAD','AI_ANALYST':'DELEGATION'}
        if ((self.kind=='AI_ANALYST')!=(self.analyst_tier is not None)
                or self.authentication.method!=method[self.kind]
                or (self.status=='REVOKED')!=(self.revoked_at is not None)):
            raise ValueError('invalid_iam_principal')
        return self


class Provenance(TenantBound):
    record_id: UUID
    issuer_ref: TenantReference
    policy_reference: Identifier
    origin: Literal['TRUSTED_CONTROL_PLANE'] = 'TRUSTED_CONTROL_PLANE'

    @model_validator(mode='after')
    def ownership(self):
        _tenant(self.tenant_id,self.issuer_ref)
        return self


class Team(TenantBound):
    team_id: UUID
    purpose: Literal['SOC','INVESTIGATION','HUNTING','AUDIT','INTEGRATION']
    active: bool
    membership_refs: References

    _members = field_validator('membership_refs')(_refs)

    @model_validator(mode='after')
    def ownership(self):
        _tenant(self.tenant_id,*self.membership_refs)
        return self


class TeamMembership(Validity):
    membership_id: UUID
    principal_ref: TenantReference
    team_ref: TenantReference
    provenance: Provenance

    @model_validator(mode='after')
    def ownership(self):
        _tenant(self.tenant_id,self.principal_ref,self.team_ref,self.provenance)
        if self.principal_ref.reference_id==self.provenance.issuer_ref.reference_id:
            raise ValueError('self_issued_team_membership')
        return self


class RoleDefinition(TenantBound):
    role_id: RoleID
    proposed_only: Literal[True] = True


def role_catalog(tenant_id):
    return tuple(RoleDefinition(tenant_id=tenant_id,role_id=role) for role in sorted(get_args(RoleID)))


class PermissionDefinition(TenantBound):
    action: Permission
    resource_type: ResourceType
    access_kind: Literal['METADATA','RAW','EXPORT','CONTROL']
    proposed_only: Literal[True] = True

    @model_validator(mode='after')
    def exact_definition(self):
        if self.resource_type!=_resource_type(self.action) or self.access_kind!=_access_kind(self.action):
            raise ValueError('conflicting_permission_definition')
        return self


def permission_catalog(tenant_id):
    result = []
    for action in sorted(get_args(Permission)):
        result.append(PermissionDefinition(tenant_id=tenant_id,action=action,resource_type=_resource_type(action),access_kind=_access_kind(action)))
    return tuple(result)


class TeamScope(TenantBound):
    mode: Literal['ASSIGNED_TEAM','EXPLICIT_TEAMS','ALL_TENANT_TEAMS']
    team_refs: Annotated[References,Field(max_length=16)]
    authorization_ref: TenantReference | None = None

    _teams = field_validator('team_refs')(_refs)

    @model_validator(mode='after')
    def restrictions(self):
        _tenant(self.tenant_id,self.authorization_ref,*self.team_refs)
        if ((self.mode=='ASSIGNED_TEAM' and len(self.team_refs)!=1)
                or (self.mode=='EXPLICIT_TEAMS' and not self.team_refs)
                or (self.mode=='ALL_TENANT_TEAMS' and self.team_refs)
                or (self.mode!='ASSIGNED_TEAM' and self.authorization_ref is None)):
            raise ValueError('invalid_iam_team_scope')
        return self


class PermissionScope(TenantBound):
    scope_id: UUID
    actions: Annotated[tuple[Permission,...],Field(min_length=1,max_length=34)]
    resource_types: Annotated[tuple[ResourceType,...],Field(min_length=1,max_length=16)]
    classifications: Annotated[tuple[Classification,...],Field(min_length=1,max_length=4)]
    team_scope: TeamScope

    _sets = field_validator('actions','resource_types','classifications')(_unique)

    @model_validator(mode='after')
    def restrictions(self):
        _tenant(self.tenant_id,self.team_scope)
        if not {_resource_type(action) for action in self.actions}<=set(self.resource_types):
            raise ValueError('iam_action_resource_mismatch')
        return self


class RoleAssignment(Validity):
    assignment_id: UUID
    principal_ref: TenantReference
    role_id: RoleID
    scope: PermissionScope
    provenance: Provenance

    @model_validator(mode='after')
    def restrictions(self):
        _tenant(self.tenant_id,self.principal_ref,self.scope,self.provenance)
        if self.principal_ref.reference_id==self.provenance.issuer_ref.reference_id:
            raise ValueError('self_issued_role_assignment')
        return self


class Resource(TenantBound):
    resource_id: UUID
    resource_type: ResourceType
    classification: Classification
    owner_ref: TenantReference
    owning_team_ref: TenantReference | None = None
    assignment_reference: TenantReference | None = None
    allowed_scope_refs: Annotated[References,Field(min_length=1,max_length=32)]

    _scopes = field_validator('allowed_scope_refs')(_refs)

    @model_validator(mode='after')
    def ownership(self):
        _tenant(self.tenant_id,self.owner_ref,self.owning_team_ref,self.assignment_reference,*self.allowed_scope_refs)
        return self


class IAMSnapshot(IAMContract):
    tenant: TenantIdentity
    principals: Annotated[tuple[PrincipalIdentity,...],Field(min_length=1,max_length=64)]
    teams: Annotated[tuple[Team,...],Field(max_length=32)] = ()
    memberships: Annotated[tuple[TeamMembership,...],Field(max_length=64)] = ()
    roles: Annotated[tuple[RoleDefinition,...],Field(max_length=10)] = ()
    scopes: Annotated[tuple[PermissionScope,...],Field(max_length=32)] = ()
    assignments: Annotated[tuple[RoleAssignment,...],Field(max_length=32)] = ()
    resources: Annotated[tuple[Resource,...],Field(max_length=32)] = ()
    default_decision: Literal['DENY'] = 'DENY'

    @model_validator(mode='after')
    def records(self):
        for name,key in (('principals','principal_id'),('teams','team_id'),('memberships','membership_id'),
            ('roles','role_id'),('scopes','scope_id'),('assignments','assignment_id'),('resources','resource_id')):
            values = _unique(getattr(self,name),key=lambda item:getattr(item,key))
            _tenant(self.tenant.tenant_id,*values)
            object.__setattr__(self,name,values)
        return self


class IssuanceEvidence(Validity):
    """Independent caller assertion binding an issued record, never a grant."""
    record_id: UUID
    subject_record_id: UUID
    record_sha256: Digest
    issuer_ref: TenantReference
    purpose: Literal['ROLE_ASSIGNMENT','TEAM_MEMBERSHIP','TEAM_SCOPE']
    origin: Literal['TRUSTED_CONTROL_PLANE'] = 'TRUSTED_CONTROL_PLANE'

    @model_validator(mode='after')
    def ownership(self):
        _tenant(self.tenant_id,self.issuer_ref)
        return self


def _bounded(value):
    nodes = 0
    def visit(item,depth):
        nonlocal nodes
        nodes+=1
        if nodes>16384 or depth>20:
            raise ValueError('iam_input_limit')
        if isinstance(item,_Contract):
            if set(item.__dict__)!=set(type(item).model_fields) or item.model_extra:
                raise ValueError('unknown_iam_fields')
            for child in item.__dict__.values(): visit(child,depth+1)
        elif type(item) in (tuple,list):
            if len(item)>64: raise ValueError('iam_input_limit')
            for child in item: visit(child,depth+1)
        elif type(item) is str:
            if len(item)>1024: raise ValueError('iam_input_limit')
            item.encode('utf-8')
        elif item is not None and type(item) not in (UUID,datetime,bool,int):
            raise ValueError('invalid_iam_input')
    visit(value,0)


def canonical_bytes(contract):
    _bounded(contract)
    if not isinstance(contract,IAMContract) and type(contract) is not TrustedContext:
        raise ValueError('invalid_iam_contract')
    # Revalidate forged copies before serializers can emit rejected values in warnings.
    contract = type(contract).model_validate(contract)
    encoded = json.dumps(contract.model_dump(mode='json'),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(encoded)>65536:
        raise ValueError('iam_input_limit')
    return encoded


def contract_digest(contract):
    """Content binding only; not audit-chain hashing, authenticity or authority."""
    return hashlib.sha256(canonical_bytes(contract)).hexdigest()


def _checked(value,contract):
    if type(value) is not contract:
        raise ValueError('missing_trusted_iam_contract')
    _bounded(value)
    result = contract.model_validate(value)
    canonical_bytes(result)
    return result


def _current(value,at):
    if (not value.valid_from<=at<value.valid_until or value.revoked_at is not None
            or (isinstance(value,PrincipalIdentity) and value.status!='ACTIVE')):
        raise ValueError('stale_iam_record')


def validate_snapshot(context: TrustedContext,snapshot: IAMSnapshot,*,at: datetime,
                      trusted_issuance: tuple[IssuanceEvidence,...] = ()) -> IAMSnapshot:
    """Validate current input relationships, NOT roles, permissions or access."""
    try:
        context = _checked(context,TrustedContext); snapshot = _checked(snapshot,IAMSnapshot); at = _utc(at)
        if snapshot.tenant.tenant_id!=context.tenant_id or snapshot.tenant.status!='ACTIVE': raise ValueError()
        _bounded(trusted_issuance)
        if type(trusted_issuance) is not tuple or len(trusted_issuance)>64: raise ValueError()
        receipts = _unique(tuple(_checked(item,IssuanceEvidence) for item in trusted_issuance),key=lambda item:item.record_id)
        _tenant(context.tenant_id,*receipts)
        receipt_ids = {item.record_id:item for item in receipts}
        principals = {item.principal_id:item for item in snapshot.principals}
        teams = {item.team_id:item for item in snapshot.teams}
        memberships = {item.membership_id:item for item in snapshot.memberships}
        scopes = {item.scope_id:item for item in snapshot.scopes}
        assignments = {item.assignment_id:item for item in snapshot.assignments}
        roles = {item.role_id for item in snapshot.roles}
        _current(principals[context.principal_id],at)
        def provenance(record,issued,issued_id,purpose):
            issuer = principals[record.issuer_ref.reference_id]
            _current(issuer,at)
            if issuer.kind not in ('HUMAN','SYSTEM_SERVICE') or record.record_id not in receipt_ids:
                raise ValueError()
            evidence = receipt_ids[record.record_id]
            _current(evidence,at)
            if (evidence.issuer_ref!=record.issuer_ref or evidence.purpose!=purpose
                    or evidence.subject_record_id!=issued_id or evidence.record_sha256!=contract_digest(issued)):
                raise ValueError()
        for member in snapshot.memberships:
            _current(member,at); provenance(member.provenance,member,member.membership_id,'TEAM_MEMBERSHIP')
            owner = principals[member.principal_ref.reference_id]; team = teams[member.team_ref.reference_id]
            _current(owner,at)
            if not team.active or member.membership_id not in {r.reference_id for r in owner.team_membership_refs} or member.membership_id not in {r.reference_id for r in team.membership_refs}: raise ValueError()
        for principal in snapshot.principals:
            for reference in principal.team_membership_refs:
                if memberships[reference.reference_id].principal_ref.reference_id!=principal.principal_id: raise ValueError()
            for reference in principal.role_assignment_refs:
                if assignments[reference.reference_id].principal_ref.reference_id!=principal.principal_id: raise ValueError()
        for team in snapshot.teams:
            for reference in team.membership_refs:
                if memberships[reference.reference_id].team_ref.reference_id!=team.team_id: raise ValueError()
        for scope in snapshot.scopes:
            team_scope = scope.team_scope
            for reference in team_scope.team_refs:
                if not teams[reference.reference_id].active: raise ValueError()
            if team_scope.authorization_ref is not None:
                evidence = receipt_ids[team_scope.authorization_ref.reference_id]
                _current(evidence,at)
                issuer = principals[evidence.issuer_ref.reference_id]
                _current(issuer,at)
                if (issuer.kind not in ('HUMAN','SYSTEM_SERVICE') or evidence.purpose!='TEAM_SCOPE'
                        or evidence.subject_record_id!=scope.scope_id or evidence.record_sha256!=contract_digest(scope)):
                    raise ValueError()
        for assignment in snapshot.assignments:
            _current(assignment,at); provenance(assignment.provenance,assignment,assignment.assignment_id,'ROLE_ASSIGNMENT')
            subject = principals[assignment.principal_ref.reference_id]
            _current(subject,at)
            if (assignment.role_id not in roles or assignment.scope!=scopes[assignment.scope.scope_id]
                    or assignment.assignment_id not in {r.reference_id for r in subject.role_assignment_refs}): raise ValueError()
            if assignment.scope.team_scope.mode=='ASSIGNED_TEAM':
                member_teams = {memberships[r.reference_id].team_ref.reference_id for r in subject.team_membership_refs}
                if assignment.scope.team_scope.team_refs[0].reference_id not in member_teams: raise ValueError()
        for resource in snapshot.resources:
            if resource.owner_ref.reference_id not in principals: raise ValueError()
            if resource.assignment_reference is not None and resource.assignment_reference.reference_id not in assignments: raise ValueError()
            if resource.owning_team_ref is not None and not teams[resource.owning_team_ref.reference_id].active: raise ValueError()
            for reference in resource.allowed_scope_refs:
                scope = scopes[reference.reference_id]
                if resource.resource_type not in scope.resource_types or resource.classification not in scope.classifications: raise ValueError()
                if scope.team_scope.mode!='ALL_TENANT_TEAMS' and (resource.owning_team_ref is None
                        or resource.owning_team_ref.reference_id not in {r.reference_id for r in scope.team_scope.team_refs}):
                    raise ValueError()
        return snapshot
    except Exception:
        raise ValueError('invalid_iam_snapshot') from None


class ProposedOperation(TenantBound):
    operation_id: UUID
    requester_ref: TenantReference
    executor_ref: TenantReference
    action: Permission
    resource: Resource
    parameters_sha256: Digest

    @model_validator(mode='after')
    def binding(self):
        _tenant(self.tenant_id,self.requester_ref,self.executor_ref,self.resource)
        if _resource_type(self.action)!=self.resource.resource_type: raise ValueError('iam_action_resource_mismatch')
        return self


class ApprovalRecord(Validity):
    approval_id: UUID
    operation: ProposedOperation
    approver: PrincipalIdentity
    operation_sha256: Digest
    resource_sha256: Digest
    outcome: Literal['APPROVED','DENIED','REVOKED']
    provenance: Provenance

    @model_validator(mode='after')
    def separation(self):
        _tenant(self.tenant_id,self.operation,self.approver,self.provenance)
        if (self.approver.kind!='HUMAN' or self.approver.principal_id in (
                self.operation.requester_ref.reference_id,self.operation.executor_ref.reference_id)
                or self.provenance.issuer_ref.reference_id!=self.approver.principal_id
                or self.operation_sha256!=contract_digest(self.operation)
                or self.resource_sha256!=contract_digest(self.operation.resource)
                or (self.outcome=='REVOKED')!=(self.revoked_at is not None)):
            raise ValueError('invalid_approval_binding')
        return self


def validate_approval(context,operation,approval,*,trusted_approver,at):
    """Check record binding/separation only. Approval never grants execution."""
    try:
        context = _checked(context,TrustedContext); operation = _checked(operation,ProposedOperation)
        approval = _checked(approval,ApprovalRecord); trusted_approver = _checked(trusted_approver,PrincipalIdentity)
        at = _utc(at)
        _tenant(context.tenant_id,operation,approval,trusted_approver)
        if (context.principal_id!=operation.requester_ref.reference_id or approval.operation!=operation
                or approval.approver!=trusted_approver or approval.outcome=='REVOKED'):
            raise ValueError()
        _current(approval,at); _current(trusted_approver,at)
        return approval
    except Exception:
        raise ValueError('invalid_iam_approval') from None


class IAMAuditMetadata(TenantBound):
    actor_ref: TenantReference
    action: Permission
    resource: Resource
    team_scope: TeamScope | None = None
    roles: Annotated[tuple[RoleID,...],Field(max_length=10)]
    permissions: Annotated[tuple[Permission,...],Field(max_length=34)]
    policy_version: Literal['1.0']
    decision: Literal['ALLOW','DENY','UNVERIFIED']
    reason: Literal['NONE','TENANT_MISMATCH','EXPIRED','REVOKED','NOT_AUTHENTICATED','NO_GRANT',
        'CLASSIFICATION','TEAM_SCOPE','APPROVAL_REQUIRED','INVALID_INPUT','UNVERIFIED']
    request_correlation_id: UUID
    timestamp: datetime

    _time = field_validator('timestamp')(_utc)
    _sets = field_validator('roles','permissions')(_unique)

    @model_validator(mode='after')
    def metadata(self):
        _tenant(self.tenant_id,self.actor_ref,self.resource,self.team_scope)
        if (_resource_type(self.action)!=self.resource.resource_type
                or (self.decision=='ALLOW' and self.reason!='NONE')
                or (self.decision=='DENY' and self.reason in ('NONE','UNVERIFIED'))
                or (self.decision=='UNVERIFIED' and self.reason!='UNVERIFIED')):
            raise ValueError('invalid_iam_audit_metadata')
        return self
