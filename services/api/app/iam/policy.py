"""IAM-02: pure policy decisions over independently trusted IAM inputs.

No verifier/issuer, authentication bridge, I/O, audit writes or executable grant.
ALLOW never bypasses gateway, disclosure, consent or runtime capability checks.
"""
from datetime import datetime
from typing import Annotated,Literal,get_args
from uuid import UUID

from pydantic import Field,field_validator,model_validator

from app.iam import contracts as iam
from app.gateway.contracts import TrustedContext


PrincipalKind = Literal['HUMAN','API_KEY_SERVICE','SYSTEM_SERVICE','AI_ANALYST']
Version = Annotated[str,Field(pattern=r'^[0-9]{1,3}\.[0-9]{1,3}$')]
Reason = Literal['AUTHORIZED','TENANT_VIOLATION','IDENTITY_INVALID','UNKNOWN_ACTION','UNSUPPORTED_POLICY',
    'MISSING_POLICY','POLICY_CONFLICT','UNVERIFIED_PROVENANCE','MISSING_ROLE_MAPPING','MISSING_GRANT',
    'TEAM_MISMATCH','CLASSIFICATION_RESTRICTED','OWNERSHIP_MISMATCH','APPROVAL_REQUIRED','APPROVAL_INVALID',
    'APPROVER_NOT_AUTHORIZED','PRINCIPAL_RESTRICTED','RESOURCE_NOT_FOUND','EXECUTOR_MISMATCH','INPUT_CONFLICT']
_AI_FORBIDDEN = frozenset(('response.approve','response.execute','models.configure','models.approve',
    'users.manage','teams.manage','roles.assign','integrations.manage','knowledge.activate','detection_rules.activate'))
_HUMAN_ONLY = frozenset(('response.approve','models.configure','models.approve','users.manage','teams.manage',
    'roles.assign','integrations.manage','knowledge.activate','detection_rules.activate'))
# Reviewed explicit data: no inheritance, name-derived privilege or wildcards.
_ROLE_DATA = (
    ('org_admin',('HUMAN',),None,('users.manage','teams.manage','roles.assign','integrations.manage',
        'models.read','models.configure','models.approve','audit.read','audit.verify','knowledge.read','detection_rules.read')),
    ('soc_manager',('HUMAN',),None,('alerts.read','alerts.triage','alerts.assign','evidence.metadata.read',
        'evidence.raw.read','evidence.export','evidence.lineage.read','cases.read','cases.create','cases.assign',
        'cases.investigate','cases.close','threat_intel.lookup','threat_intel.export','tools.propose','tools.invoke.approved',
        'response.propose','response.approve','models.read','knowledge.read','knowledge.update.propose','knowledge.activate',
        'detection_rules.read','detection_rules.update.propose','detection_rules.activate','audit.read','audit.verify')),
    ('l1_analyst',('HUMAN',),None,('alerts.read','alerts.triage','evidence.metadata.read','evidence.lineage.read',
        'cases.read','cases.create','tools.propose','knowledge.read','detection_rules.read')),
    ('l2_analyst',('HUMAN',),None,('alerts.read','alerts.triage','evidence.metadata.read','evidence.raw.read',
        'evidence.lineage.read','cases.read','cases.create','cases.investigate','threat_intel.lookup','tools.propose',
        'response.propose','knowledge.read','detection_rules.read')),
    ('l3_threat_hunter',('HUMAN',),None,('alerts.read','evidence.metadata.read','evidence.raw.read','evidence.lineage.read',
        'cases.read','cases.investigate','threat_intel.lookup','tools.propose','response.propose','knowledge.read',
        'knowledge.update.propose','detection_rules.read','detection_rules.update.propose')),
    ('read_only_auditor',('HUMAN',),None,('audit.read','audit.verify','evidence.metadata.read','evidence.lineage.read',
        'cases.read','alerts.read','detection_rules.read','models.read')),
    ('service_integration',('API_KEY_SERVICE','SYSTEM_SERVICE'),None,('alerts.read','evidence.metadata.read',
        'tools.invoke.approved','response.execute')),
    ('ai_l1_service',('AI_ANALYST',),'L1',('alerts.read','alerts.triage','evidence.metadata.read','evidence.lineage.read',
        'cases.read','cases.create','tools.propose','knowledge.read','detection_rules.read')),
    ('ai_l2_service',('AI_ANALYST',),'L2',('alerts.read','evidence.metadata.read','evidence.raw.read','evidence.lineage.read',
        'cases.read','cases.investigate','tools.propose','knowledge.read','detection_rules.read')),
    ('ai_l3_service',('AI_ANALYST',),'L3',('alerts.read','evidence.metadata.read','evidence.raw.read','evidence.lineage.read',
        'cases.read','cases.investigate','threat_intel.lookup','tools.propose','knowledge.read','knowledge.update.propose',
        'detection_rules.read','detection_rules.update.propose')),
)
_APPROVAL_ACTIONS = {
    'evidence.export':'evidence.export','threat_intel.export':'threat_intel.export',
    'tools.invoke.approved':'tools.invoke.approved','response.execute':'response.approve',
    'models.configure':'models.approve','knowledge.activate':'knowledge.activate',
    'detection_rules.activate':'detection_rules.activate','roles.assign':'roles.assign','integrations.manage':'integrations.manage'}


class RoleRule(iam.IAMContract):
    role_id: iam.RoleID
    kinds: Annotated[tuple[PrincipalKind,...],Field(min_length=1,max_length=4)]
    required_tier: Literal['L1','L2','L3'] | None = None
    actions: Annotated[tuple[iam.Permission,...],Field(max_length=34)]
    _sets = field_validator('kinds','actions')(iam._unique)


class ActionRule(iam.IAMContract):
    action: iam.Permission
    classifications: Annotated[tuple[iam.Classification,...],Field(min_length=1,max_length=4)]
    kinds: Annotated[tuple[PrincipalKind,...],Field(min_length=1,max_length=4)]
    owner_or_assignment_required: bool = False
    approval_action: iam.Permission | None = None
    _sets = field_validator('classifications','kinds')(iam._unique)

    @model_validator(mode='after')
    def compatible(self):
        if self.approval_action is not None and iam._resource_type(self.approval_action)!=iam._resource_type(self.action):
            raise ValueError('approval_action_resource_mismatch')
        return self


class AuthorizationPolicy(iam.IAMContract):
    policy_version: Literal['1.0'] = '1.0'
    roles: Annotated[tuple[RoleRule,...],Field(max_length=10)]
    actions: Annotated[tuple[ActionRule,...],Field(max_length=34)]
    default_decision: Literal['DENY'] = 'DENY'

    @model_validator(mode='after')
    def canonical(self):
        object.__setattr__(self,'roles',iam._unique(self.roles,key=lambda r:r.role_id))
        object.__setattr__(self,'actions',iam._unique(self.actions,key=lambda r:r.action))
        return self


def default_policy():
    """Explicit opt-in policy data; evaluate never substitutes it for missing policy."""
    roles=tuple(RoleRule(role_id=role,kinds=kinds,required_tier=tier,actions=actions)
                for role,kinds,tier,actions in _ROLE_DATA)
    actions=[]
    for action in get_args(iam.Permission):
        kinds=('HUMAN',) if action in _HUMAN_ONLY else (('SYSTEM_SERVICE',) if action=='response.execute'
            else ('HUMAN','API_KEY_SERVICE','SYSTEM_SERVICE','AI_ANALYST'))
        actions.append(ActionRule(action=action,classifications=get_args(iam.Classification),kinds=kinds,
            owner_or_assignment_required=action in ('cases.investigate','cases.close'),approval_action=_APPROVAL_ACTIONS.get(action)))
    return AuthorizationPolicy(roles=roles,actions=tuple(actions))


class AuthorizationRequest(iam.IAMContract):
    correlation_id: UUID
    operation_id: UUID
    action: Annotated[str,Field(min_length=1,max_length=64,pattern=r'^(?:[a-z][a-z0-9_.*-]{0,63}|\*)$')]
    resource_ref: iam.TenantReference
    resource_type: iam.ResourceType
    executor_ref: iam.TenantReference
    parameters_sha256: iam.Digest
    policy_version: Version


class TrustedVerification(iam.Validity):
    """Protected verifier output, never a model/request-supplied claim or issuer."""
    verifier_ref: iam.TenantReference
    principal_sha256: iam.Digest
    authentication_sha256: iam.Digest
    snapshot_sha256: iam.Digest
    policy_sha256: iam.Digest
    verified_issuance_sha256: Annotated[tuple[iam.Digest,...],Field(max_length=64)]
    identity_authenticated: bool
    snapshot_authoritative: bool
    issuers_authenticated: bool
    issuance_authorized: bool
    policy_verified: bool
    approval_verified: bool = False
    approval_sha256: iam.Digest | None = None
    origin: Literal['AUTHENTICATED_CONTROL_PLANE'] = 'AUTHENTICATED_CONTROL_PLANE'
    _hashes = field_validator('verified_issuance_sha256')(iam._unique)

    @model_validator(mode='after')
    def freshness(self):
        iam._tenant(self.tenant_id,self.verifier_ref)
        if (self.valid_until-self.valid_from).total_seconds()>300:
            raise ValueError('verification_window_too_large')
        if self.approval_verified and self.approval_sha256 is None:
            raise ValueError('missing_approval_binding')
        return self


class DecisionAudit(iam.TenantBound):
    actor_ref: iam.TenantReference
    actor_kind: PrincipalKind | None
    action: iam.Permission | None
    resource_ref: iam.TenantReference
    resource_type: iam.ResourceType
    matched_assignment_id: UUID | None
    matched_scope_id: UUID | None
    team_ref: iam.TenantReference | None
    policy_version: Version
    policy_sha256: iam.Digest | None
    decision: Literal['ALLOW','DENY']
    reason: Reason
    correlation_id: UUID
    timestamp: datetime


class AuthorizationDecision(iam.TenantBound):
    principal_id: UUID
    outcome: Literal['ALLOW','DENY']
    reason: Reason
    policy_version: Version
    policy_sha256: iam.Digest | None
    correlation_id: UUID
    action: iam.Permission | None
    resource_ref: iam.TenantReference
    resource_type: iam.ResourceType
    operation_sha256: iam.Digest | None
    resource_sha256: iam.Digest | None
    evaluated_at: datetime
    audit: DecisionAudit

    @model_validator(mode='after')
    def consistency(self):
        audit=self.audit
        if ((self.outcome=='ALLOW')!=(self.reason=='AUTHORIZED')
                or (self.outcome=='ALLOW' and any(v is None for v in (self.policy_sha256,self.action,self.operation_sha256,self.resource_sha256,audit.actor_kind)))
                or (self.tenant_id,self.principal_id,self.outcome,self.reason,self.policy_version,self.policy_sha256,
                    self.correlation_id,self.action,self.resource_ref,self.resource_type,self.evaluated_at)
                != (audit.tenant_id,audit.actor_ref.reference_id,audit.decision,audit.reason,audit.policy_version,audit.policy_sha256,
                    audit.correlation_id,audit.action,audit.resource_ref,audit.resource_type,audit.timestamp)
                or audit.actor_ref.tenant_id!=self.tenant_id):
            raise ValueError('inconsistent_authorization_decision')
        iam._utc(self.evaluated_at)
        return self


def _tenant_violation(tenant,value):
    if isinstance(value,iam.TenantBound) and value.tenant_id!=tenant:
        return True
    if isinstance(value,iam.IAMContract):
        return any(_tenant_violation(tenant,child) for child in value.__dict__.values())
    if type(value) is tuple:
        return any(_tenant_violation(tenant,child) for child in value)
    return False


def _grant(subject,action,resource,snapshot,rules,at):
    role_rules={r.role_id:r for r in rules.roles}; scopes={s.scope_id:s for s in snapshot.scopes}
    assignments={a.assignment_id:a for a in snapshot.assignments}; members={m.membership_id:m for m in snapshot.memberships}
    action_rule=next((r for r in rules.actions if r.action==action),None)
    if action_rule is None: return None,'POLICY_CONFLICT'
    if (subject.kind not in action_rule.kinds or (subject.kind=='AI_ANALYST' and action in _AI_FORBIDDEN)):
        return None,'PRINCIPAL_RESTRICTED'
    candidates=[]; seen=set()
    for reference in subject.role_assignment_refs:
        assigned=assignments.get(reference.reference_id)
        if assigned is None or assigned.principal_ref.reference_id!=subject.principal_id: return None,'INPUT_CONFLICT'
        key=(assigned.role_id,assigned.scope.scope_id)
        if key in seen: return None,'INPUT_CONFLICT'
        seen.add(key)
        mapping=role_rules.get(assigned.role_id)
        if mapping is None: return None,'MISSING_ROLE_MAPPING'
        try: iam._current(assigned,at)
        except ValueError: return None,'MISSING_GRANT'
        if subject.kind not in mapping.kinds or (mapping.required_tier is not None and subject.analyst_tier!=mapping.required_tier):
            return None,'PRINCIPAL_RESTRICTED'
        scope=scopes.get(assigned.scope.scope_id)
        if scope!=assigned.scope: return None,'INPUT_CONFLICT'
        if (action in mapping.actions and action in scope.actions and resource.resource_type in scope.resource_types
                and scope.scope_id in {r.reference_id for r in resource.allowed_scope_refs}):
            candidates.append(assigned)
    if not candidates: return None,'MISSING_GRANT'
    team_id=None if resource.owning_team_ref is None else resource.owning_team_ref.reference_id
    if team_id is not None:
        team=next((t for t in snapshot.teams if t.team_id==team_id),None)
        if team is None or not team.active: return None,'TEAM_MISMATCH'
        active_member=False
        for reference in subject.team_membership_refs:
            member=members.get(reference.reference_id)
            if member is None: return None,'INPUT_CONFLICT'
            try: iam._current(member,at)
            except ValueError: continue
            if member.principal_ref.reference_id==subject.principal_id and member.team_ref.reference_id==team_id:
                active_member=True
        if not active_member: return None,'TEAM_MISMATCH'
    candidates=[a for a in candidates if (a.scope.team_scope.mode=='ALL_TENANT_TEAMS'
        or (team_id is not None and team_id in {r.reference_id for r in a.scope.team_scope.team_refs}))]
    if not candidates: return None,'TEAM_MISMATCH'
    candidates=[a for a in candidates if resource.classification in a.scope.classifications and resource.classification in action_rule.classifications]
    if not candidates: return None,'CLASSIFICATION_RESTRICTED'
    if action_rule.owner_or_assignment_required:
        candidates=[a for a in candidates if resource.owner_ref.reference_id==subject.principal_id
            or (resource.assignment_reference is not None and resource.assignment_reference.reference_id==a.assignment_id)]
        if not candidates: return None,'OWNERSHIP_MISMATCH'
    return min(candidates,key=lambda a:str(a.assignment_id)),None


def evaluate(context: TrustedContext,snapshot: iam.IAMSnapshot,request: AuthorizationRequest,*,
             policy: AuthorizationPolicy | None,at: datetime,issuance_evidence: tuple[iam.IssuanceEvidence,...] = (),
             trusted_verification: TrustedVerification | None = None,approval: iam.ApprovalRecord | None = None) -> AuthorizationDecision:
    """Offline ALLOW/DENY only. Inputs must arrive through protected application channels."""
    try: context=iam._checked(context,TrustedContext); at=iam._utc(at)
    except Exception: raise ValueError('invalid_authorization_context') from None
    try: request=iam._checked(request,AuthorizationRequest)
    except Exception: raise ValueError('invalid_authorization_request') from None
    actor=resource=assignment=operation=None; digest=None
    action=request.action if request.action in get_args(iam.Permission) else None
    def decision(reason):
        outcome='ALLOW' if reason=='AUTHORIZED' else 'DENY'
        audit=DecisionAudit(tenant_id=context.tenant_id,
            actor_ref=iam.TenantReference(tenant_id=context.tenant_id,reference_id=context.principal_id),
            actor_kind=None if actor is None else actor.kind,action=action,resource_ref=request.resource_ref,
            resource_type=request.resource_type,matched_assignment_id=None if assignment is None else assignment.assignment_id,
            matched_scope_id=None if assignment is None else assignment.scope.scope_id,
            team_ref=None if resource is None else resource.owning_team_ref,policy_version=request.policy_version,
            policy_sha256=digest,decision=outcome,reason=reason,correlation_id=request.correlation_id,timestamp=at)
        return AuthorizationDecision(tenant_id=context.tenant_id,principal_id=context.principal_id,outcome=outcome,reason=reason,
            policy_version=request.policy_version,policy_sha256=digest,correlation_id=request.correlation_id,action=action,
            resource_ref=request.resource_ref,resource_type=request.resource_type,
            operation_sha256=None if operation is None else iam.contract_digest(operation),
            resource_sha256=None if resource is None else iam.contract_digest(resource),evaluated_at=at,audit=audit)
    # Tenant priority is established before trusting roles, approval or policy data.
    try:
        for value in (snapshot,request.resource_ref,request.executor_ref,issuance_evidence,trusted_verification,approval):
            if value is not None:
                iam._bounded(value)
                if _tenant_violation(context.tenant_id,value): return decision('TENANT_VIOLATION')
    except Exception: return decision('INPUT_CONFLICT')
    try: snapshot=iam._checked(snapshot,iam.IAMSnapshot)
    except Exception: return decision('INPUT_CONFLICT')
    actor=next((p for p in snapshot.principals if p.principal_id==context.principal_id),None)
    try:
        if actor is None or snapshot.tenant.status!='ACTIVE': raise ValueError()
        iam._current(actor,at)
    except Exception: return decision('IDENTITY_INVALID')
    if request.executor_ref.reference_id!=context.principal_id: return decision('EXECUTOR_MISMATCH')
    if action is None: return decision('UNKNOWN_ACTION')
    if request.policy_version!='1.0': return decision('UNSUPPORTED_POLICY')
    if policy is None: return decision('MISSING_POLICY')
    try: policy=iam._checked(policy,AuthorizationPolicy); digest=iam.contract_digest(policy)
    except Exception: return decision('POLICY_CONFLICT')
    try:
        trust=iam._checked(trusted_verification,TrustedVerification); iam._current(trust,at)
    except Exception: return decision('UNVERIFIED_PROVENANCE')
    if (not trust.identity_authenticated or trust.verifier_ref.reference_id==context.principal_id
            or trust.principal_sha256!=iam.contract_digest(actor)
            or trust.authentication_sha256!=iam.contract_digest(actor.authentication)):
        return decision('IDENTITY_INVALID')
    if not trust.policy_verified or trust.policy_sha256!=digest: return decision('POLICY_CONFLICT')
    try:
        if type(issuance_evidence) is not tuple or len(issuance_evidence)>64: raise ValueError()
        receipts=tuple(iam._checked(r,iam.IssuanceEvidence) for r in issuance_evidence)
        if (not trust.snapshot_authoritative or not trust.issuers_authenticated or not trust.issuance_authorized
                or trust.snapshot_sha256!=iam.contract_digest(snapshot)
                or trust.verified_issuance_sha256!=tuple(sorted(iam.contract_digest(r) for r in receipts))):
            raise ValueError()
        if sum(len(iam.canonical_bytes(v)) for v in (snapshot,request,policy,trust,*receipts))>262144: raise ValueError()
    except Exception: return decision('UNVERIFIED_PROVENANCE')
    resource=next((r for r in snapshot.resources if r.resource_id==request.resource_ref.reference_id
                   and r.resource_type==request.resource_type),None)
    if resource is None: return decision('RESOURCE_NOT_FOUND')
    if iam._resource_type(action)!=resource.resource_type: return decision('MISSING_GRANT')
    assignment,reason=_grant(actor,action,resource,snapshot,policy,at)
    if reason: return decision(reason)
    try: snapshot=iam.validate_snapshot(context,snapshot,at=at,trusted_issuance=receipts)
    except Exception: return decision('INPUT_CONFLICT')
    operation=iam.ProposedOperation(tenant_id=context.tenant_id,operation_id=request.operation_id,
        requester_ref=iam.TenantReference(tenant_id=context.tenant_id,reference_id=context.principal_id),
        executor_ref=request.executor_ref,action=action,resource=resource,parameters_sha256=request.parameters_sha256)
    rule=next(r for r in policy.actions if r.action==action)
    if rule.approval_action is not None:
        if approval is None: return decision('APPROVAL_REQUIRED')
        try:
            if not trust.approval_verified: raise ValueError()
            approval=iam._checked(approval,iam.ApprovalRecord)
            if approval.outcome!='APPROVED' or trust.approval_sha256!=iam.contract_digest(approval): raise ValueError()
            approver=next(p for p in snapshot.principals if p.principal_id==approval.approver.principal_id)
            iam.validate_approval(context,operation,approval,trusted_approver=approver,at=at)
        except Exception: return decision('APPROVAL_INVALID')
        # Test authority to approve, not a recursive request to execute that action.
        _,reason=_grant(approver,rule.approval_action,resource,snapshot,policy,at)
        if reason: return decision('APPROVER_NOT_AUTHORIZED')
    elif approval is not None:
        return decision('APPROVAL_INVALID')
    return decision('AUTHORIZED')
