"""IAM-02: synthetic protected inputs and pure authorization decisions."""
import builtins
from datetime import timedelta
from pathlib import Path
import socket
import subprocess
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.iam import contracts as iam
from app.iam import policy as policy
from tests.iam.test_iam_contracts import NOW,TENANT,ref,principal,sample


def issuances(snapshot):
    records=[(m,m.membership_id,'TEAM_MEMBERSHIP') for m in snapshot.memberships]
    records += [(a,a.assignment_id,'ROLE_ASSIGNMENT') for a in snapshot.assignments]
    return tuple(iam.IssuanceEvidence(tenant_id=TENANT,record_id=r.provenance.record_id,
        subject_record_id=i,record_sha256=iam.contract_digest(r),issuer_ref=r.provenance.issuer_ref,purpose=p,
        valid_from=NOW-timedelta(seconds=30),valid_until=NOW+timedelta(seconds=30)) for r,i,p in records)


def verification(context,snapshot,rules,receipts,approval=None):
    subject=next(p for p in snapshot.principals if p.principal_id==context.principal_id)
    return policy.TrustedVerification(tenant_id=TENANT,verifier_ref=ref(900),
        principal_sha256=iam.contract_digest(subject),authentication_sha256=iam.contract_digest(subject.authentication),
        snapshot_sha256=iam.contract_digest(snapshot),policy_sha256=iam.contract_digest(rules),
        verified_issuance_sha256=tuple(sorted(iam.contract_digest(r) for r in receipts)),
        identity_authenticated=True,snapshot_authoritative=True,issuers_authenticated=True,
        issuance_authorized=True,policy_verified=True,approval_verified=approval is not None,
        approval_sha256=None if approval is None else iam.contract_digest(approval),
        valid_from=NOW-timedelta(seconds=30),valid_until=NOW+timedelta(seconds=30))


def scenario(role='l1_analyst',actions=('evidence.metadata.read',),kind='HUMAN',classification='RESTRICTED'):
    context,snapshot,_=sample()
    category=iam._resource_type(actions[0])
    scope=snapshot.scopes[0].model_copy(update={'actions':actions,'resource_types':(category,),
        'classifications':(classification,)})
    assignment=snapshot.assignments[0].model_copy(update={'role_id':role,'scope':scope})
    actor=principal(2,kind).model_copy(update={'role_assignment_refs':(ref(8),),'team_membership_refs':(ref(5),)})
    resource=snapshot.resources[0].model_copy(update={'resource_type':category,'classification':classification})
    snapshot=snapshot.model_copy(update={'principals':(actor,snapshot.principals[1]),'scopes':(scope,),
        'assignments':(assignment,),'resources':(resource,)})
    rules=policy.default_policy(); receipts=issuances(snapshot)
    request=policy.AuthorizationRequest(correlation_id=UUID(int=50),operation_id=UUID(int=20),
        action=actions[0],resource_ref=ref(9),resource_type=category,executor_ref=ref(2),
        parameters_sha256='a'*64,policy_version='1.0')
    return dict(context=context,snapshot=snapshot,request=request,policy=rules,at=NOW,
        issuance_evidence=receipts,trusted_verification=verification(context,snapshot,rules,receipts),approval=None)


def refresh(args):
    args['issuance_evidence']=issuances(args['snapshot'])
    args['trusted_verification']=verification(args['context'],args['snapshot'],args['policy'],
        args['issuance_evidence'],args.get('approval'))
    return args


def approved_scenario():
    args=scenario('service_integration',('response.execute',),'SYSTEM_SERVICE')
    snapshot=args['snapshot']; actor=snapshot.principals[0]; root=principal(40)
    approver=principal(3).model_copy(update={'role_assignment_refs':(ref(18),),'team_membership_refs':(ref(15),)})
    scope=snapshot.scopes[0].model_copy(update={'scope_id':UUID(int=17),'actions':('response.approve',)})
    provenance=iam.Provenance(tenant_id=TENANT,record_id=UUID(int=36),issuer_ref=ref(40),policy_reference='iam-policy:1.0')
    assignment=iam.RoleAssignment(tenant_id=TENANT,assignment_id=UUID(int=18),principal_ref=ref(3),role_id='soc_manager',
        scope=scope,provenance=provenance,valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(minutes=1))
    member=iam.TeamMembership(tenant_id=TENANT,membership_id=UUID(int=15),principal_ref=ref(3),team_ref=ref(4),
        provenance=provenance.model_copy(update={'record_id':UUID(int=37)}),
        valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(minutes=1))
    resource=snapshot.resources[0].model_copy(update={'allowed_scope_refs':(ref(7),ref(17))})
    args['snapshot']=snapshot.model_copy(update={'principals':(actor,approver,root),'scopes':(*snapshot.scopes,scope),
        'assignments':(*snapshot.assignments,assignment),'memberships':(*snapshot.memberships,member),
        'teams':(snapshot.teams[0].model_copy(update={'membership_refs':(ref(5),ref(15))}),),'resources':(resource,)})
    operation=iam.ProposedOperation(tenant_id=TENANT,operation_id=UUID(int=20),requester_ref=ref(2),executor_ref=ref(2),
        action='response.execute',resource=resource,parameters_sha256='a'*64)
    args['approval']=iam.ApprovalRecord(tenant_id=TENANT,approval_id=UUID(int=21),operation=operation,approver=approver,
        operation_sha256=iam.contract_digest(operation),resource_sha256=iam.contract_digest(resource),outcome='APPROVED',
        provenance=iam.Provenance(tenant_id=TENANT,record_id=UUID(int=22),issuer_ref=ref(3),policy_reference='approval-policy:1.0'),
        valid_from=NOW-timedelta(seconds=20),valid_until=NOW+timedelta(seconds=20))
    return refresh(args)


def test_valid_same_tenant_decision_is_not_an_executable_capability():
    result=policy.evaluate(**scenario())
    assert result.outcome=='ALLOW' and result.reason=='AUTHORIZED' and result.executable is False
    assert result.audit.actor_ref==ref(2) and result.audit.action=='evidence.metadata.read'


@pytest.mark.parametrize('left,right,role',[
    ('evidence.metadata.read','evidence.raw.read','l2_analyst'),
    ('evidence.raw.read','evidence.export','soc_manager'),
    ('tools.propose','tools.invoke.approved','soc_manager'),
    ('response.propose','response.approve','soc_manager'),
    ('response.approve','response.execute','soc_manager'),
    ('models.configure','models.approve','org_admin'),
    ('knowledge.update.propose','knowledge.activate','soc_manager'),
    ('detection_rules.update.propose','detection_rules.activate','soc_manager')])
def test_actions_do_not_imply_other_permissions(left,right,role):
    args=scenario(role,(left,));args['request']=args['request'].model_copy(update={'action':right})
    result=policy.evaluate(**args)
    assert result.outcome=='DENY' and result.reason in ('MISSING_GRANT','PRINCIPAL_RESTRICTED')


@pytest.mark.parametrize('kind',['resource','assignment','membership','principal','approval'])
def test_tenant_violation_precedes_other_failures(kind):
    args=approved_scenario() if kind=='approval' else scenario()
    if kind=='resource': args['request']=args['request'].model_copy(update={'resource_ref':ref(9,UUID(int=99))})
    elif kind=='approval': args['approval']=args['approval'].model_copy(update={'tenant_id':UUID(int=99)})
    else:
        name={'assignment':'assignments','membership':'memberships','principal':'principals'}[kind]
        values=getattr(args['snapshot'],name)
        args['snapshot']=args['snapshot'].model_copy(update={name:(values[0].model_copy(update={'tenant_id':UUID(int=99)}),*values[1:])})
    result=policy.evaluate(**args)
    assert result.outcome=='DENY' and result.reason=='TENANT_VIOLATION'


@pytest.mark.parametrize('action',['unknown.read','evidence.*','*'])
def test_unknown_action_is_denied_without_echoing_untrusted_value(action):
    args=scenario();args['request']=args['request'].model_copy(update={'action':action})
    result=policy.evaluate(**args)
    assert result.outcome=='DENY' and result.reason=='UNKNOWN_ACTION' and result.action is None


@pytest.mark.parametrize('kind',['missing','unauthenticated','issuer','issuance','snapshot','principal','policy','expired'])
def test_separate_verification_is_mandatory_and_exact(kind):
    args=scenario(); trust=args['trusted_verification']
    if kind=='missing': trust=None
    else:
        changes={'unauthenticated':{'identity_authenticated':False},'issuer':{'issuers_authenticated':False},
            'issuance':{'issuance_authorized':False},'snapshot':{'snapshot_sha256':'0'*64},
            'principal':{'principal_sha256':'0'*64},'policy':{'policy_sha256':'0'*64},'expired':{'valid_until':NOW}}[kind]
        trust=trust.model_copy(update=changes)
    args['trusted_verification']=trust
    assert policy.evaluate(**args).outcome=='DENY'


@pytest.mark.parametrize('kind',['suspended','revoked','expired_assignment','revoked_assignment','expired_member','inactive_team'])
def test_stale_security_records_cannot_authorize(kind):
    args=scenario(); snapshot=args['snapshot']
    if kind in ('suspended','revoked'):
        actor=snapshot.principals[0].model_copy(update={'status':'SUSPENDED'} if kind=='suspended' else
            {'status':'REVOKED','revoked_at':NOW-timedelta(seconds=1),'revocation_reference':ref(80)})
        snapshot=snapshot.model_copy(update={'principals':(actor,snapshot.principals[1])})
    if kind in ('expired_assignment','revoked_assignment'):
        value=snapshot.assignments[0].model_copy(update={'valid_until':NOW} if kind=='expired_assignment' else
            {'revoked_at':NOW-timedelta(seconds=1),'revocation_reference':ref(80)})
        snapshot=snapshot.model_copy(update={'assignments':(value,)})
    if kind=='expired_member': snapshot=snapshot.model_copy(update={'memberships':(snapshot.memberships[0].model_copy(update={'valid_until':NOW}),)})
    if kind=='inactive_team': snapshot=snapshot.model_copy(update={'teams':(snapshot.teams[0].model_copy(update={'active':False}),)})
    args['snapshot']=snapshot
    assert policy.evaluate(**refresh(args)).outcome=='DENY'


def test_ownership_is_independent_of_role_name():
    args=scenario('l2_analyst',('cases.investigate',))
    assert policy.evaluate(**args).reason=='OWNERSHIP_MISMATCH'
    resource=args['snapshot'].resources[0].model_copy(update={'owner_ref':ref(2)})
    args['snapshot']=args['snapshot'].model_copy(update={'resources':(resource,)})
    assert policy.evaluate(**refresh(args)).outcome=='ALLOW'


@pytest.mark.parametrize('classification',['CONFIDENTIAL','RESTRICTED'])
def test_classification_requires_exact_explicit_scope(classification):
    args=scenario(classification=classification); snapshot=args['snapshot']
    scope=snapshot.scopes[0].model_copy(update={'classifications':('PUBLIC',)})
    args['snapshot']=snapshot.model_copy(update={'scopes':(scope,),
        'assignments':(snapshot.assignments[0].model_copy(update={'scope':scope}),)})
    assert policy.evaluate(**refresh(args)).reason=='CLASSIFICATION_RESTRICTED'


def test_approved_exact_operation_requires_human_authority_and_execute_grant():
    args=approved_scenario(); result=policy.evaluate(**args)
    assert result.outcome=='ALLOW' and result.executable is False
    assert result.operation_sha256==args['approval'].operation_sha256
    args['request']=args['request'].model_copy(update={'parameters_sha256':'b'*64})
    assert policy.evaluate(**args).reason=='APPROVAL_INVALID'


@pytest.mark.parametrize('kind',['missing','expired','unverified','digest','self','ai','no_approve_permission','no_execute_permission'])
def test_approval_failures_never_override_authorization(kind):
    args=approved_scenario()
    if kind=='missing': args['approval']=None
    if kind=='expired': args['approval']=args['approval'].model_copy(update={'valid_until':NOW})
    if kind=='unverified': args['trusted_verification']=args['trusted_verification'].model_copy(update={'approval_verified':False})
    if kind=='digest': args['approval']=args['approval'].model_copy(update={'operation_sha256':'0'*64})
    if kind=='self': args['approval']=args['approval'].model_copy(update={'approver':args['snapshot'].principals[0]})
    if kind=='ai': args['approval']=args['approval'].model_copy(update={'approver':principal(3,'AI_ANALYST')})
    if kind in ('no_approve_permission','no_execute_permission'):
        index=1 if kind=='no_approve_permission' else 0; snapshot=args['snapshot']; old=snapshot.scopes[index]
        scope=old.model_copy(update={'actions':('response.propose',)})
        scopes=list(snapshot.scopes);scopes[index]=scope
        assignments=tuple(a.model_copy(update={'scope':scope}) if a.scope.scope_id==scope.scope_id else a for a in snapshot.assignments)
        args['snapshot']=snapshot.model_copy(update={'scopes':tuple(scopes),'assignments':assignments})
        args=refresh(args)
    assert policy.evaluate(**args).outcome=='DENY'


@pytest.mark.parametrize('action',['response.approve','response.execute','models.approve','roles.assign'])
def test_ai_tier_is_not_authority(action):
    args=scenario('ai_l1_service',(action,),'AI_ANALYST')
    assert policy.evaluate(**args).outcome=='DENY'


@pytest.mark.parametrize('kind',['missing_policy','unknown_version','duplicate_policy','missing_role','wildcard_policy','role_spoof','duplicate_assignment','changed_assignment'])
def test_policy_or_assignment_conflicts_fail_closed(kind):
    args=scenario()
    if kind=='missing_policy': args['policy']=None
    if kind=='unknown_version': args['request']=args['request'].model_copy(update={'policy_version':'2.0'})
    if kind=='duplicate_policy': args['policy']=args['policy'].model_copy(update={'roles':args['policy'].roles*2})
    if kind=='missing_role': args['policy']=args['policy'].model_copy(update={'roles':tuple(r for r in args['policy'].roles if r.role_id!='l1_analyst')});args=refresh(args)
    if kind=='wildcard_policy':
        rules=list(args['policy'].roles);rules[0]=rules[0].model_copy(update={'actions':('*',)})
        args['policy']=args['policy'].model_copy(update={'roles':tuple(rules)})
    if kind=='role_spoof': args['snapshot']=args['snapshot'].model_copy(update={'assignments':(args['snapshot'].assignments[0].model_copy(update={'role_id':'global_admin'}),)})
    if kind=='duplicate_assignment': args['snapshot']=args['snapshot'].model_copy(update={'assignments':args['snapshot'].assignments*2})
    if kind=='changed_assignment': args['snapshot']=args['snapshot'].model_copy(update={'assignments':(args['snapshot'].assignments[0].model_copy(update={'role_id':'org_admin'}),)})
    assert policy.evaluate(**args).outcome=='DENY'


def test_decisions_are_immutable_canonical_and_have_sanitized_audit_metadata():
    args=scenario(); first=policy.evaluate(**args)
    assert iam.canonical_bytes(first)==iam.canonical_bytes(policy.evaluate(**args))
    assert type(first).model_validate_json(first.model_dump_json())==first
    with pytest.raises(ValidationError): first.outcome='DENY'
    data=args['request'].model_dump();data['grants']=['synthetic-secret-canary']
    with pytest.raises(ValueError,match='invalid_authorization_request'):
        policy.evaluate(**dict(args,request=args['request'].model_copy(update={'grants':['synthetic-secret-canary']})))
    assert 'authentication' not in first.audit.model_dump_json()


def test_missing_context_raises_only_a_sanitized_error():
    args=scenario(); args['context']=None
    with pytest.raises(ValueError,match='invalid_authorization_context'): policy.evaluate(**args)


@pytest.mark.parametrize('role,kind,tier',[
    ('org_admin','HUMAN',None),('soc_manager','HUMAN',None),('l1_analyst','HUMAN',None),
    ('l2_analyst','HUMAN',None),('l3_threat_hunter','HUMAN',None),('read_only_auditor','HUMAN',None),
    ('service_integration','API_KEY_SERVICE',None),('ai_l1_service','AI_ANALYST','L1'),
    ('ai_l2_service','AI_ANALYST','L2'),('ai_l3_service','AI_ANALYST','L3')])
def test_explicit_role_catalog_requires_matching_identity(role,kind,tier):
    args=scenario(role,('evidence.metadata.read',),kind)
    if tier is not None:
        people=args['snapshot'].principals
        args['snapshot']=args['snapshot'].model_copy(update={'principals':(
            people[0].model_copy(update={'analyst_tier':tier}),*people[1:])})
        refresh(args)
    result=policy.evaluate(**args)
    assert result.outcome==('DENY' if role=='org_admin' else 'ALLOW')


def test_privileged_mappings_and_all_actions_are_explicit():
    rules=policy.default_policy(); roles={r.role_id:set(r.actions) for r in rules.roles}
    assert len(rules.roles)==10 and len(rules.actions)==34
    assert 'response.execute' not in roles['soc_manager']
    assert 'response.approve' not in roles['service_integration']
    assert 'evidence.raw.read' not in roles['org_admin']
    for role in ('ai_l1_service','ai_l2_service','ai_l3_service'):
        assert not roles[role]&{'response.execute','response.approve','roles.assign','models.approve'}


def test_policy_classification_rule_cannot_be_bypassed_by_explicit_assignment():
    args=scenario()
    args['policy']=args['policy'].model_copy(update={'actions':tuple(
        r.model_copy(update={'classifications':('PUBLIC',)}) if r.action=='evidence.metadata.read' else r
        for r in args['policy'].actions)})
    assert policy.evaluate(**refresh(args)).reason=='CLASSIFICATION_RESTRICTED'


def test_no_io_database_model_or_gateway_access(monkeypatch):
    args=approved_scenario()
    from app.gateway import tool_gateway
    def forbidden(*a,**k): raise AssertionError('forbidden access')
    original=builtins.__import__
    def restricted(name,*a,**k):
        if name.startswith(('sqlalchemy','psycopg','ollama','httpx')) or name in ('app.auth','app.iam.auth','app.audit','app.audit.integrity','app.db','app.config','app.core.config'):
            raise AssertionError('forbidden import')
        return original(name,*a,**k)
    for owner,name in ((builtins,'open'),(Path,'open'),(socket,'socket'),(socket,'create_connection'),
        (subprocess,'Popen'),(tool_gateway,'execute')):
        monkeypatch.setattr(owner,name,forbidden)
    monkeypatch.setattr(builtins,'__import__',restricted)
    assert policy.evaluate(**args).outcome=='ALLOW'
