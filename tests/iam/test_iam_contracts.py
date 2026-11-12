"""IAM-01 synthetic structural contracts, never an access-control engine."""
import builtins
from datetime import datetime,timedelta,timezone
from pathlib import Path
import socket
import subprocess
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.iam import contracts as iam
from app.gateway.contracts import TrustedContext

NOW=datetime(2026,11,12,tzinfo=timezone.utc)
TENANT=UUID(int=1)


def ref(value,tenant=TENANT): return iam.TenantReference(tenant_id=tenant,reference_id=UUID(int=value))


def principal(value,kind='HUMAN'):
    return iam.PrincipalIdentity(tenant_id=TENANT,principal_id=UUID(int=value),kind=kind,
        authentication=iam.AuthenticationReference(tenant_id=TENANT,reference_id=UUID(int=value+1000),
            method={'HUMAN':'SESSION','API_KEY_SERVICE':'API_KEY','SYSTEM_SERVICE':'WORKLOAD','AI_ANALYST':'DELEGATION'}[kind]),
        analyst_tier='L1' if kind=='AI_ANALYST' else None,status='ACTIVE',
        valid_from=NOW-timedelta(hours=1),valid_until=NOW+timedelta(hours=1))


def sample():
    subject=principal(2); issuer=principal(3)
    team=iam.Team(tenant_id=TENANT,team_id=UUID(int=4),purpose='SOC',active=True,membership_refs=(ref(5),))
    provenance=iam.Provenance(tenant_id=TENANT,record_id=UUID(int=6),issuer_ref=ref(3),policy_reference='iam-policy:1.0')
    membership=iam.TeamMembership(tenant_id=TENANT,membership_id=UUID(int=5),principal_ref=ref(2),team_ref=ref(4),
        provenance=provenance.model_copy(update={'record_id':UUID(int=16)}),valid_from=NOW-timedelta(minutes=5),valid_until=NOW+timedelta(minutes=5))
    scope=iam.PermissionScope(tenant_id=TENANT,scope_id=UUID(int=7),actions=('evidence.metadata.read',),
        resource_types=('evidence',),classifications=('RESTRICTED',),
        team_scope=iam.TeamScope(tenant_id=TENANT,mode='ASSIGNED_TEAM',team_refs=(ref(4),)))
    assignment=iam.RoleAssignment(tenant_id=TENANT,assignment_id=UUID(int=8),principal_ref=ref(2),role_id='l1_analyst',
        scope=scope,provenance=provenance,valid_from=NOW-timedelta(minutes=5),valid_until=NOW+timedelta(minutes=5))
    subject=subject.model_copy(update={'role_assignment_refs':(ref(8),),'team_membership_refs':(ref(5),)})
    resource=iam.Resource(tenant_id=TENANT,resource_id=UUID(int=9),resource_type='evidence',classification='RESTRICTED',
        owner_ref=ref(3),owning_team_ref=ref(4),allowed_scope_refs=(ref(7),))
    snapshot=iam.IAMSnapshot(tenant=iam.TenantIdentity(tenant_id=TENANT,status='ACTIVE'),
        principals=(subject,issuer),teams=(team,),memberships=(membership,),scopes=(scope,),
        assignments=(assignment,),resources=(resource,),roles=iam.role_catalog(TENANT))
    context=TrustedContext(tenant_id=TENANT,principal_id=UUID(int=2))
    receipts=tuple(iam.IssuanceEvidence(tenant_id=TENANT,record_id=record.provenance.record_id,
        subject_record_id=identity,record_sha256=iam.contract_digest(record),issuer_ref=ref(3),purpose=purpose,
        valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(minutes=1))
        for record,identity,purpose in ((membership,membership.membership_id,'TEAM_MEMBERSHIP'),
            (assignment,assignment.assignment_id,'ROLE_ASSIGNMENT')))
    return context,snapshot,receipts


def validate(parts):
    return iam.validate_snapshot(parts[0],parts[1],at=NOW,trusted_issuance=parts[2])


@pytest.mark.parametrize('kind',['HUMAN','API_KEY_SERVICE','SYSTEM_SERVICE','AI_ANALYST'])
def test_valid_principal_categories(kind):
    value=principal(2,kind)
    assert value.tenant_id==TENANT and value.executable is False


def test_valid_snapshot_and_catalogs_are_proposals_only():
    context,snapshot,receipts=sample()
    checked=validate((context,snapshot,receipts))
    assert checked.executable is False and checked.default_decision=='DENY'
    assert len(iam.role_catalog(TENANT))==10
    assert len(iam.permission_catalog(TENANT))==34
    assert all(item.proposed_only for item in iam.role_catalog(TENANT))


@pytest.mark.parametrize('field,value',[('kind','MODEL_ADMIN'),('tenant_id',None),('schema_version','2.0'),
    ('analyst_tier','L3'),('status','SUPERUSER'),('grants',('all',)),('origin','MODEL_OUTPUT')])
def test_invalid_principal_or_model_authority(field,value):
    data=principal(2).model_dump();data[field]=value
    with pytest.raises(ValueError): iam.PrincipalIdentity.model_validate(data)


@pytest.mark.parametrize('kind',['context_tenant','context_principal','principal','team','membership','resource','scope','assignment','missing_subject'])
def test_tenant_boundary_and_missing_identity(kind):
    context,snapshot,receipts=sample()
    if kind=='context_tenant': context=context.model_copy(update={'tenant_id':UUID(int=99)})
    elif kind=='context_principal': context=context.model_copy(update={'principal_id':UUID(int=99)})
    elif kind=='missing_subject': context=None
    else:
        name={'principal':'principals','team':'teams','membership':'memberships','resource':'resources',
              'scope':'scopes','assignment':'assignments'}[kind]
        items=getattr(snapshot,name); snapshot=snapshot.model_copy(update={name:(items[0].model_copy(update={'tenant_id':UUID(int=99)}),*items[1:])})
    with pytest.raises(ValueError,match='invalid_iam_snapshot'): validate((context,snapshot,receipts))


@pytest.mark.parametrize('changes',[{'mode':'GLOBAL'},{'mode':'EXPLICIT_TEAMS','team_refs':()},
    {'team_refs':(ref(4),ref(4))},{'team_refs':(ref(4,UUID(int=99)),)},
    {'mode':'ALL_TENANT_TEAMS','team_refs':()}])
def test_bad_team_scope(changes):
    data=sample()[1].scopes[0].team_scope.model_dump();data.update(changes)
    with pytest.raises(ValueError): iam.TeamScope.model_validate(data)


def test_all_tenant_teams_requires_independent_authorization_reference():
    scope=iam.TeamScope(tenant_id=TENANT,mode='ALL_TENANT_TEAMS',team_refs=(),authorization_ref=ref(66))
    assert scope.executable is False


@pytest.mark.parametrize('kind',['duplicate_membership','wrong_team','issuer','self_issued','expired','revoked','no_receipt','inactive_team','orphan_reference'])
def test_invalid_assignment_and_membership_graph(kind):
    context,snapshot,receipts=sample(); assignment=snapshot.assignments[0]
    if kind=='duplicate_membership': snapshot=snapshot.model_copy(update={'memberships':snapshot.memberships*2})
    if kind=='wrong_team': snapshot=snapshot.model_copy(update={'memberships':(snapshot.memberships[0].model_copy(update={'team_ref':ref(99)}),)})
    if kind=='issuer': assignment=assignment.model_copy(update={'provenance':assignment.provenance.model_copy(update={'issuer_ref':ref(99)})})
    if kind=='self_issued': assignment=assignment.model_copy(update={'provenance':assignment.provenance.model_copy(update={'issuer_ref':ref(2)})})
    if kind=='expired': assignment=assignment.model_copy(update={'valid_until':NOW})
    if kind=='revoked': assignment=assignment.model_copy(update={'revoked_at':NOW-timedelta(seconds=1)})
    if kind=='no_receipt': receipts=()
    if kind=='inactive_team': snapshot=snapshot.model_copy(update={'teams':(snapshot.teams[0].model_copy(update={'active':False}),)})
    if kind=='orphan_reference': snapshot=snapshot.model_copy(update={'resources':(snapshot.resources[0].model_copy(update={'allowed_scope_refs':(ref(99),)}),)})
    snapshot=snapshot.model_copy(update={'assignments':(assignment,)})
    with pytest.raises(ValueError): validate((context,snapshot,receipts))


@pytest.mark.parametrize('role',['global_admin','root','*','L4','unknown'])
def test_unknown_roles_never_bypass_tenants(role):
    data=sample()[1].assignments[0].model_dump();data['role_id']=role
    with pytest.raises(ValueError): iam.RoleAssignment.model_validate(data)


@pytest.mark.parametrize('action',['*','evidence.*','response','response.all','tools.invoke','unknown.read'])
def test_unknown_wildcard_actions_fail(action):
    data=sample()[1].scopes[0].model_dump();data['actions']=(action,)
    with pytest.raises(ValueError): iam.PermissionScope.model_validate(data)


def test_sensitive_permissions_are_separate_and_do_not_inherit():
    scope=sample()[1].scopes[0]
    assert scope.actions==('evidence.metadata.read',)
    assert not set(('evidence.raw.read','evidence.export','tools.invoke.approved','response.execute')) & set(scope.actions)
    catalog={item.action:item for item in iam.permission_catalog(TENANT)}
    assert catalog['evidence.metadata.read'].access_kind=='METADATA'
    assert catalog['evidence.raw.read'].access_kind=='RAW'
    assert catalog['evidence.export'].access_kind=='EXPORT'
    for left,right in (('tools.propose','tools.invoke.approved'),('response.propose','response.approve'),('response.approve','response.execute')):
        assert catalog[left].action!=catalog[right].action


@pytest.mark.parametrize('changes',[{'classification':None},{'classification':'SECRET'},{'classification':'*'},
    {'classification_override':'PUBLIC'},{'owning_team_ref':ref(4,UUID(int=99))}])
def test_resource_classification_and_ownership(changes):
    data=sample()[1].resources[0].model_dump();data.update(changes)
    with pytest.raises(ValueError): iam.Resource.model_validate(data)


def approval_fixture():
    context,snapshot,_=sample(); resource=snapshot.resources[0]
    operation=iam.ProposedOperation(tenant_id=TENANT,operation_id=UUID(int=20),requester_ref=ref(2),executor_ref=ref(2),
        action='evidence.export',resource=resource,parameters_sha256='a'*64)
    approver=principal(3)
    approval=iam.ApprovalRecord(tenant_id=TENANT,approval_id=UUID(int=21),operation=operation,approver=approver,
        operation_sha256=iam.contract_digest(operation),resource_sha256=iam.contract_digest(resource),outcome='APPROVED',
        provenance=iam.Provenance(tenant_id=TENANT,record_id=UUID(int=22),issuer_ref=ref(3),policy_reference='approval-policy:1.0'),
        valid_from=NOW-timedelta(minutes=1),valid_until=NOW+timedelta(minutes=1))
    return context,operation,approval,approver


def test_approval_is_not_an_execution_token():
    context,operation,approval,approver=approval_fixture()
    checked=iam.validate_approval(context,operation,approval,trusted_approver=approver,at=NOW)
    assert checked.executable is False and checked.outcome=='APPROVED'


@pytest.mark.parametrize('kind',['ai','self','digest','resource_digest','tenant','expired','forged_human','missing_approver','downgrade'])
def test_approval_separation_and_binding(kind):
    context,operation,approval,approver=approval_fixture()
    if kind=='ai': approval=approval.model_copy(update={'approver':principal(3,'AI_ANALYST')})
    if kind=='self': approval=approval.model_copy(update={'approver':principal(2)})
    if kind=='digest': approval=approval.model_copy(update={'operation_sha256':'0'*64})
    if kind=='resource_digest': approval=approval.model_copy(update={'resource_sha256':'0'*64})
    if kind=='tenant': approval=approval.model_copy(update={'tenant_id':UUID(int=99)})
    if kind=='expired': approval=approval.model_copy(update={'valid_until':NOW})
    if kind=='forged_human': approver=principal(3,'AI_ANALYST')
    if kind=='missing_approver': approver=None
    if kind=='downgrade':
        resource=operation.resource.model_copy(update={'classification':'PUBLIC'})
        changed=operation.model_copy(update={'resource':resource})
        approval=approval.model_copy(update={'operation':changed,'operation_sha256':iam.contract_digest(changed),'resource_sha256':iam.contract_digest(resource)})
    with pytest.raises(ValueError,match='invalid_iam_approval'):
        iam.validate_approval(context,operation,approval,trusted_approver=approver,at=NOW)


def audit():
    return iam.IAMAuditMetadata(tenant_id=TENANT,actor_ref=ref(2),action='evidence.metadata.read',resource=sample()[1].resources[0],
        team_scope=sample()[1].scopes[0].team_scope,roles=('l1_analyst',),permissions=('evidence.metadata.read',),
        policy_version='1.0',decision='DENY',reason='NO_GRANT',request_correlation_id=UUID(int=30),timestamp=NOW)


def test_audit_metadata_is_bounded_non_executable_and_deterministic():
    event=audit()
    assert iam.canonical_bytes(event)==iam.canonical_bytes(audit())
    assert event.executable is False
    assert type(event).model_validate_json(event.model_dump_json())==event
    with pytest.raises(ValidationError): event.decision='ALLOW'


@pytest.mark.parametrize('changes',[{'decision':'ALLOW'},{'reason':'password=synthetic-secret'},
    {'api_key':'soc_synthetic-secret'},{'raw_evidence':'synthetic-secret'},
    {'actor_ref':ref(2,UUID(int=99))},{'timestamp':NOW.replace(tzinfo=None)}, {'schema_version':'2.0'}])
def test_invalid_or_sensitive_audit_metadata(changes):
    data=audit().model_dump();data.update(changes)
    with pytest.raises(ValueError) as caught: iam.IAMAuditMetadata.model_validate(data)
    assert 'synthetic-secret' not in str(caught.value)


def test_contracts_and_helpers_do_no_io_or_authorization(monkeypatch):
    parts=sample(); approval=approval_fixture()
    from app.gateway import tool_gateway
    def forbidden(*a,**k): raise AssertionError('forbidden access')
    original=builtins.__import__
    def restricted(name,*a,**k):
        if name.startswith(('sqlalchemy','psycopg','ollama')) or name in ('app.db','app.auth','app.iam.auth','app.audit','app.audit.integrity','app.config','app.core.config'):
            raise AssertionError('forbidden runtime import')
        return original(name,*a,**k)
    for owner,name in ((builtins,'open'),(Path,'open'),(socket,'socket'),(socket,'create_connection'),
        (subprocess,'Popen'),(tool_gateway,'execute')):
        monkeypatch.setattr(owner,name,forbidden)
    monkeypatch.setattr(builtins,'__import__',restricted)
    assert validate(parts).default_decision=='DENY'
    assert iam.validate_approval(*approval[:3],trusted_approver=approval[3],at=NOW).executable is False
    assert audit().decision=='DENY'


@pytest.mark.parametrize('kind',['role','scope','receipt_digest','receipt_tenant','receipt_expired','receipt_duplicate','model_origin'])
def test_stale_or_forged_issuance_evidence_never_validates_changed_records(kind):
    context,snapshot,receipts=sample(); receipts=list(receipts)
    if kind=='role': snapshot=snapshot.model_copy(update={'assignments':(snapshot.assignments[0].model_copy(update={'role_id':'org_admin'}),)})
    if kind=='scope':
        scope=snapshot.scopes[0].model_copy(update={'actions':('evidence.raw.read',)})
        snapshot=snapshot.model_copy(update={'scopes':(scope,),
            'assignments':(snapshot.assignments[0].model_copy(update={'scope':scope}),)})
    if kind=='receipt_digest': receipts[0]=receipts[0].model_copy(update={'record_sha256':'0'*64})
    if kind=='receipt_tenant': receipts[0]=receipts[0].model_copy(update={'tenant_id':UUID(int=99)})
    if kind=='receipt_expired': receipts[0]=receipts[0].model_copy(update={'valid_until':NOW})
    if kind=='receipt_duplicate': receipts.append(receipts[0])
    if kind=='model_origin': receipts[0]=receipts[0].model_copy(update={'origin':'MODEL_OUTPUT'})
    with pytest.raises(ValueError): validate((context,snapshot,tuple(receipts)))


def test_well_formed_revoked_assignment_remains_non_executable_and_is_not_current_input():
    context,snapshot,receipts=sample(); assignment=snapshot.assignments[0]
    data=assignment.model_dump(); data.update(revoked_at=NOW-timedelta(seconds=1),revocation_reference=ref(91))
    revoked=iam.RoleAssignment.model_validate(data)
    assert revoked.executable is False
    with pytest.raises(ValueError): validate((context,snapshot.model_copy(update={'assignments':(revoked,)}),receipts))


@pytest.mark.parametrize('field,value',[('valid_until',NOW-timedelta(days=1)),
    ('valid_from',NOW.replace(tzinfo=None)),('valid_from',NOW+timedelta(days=1)),
    ('provenance',None),('principal_ref',ref(2,UUID(int=99)))])
def test_assignment_contract_rejects_invalid_periods_or_provenance(field,value):
    data=sample()[1].assignments[0].model_dump();data[field]=value
    with pytest.raises(ValueError): iam.RoleAssignment.model_validate(data)


def test_missing_classification_and_duplicate_principal_refs_fail():
    data=sample()[1].resources[0].model_dump();del data['classification']
    with pytest.raises(ValueError): iam.Resource.model_validate(data)
    data=principal(2).model_dump();data['team_membership_refs']=(ref(5),ref(5))
    with pytest.raises(ValueError): iam.PrincipalIdentity.model_validate(data)


def test_resource_scope_classification_and_team_are_not_inherited():
    context,snapshot,receipts=sample()
    for changes in ({'classification':'PUBLIC'}, {'owning_team_ref':None}, {'assignment_reference':ref(99)}):
        resource=snapshot.resources[0].model_copy(update=changes)
        with pytest.raises(ValueError): validate((context,snapshot.model_copy(update={'resources':(resource,)}),receipts))


def test_ai_issuer_and_suspended_subject_are_not_current_control_plane_inputs():
    context,snapshot,receipts=sample()
    issuer=principal(3,'AI_ANALYST')
    with pytest.raises(ValueError): validate((context,snapshot.model_copy(update={'principals':(snapshot.principals[0],issuer)}),receipts))
    subject=snapshot.principals[0].model_copy(update={'status':'SUSPENDED'})
    with pytest.raises(ValueError): validate((context,snapshot.model_copy(update={'principals':(subject,snapshot.principals[1])}),receipts))


def test_snapshot_ordering_immutability_and_capacity_are_deterministic():
    context,snapshot,receipts=sample()
    reversed_=snapshot.model_copy(update={'principals':tuple(reversed(snapshot.principals)),'roles':tuple(reversed(snapshot.roles))})
    assert iam.canonical_bytes(validate((context,reversed_,receipts)))==iam.canonical_bytes(validate((context,snapshot,receipts)))
    with pytest.raises(ValidationError): snapshot.default_decision='ALLOW'
    with pytest.raises(ValueError): validate((context,snapshot.model_copy(update={'principals':snapshot.principals*33}),receipts))


def test_denial_approval_record_does_not_become_an_allow_decision():
    context,operation,approval,approver=approval_fixture()
    denied=approval.model_copy(update={'outcome':'DENIED'})
    assert iam.validate_approval(context,operation,denied,trusted_approver=approver,at=NOW).outcome=='DENIED'
    assert denied.executable is False


def test_canonicalization_rejects_forged_values_without_serializer_leakage():
    forged=sample()[1].resources[0].model_copy(update={'resource_id':'synthetic-secret-canary'})
    with pytest.raises(ValueError) as caught: iam.canonical_bytes(forged)
    assert 'synthetic-secret-canary' not in str(caught.value)
