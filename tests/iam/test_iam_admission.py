"""Synthetic authority fixtures; no operational authentication or credentials."""
import builtins
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
import socket
import subprocess
from uuid import UUID

import pytest
from pydantic import ValidationError
from app.iam import contracts as iam
from app.iam import policy as policy
from app.iam import admission as admission
from tests.iam.test_iam_contracts import NOW,TENANT,ref
from tests.iam.test_iam_policy import scenario,refresh


@dataclass(frozen=True)
class SyntheticAuthenticatedPrincipal:
    tenant_id: UUID
    api_key_id: UUID


def fixture():
    args=scenario('service_integration',kind='API_KEY_SERVICE')
    actor=args['snapshot'].principals[0]
    actor=actor.model_copy(update={'authentication':actor.authentication.model_copy(update={'reference_id':actor.principal_id})})
    args['snapshot']=args['snapshot'].model_copy(update={'principals':(actor,*args['snapshot'].principals[1:])})
    refresh(args)
    auth=SyntheticAuthenticatedPrincipal(TENANT,UUID(int=2))
    operation=iam.ProposedOperation(tenant_id=TENANT,operation_id=args['request'].operation_id,
        requester_ref=ref(2),executor_ref=ref(2),action=args['request'].action,
        resource=args['snapshot'].resources[0],parameters_sha256=args['request'].parameters_sha256)
    state=admission.RevocationState(tenant_id=TENANT,state_id=UUID(int=70),observed_at=NOW,
        revoked_refs=())
    bundle=admission.AuthoritySnapshot(tenant_id=TENANT,snapshot_id=UUID(int=60),source_ref=ref(800),
        issuer_ref=ref(600),verifier_ref=ref(900),valid_from=NOW-timedelta(seconds=1),
        valid_until=NOW+timedelta(seconds=30),evaluated_at=NOW,request_sha256=iam.contract_digest(args['request']),
        operation_sha256=iam.contract_digest(operation),snapshot=args['snapshot'],policy=args['policy'],
        api_key_state=admission.APIKeyState(tenant_id=TENANT,api_key_id=UUID(int=2),principal_ref=ref(2),
            active=True,valid_from=NOW-timedelta(seconds=1),valid_until=NOW+timedelta(seconds=30)),
        issuance_evidence=args['issuance_evidence'],revocations=state)
    anchors=tuple(admission.IssuerAuthority(tenant_id=TENANT,issuer_ref=ref(i),source_ref=ref(800),
        record_types=kinds,valid_from=NOW-timedelta(seconds=60),valid_until=NOW+timedelta(seconds=60))
        for i,kinds in ((600,('SNAPSHOT',)),(900,('VERIFIER',)),(3,('ROLE_ASSIGNMENT','TEAM_MEMBERSHIP'))))
    return auth,args['request'],bundle,anchors


def run(parts,*,origin=True,auth_override=None,at=NOW):
    auth,request,bundle,anchors=parts
    registry=admission.SyntheticOriginRegistry.for_tests((bundle,) if origin else ())
    source=admission.SyntheticAuthority.for_tests(auth,bundle,anchors,registry)
    return admission.admit(auth if auth_override is None else auth_override,request,authority=source,at=at)


def test_valid_admitted_identity_and_policy_allowance():
    result=run(fixture())
    assert result.status=='POLICY_ALLOW' and result.admitted is not None
    assert result.policy_decision.outcome=='ALLOW' and result.executable is False
    assert result.admitted.principal_ref==ref(2)
    assert result.admitted.authentication_ref.reference_id==UUID(int=2)


@pytest.mark.parametrize('change',['none','forged_key','forged_tenant','copied_identity'])
def test_authentication_mapping_requires_independent_current_identity(change):
    parts=fixture(); auth=parts[0]
    overrides={'none':None,'forged_key':replace(auth,api_key_id=UUID(int=42)),
        'forged_tenant':replace(auth,tenant_id=UUID(int=42)),'copied_identity':replace(auth)}
    registry=admission.SyntheticOriginRegistry.for_tests((parts[2],))
    source=admission.SyntheticAuthority.for_tests(auth,parts[2],parts[3],registry)
    assert admission.admit(overrides[change],parts[1],authority=source,at=NOW).status=='ADMISSION_DENIED'


@pytest.mark.parametrize('change',['unknown','revoked','expired','tenant','record_scope','duplicate','self_declared'])
def test_independent_issuer_allowlist(change):
    auth,req,bundle,anchors=fixture(); anchor=anchors[0]
    if change=='unknown': anchors=anchors[1:]
    elif change=='revoked': anchors=(anchor.model_copy(update={'revoked_at':NOW,'revocation_reference':ref(90)}),*anchors[1:])
    elif change=='expired': anchors=(anchor.model_copy(update={'valid_until':NOW}),*anchors[1:])
    elif change=='tenant': anchors=(anchor.model_copy(update={'tenant_id':UUID(int=99)}),*anchors[1:])
    elif change=='record_scope': anchors=(anchor.model_copy(update={'record_types':('APPROVAL',)}),*anchors[1:])
    elif change=='duplicate': anchors=(*anchors,anchor)
    elif change=='self_declared': anchors=()
    assert run((auth,req,bundle,anchors)).status=='ADMISSION_DENIED'


@pytest.mark.parametrize('change',['missing_origin','matching_digest','flag','missing_principal','duplicate_principal',
    'inactive','revoked_principal','tenant_principal','expired_assignment','revoked_assignment','expired_member',
    'revoked_member','missing_resource','conflicting_scope','missing_receipt','issuer_substitution'])
def test_untrusted_missing_conflicting_or_stale_records(change):
    auth,req,bundle,anchors=fixture(); snapshot=bundle.snapshot
    if change in ('missing_origin','matching_digest'):
        assert run((auth,req,bundle,anchors),origin=False).status=='ADMISSION_DENIED'; return
    if change=='flag': bundle=bundle.model_copy(update={'verified':True})
    if change in ('missing_principal','duplicate_principal','inactive','revoked_principal','tenant_principal'):
        actor=snapshot.principals[0]
        if change=='missing_principal': people=snapshot.principals[1:]
        elif change=='duplicate_principal': people=(*snapshot.principals,actor)
        else:
            updates={'inactive':{'status':'SUSPENDED'},'revoked_principal':{'status':'REVOKED','revoked_at':NOW,'revocation_reference':ref(90)},'tenant_principal':{'tenant_id':UUID(int=99)}}[change]
            people=(actor.model_copy(update=updates),*snapshot.principals[1:])
        snapshot=snapshot.model_copy(update={'principals':people})
    if change in ('expired_assignment','revoked_assignment','expired_member','revoked_member'):
        name='assignments' if 'assignment' in change else 'memberships'
        old=getattr(snapshot,name)[0]
        update={'valid_until':NOW} if change.startswith('expired') else {'revoked_at':NOW,'revocation_reference':ref(90)}
        snapshot=snapshot.model_copy(update={name:(old.model_copy(update=update),)})
    if change=='missing_resource': snapshot=snapshot.model_copy(update={'resources':()})
    if change=='conflicting_scope': snapshot=snapshot.model_copy(update={'scopes':snapshot.scopes*2})
    bundle=bundle.model_copy(update={'snapshot':snapshot})
    if change=='missing_receipt': bundle=bundle.model_copy(update={'issuance_evidence':()})
    if change=='issuer_substitution':
        receipts=bundle.issuance_evidence
        bundle=bundle.model_copy(update={'issuance_evidence':(receipts[0].model_copy(update={'issuer_ref':ref(77)}),*receipts[1:])})
    assert run((auth,req,bundle,anchors)).status=='ADMISSION_DENIED'


@pytest.mark.parametrize('change',['missing','stale','future','revoked_actor','revoked_issuer','revoked_grant','duplicate'])
def test_current_revocation_evidence_is_required(change):
    auth,req,bundle,anchors=fixture(); state=bundle.revocations
    if change=='missing': state=None
    elif change=='stale': state=state.model_copy(update={'observed_at':NOW-timedelta(seconds=16)})
    elif change=='future': state=state.model_copy(update={'observed_at':NOW+timedelta(seconds=1)})
    elif change=='duplicate': state=state.model_copy(update={'revoked_refs':(ref(2),ref(2))})
    else: state=state.model_copy(update={'revoked_refs':(ref({'revoked_actor':2,'revoked_issuer':600,'revoked_grant':8}[change]),)})
    assert run((auth,req,bundle.model_copy(update={'revocations':state}),anchors)).status=='ADMISSION_DENIED'


@pytest.mark.parametrize('change',['future','expired','old','version','time','request','action','resource','tenant','policy','operation','team'])
def test_exact_snapshot_request_and_freshness_binding(change):
    auth,req,bundle,anchors=fixture()
    if change=='future': bundle=bundle.model_copy(update={'valid_from':NOW+timedelta(seconds=1)})
    if change=='expired': bundle=bundle.model_copy(update={'valid_until':NOW})
    if change=='old': bundle=bundle.model_copy(update={'valid_from':NOW-timedelta(seconds=61)})
    if change=='version': bundle=bundle.model_copy(update={'schema_version':'2.0'})
    if change=='time': bundle=bundle.model_copy(update={'evaluated_at':NOW-timedelta(seconds=1)})
    if change=='request': req=req.model_copy(update={'correlation_id':UUID(int=99)})
    if change=='action': req=req.model_copy(update={'action':'evidence.raw.read'})
    if change=='resource': req=req.model_copy(update={'resource_ref':ref(99)})
    if change=='tenant': req=req.model_copy(update={'resource_ref':ref(9,UUID(int=99))})
    if change=='policy': req=req.model_copy(update={'policy_version':'2.0'})
    if change=='operation': bundle=bundle.model_copy(update={'operation_sha256':'0'*64})
    if change=='team':
        resource=bundle.snapshot.resources[0].model_copy(update={'owning_team_ref':ref(99)})
        bundle=bundle.model_copy(update={'snapshot':bundle.snapshot.model_copy(update={'resources':(resource,)})})
    assert run((auth,req,bundle,anchors)).status=='ADMISSION_DENIED'


def test_admission_does_not_replace_policy_evaluation(monkeypatch):
    auth,req,bundle,anchors=fixture()
    deny_rules=bundle.policy.model_copy(update={'roles':tuple(r.model_copy(update={'actions':()}) for r in bundle.policy.roles)})
    result=run((auth,req,bundle.model_copy(update={'policy':deny_rules}),anchors))
    assert result.status=='POLICY_DENY' and result.admitted is not None
    calls=[]; original=policy.evaluate
    def counted(*a,**k): calls.append(True); return original(*a,**k)
    monkeypatch.setattr(policy,'evaluate',counted)
    assert run(fixture()).status=='POLICY_ALLOW' and len(calls)==1
    def broken(*a,**k): raise RuntimeError('secret-canary')
    monkeypatch.setattr(policy,'evaluate',broken)
    result=run(fixture())
    assert result.status=='ADMISSION_DENIED' and 'secret-canary' not in result.model_dump_json()


def test_immutability_canonical_audit_and_unregistered_sources():
    result=run(fixture())
    assert iam.canonical_bytes(result)==iam.canonical_bytes(run(fixture()))
    with pytest.raises(ValidationError): result.status='POLICY_ALLOW'
    assert 'key_hash' not in result.model_dump_json()
    assert admission.admit(fixture()[0],fixture()[1],authority=object(),at=NOW).status=='ADMISSION_DENIED'


def test_no_io_or_gateway_dispatch(monkeypatch):
    parts=fixture()
    from app.gateway import tool_gateway
    def forbidden(*a,**k): raise AssertionError('forbidden IO')
    for owner,name in ((builtins,'open'),(Path,'open'),(socket,'socket'),(socket,'create_connection'),
        (subprocess,'Popen'),(tool_gateway,'execute')): monkeypatch.setattr(owner,name,forbidden)
    original=builtins.__import__
    def guarded(name,*a,**k):
        if name.startswith(('sqlalchemy','psycopg','httpx','ollama')) or name in ('app.auth','app.iam.auth','app.db','app.config','app.core.config'):
            raise AssertionError('forbidden import')
        return original(name,*a,**k)
    monkeypatch.setattr(builtins,'__import__',guarded)
    assert run(parts).status=='POLICY_ALLOW'


def approval_fixture():
    from tests.iam.test_iam_policy import approved_scenario,issuances
    auth,req,base,anchors=fixture()
    args=approved_scenario(); snapshot=args['snapshot']
    people=list(snapshot.principals)
    actor=next(p for p in people if p.principal_id==UUID(int=2))
    from tests.iam.test_iam_contracts import principal
    actor=principal(2,'API_KEY_SERVICE').model_copy(update={'role_assignment_refs':actor.role_assignment_refs,
        'team_membership_refs':actor.team_membership_refs,
        'authentication':iam.AuthenticationReference(tenant_id=TENANT,reference_id=UUID(int=2),method='API_KEY')})
    people=[actor if p.principal_id==UUID(int=2) else p for p in people]
    scopes=tuple(s.model_copy(update={'actions':('tools.invoke.approved',),'resource_types':('tool',)}) for s in snapshot.scopes)
    scopes_by_id={s.scope_id:s for s in scopes}
    assignments=tuple(a.model_copy(update={'scope':scopes_by_id[a.scope.scope_id]}) for a in snapshot.assignments)
    resource=snapshot.resources[0].model_copy(update={'resource_type':'tool'})
    snapshot=snapshot.model_copy(update={'principals':tuple(people),'scopes':scopes,'assignments':assignments,'resources':(resource,)})
    req=req.model_copy(update={'action':'tools.invoke.approved','resource_type':'tool'})
    operation=args['approval'].operation.model_copy(update={'action':'tools.invoke.approved','resource':resource})
    approval=args['approval'].model_copy(update={'operation':operation,'operation_sha256':iam.contract_digest(operation),
        'resource_sha256':iam.contract_digest(resource)})
    bundle=base.model_copy(update={'snapshot':snapshot,'issuance_evidence':issuances(snapshot),'approval':approval,
        'request_sha256':iam.contract_digest(req),'operation_sha256':iam.contract_digest(operation)})
    anchors=tuple(a.model_copy(update={'record_types':(*a.record_types,'APPROVAL')}) if a.issuer_ref==ref(3) else a for a in anchors)
    anchors=(*anchors,admission.IssuerAuthority(tenant_id=TENANT,issuer_ref=ref(40),source_ref=ref(800),
        record_types=('ROLE_ASSIGNMENT','TEAM_MEMBERSHIP'),valid_from=NOW-timedelta(seconds=60),valid_until=NOW+timedelta(seconds=60)))
    return auth,req,bundle,anchors


@pytest.mark.parametrize('change',['valid','missing','untrusted_issuer','expired','revoked','other_operation','other_action','forged_flag'])
def test_human_approval_origin_validity_and_exact_operation(change):
    auth,req,bundle,anchors=approval_fixture(); approval=bundle.approval
    if change=='missing': approval=None
    if change=='untrusted_issuer':
        anchors=tuple(a.model_copy(update={'record_types':tuple(t for t in a.record_types if t!='APPROVAL')}) for a in anchors)
    if change=='expired': approval=approval.model_copy(update={'valid_until':NOW})
    if change=='revoked':
        bundle=bundle.model_copy(update={'revocations':bundle.revocations.model_copy(update={'revoked_refs':(ref(21),)})})
    if change in ('other_operation','other_action'):
        operation=approval.operation.model_copy(update={'operation_id':UUID(int=91)} if change=='other_operation' else {'action':'tools.propose'})
        approval=approval.model_copy(update={'operation':operation,'operation_sha256':iam.contract_digest(operation)})
    if change=='forged_flag': approval=approval.model_copy(update={'verified':True})
    result=run((auth,req,bundle.model_copy(update={'approval':approval}),anchors))
    assert result.status==('POLICY_ALLOW' if change=='valid' else ('POLICY_DENY' if change=='missing' else 'ADMISSION_DENIED'))


def test_origin_identity_is_not_replaced_by_equal_content_or_digest():
    auth,req,bundle,anchors=fixture()
    origins=admission.SyntheticOriginRegistry.for_tests((bundle,))
    copied=bundle.model_copy()
    assert iam.contract_digest(copied)==iam.contract_digest(bundle)
    source=admission.SyntheticAuthority.for_tests(auth,copied,anchors,origins)
    result=admission.admit(auth,req,authority=source,at=NOW)
    assert result.reason=='UNVERIFIED_ORIGIN'
    assert result.audit.correlation_id==req.correlation_id and result.audit.iam_decision is None


def test_unknown_verifier_and_clock_replay_deny():
    auth,req,bundle,anchors=fixture()
    assert run((auth,req,bundle.model_copy(update={'verifier_ref':ref(999)}),anchors)).status=='ADMISSION_DENIED'
    assert run((auth,req,bundle,anchors),at=NOW+timedelta(seconds=1)).status=='ADMISSION_DENIED'


def test_trust_configuration_is_explicit_and_no_model_fields_are_accepted():
    auth,req,bundle,anchors=fixture()
    with pytest.raises(ValueError): admission.SyntheticAuthority.for_tests(auth,bundle,anchors,object())
    with pytest.raises(ValueError): admission.SyntheticOriginRegistry.for_tests([bundle])
    result=run((auth,req.model_copy(update={'trusted_principal':ref(42)}),bundle,anchors))
    assert result.status=='ADMISSION_DENIED'
    assert result.audit.principal_id is None and result.audit.correlation_id is None


@pytest.mark.parametrize('change',['missing','inactive','revoked','expired','wrong_key','tenant'])
def test_current_api_key_record_is_separate_from_principal_status(change):
    auth,req,bundle,anchors=fixture(); state=bundle.api_key_state
    if change=='missing': state=None
    else:
        updates={'inactive':{'active':False},'revoked':{'revoked_at':NOW,'revocation_reference':ref(90)},
            'expired':{'valid_until':NOW},'wrong_key':{'api_key_id':UUID(int=42),'principal_ref':ref(42)},
            'tenant':{'tenant_id':UUID(int=99)}}[change]
        state=state.model_copy(update=updates)
    assert run((auth,req,bundle.model_copy(update={'api_key_state':state}),anchors)).status=='ADMISSION_DENIED'
