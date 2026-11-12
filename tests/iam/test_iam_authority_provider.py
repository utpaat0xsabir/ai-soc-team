"""IAM-03B synthetic authority conformance; all records are test-only."""
import builtins
from dataclasses import replace
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
from app.iam import authority_provider as providers
from tests.iam.test_iam_admission import fixture,approval_fixture
from tests.iam.test_iam_contracts import NOW,TENANT,ref

EPOCH=UUID(int=400)
PARTS=('tenant','api_key','principals','roles','memberships','resources','policy','revocations','issuance','approval')


def setup(parts=None):
    auth,request,bundle,anchors=fixture() if parts is None else parts
    response=providers.ProviderSnapshot(provider_id=UUID(int=300),read_epoch=EPOCH,
        component_epochs=tuple(providers.ComponentEpoch(component=name,epoch=EPOCH) for name in PARTS),
        state=fixture()[2]).model_copy(update={'state':bundle})
    source=providers.SyntheticProvider.for_tests(response)
    authority=providers.ProviderAuthority(tenant_id=TENANT,provider_id=UUID(int=300),source_ref=ref(800),
        record_types=('SNAPSHOT','VERIFIER','ROLE_ASSIGNMENT','TEAM_MEMBERSHIP','TEAM_SCOPE','APPROVAL'),
        valid_from=NOW-timedelta(seconds=60),valid_until=NOW+timedelta(seconds=60))
    origins=providers.SyntheticProviderOrigins.for_tests(source,(response,))
    registration=providers.ProviderRegistration(authority=authority,provider=source,authenticated=auth,
        issuer_authorities=anchors)
    return auth,request,response,source,registration,origins


def evaluate(data,*,registrations=None,origins=None,request=None,auth=None):
    identity,req,response,source,registration,origin=data
    bridge=providers.ProtectedAuthorityBridge.for_tests(
        (registration,) if registrations is None else registrations,(origin,) if origins is None else origins)
    return bridge.authorize(identity if auth is None else auth,req if request is None else request,at=NOW)


def test_valid_explicit_registered_provider_and_mapping():
    data=setup(); result=evaluate(data)
    assert result.status=='POLICY_ALLOW' and result.executable is False
    assert result.admitted.principal_ref==ref(2)
    assert data[3].reads==1 and data[3].epoch_checks==2


@pytest.mark.parametrize('change',['missing','unknown_provider','revoked','expired','tenant','record_scope','duplicate','conflicting_source','forged_provider_id'])
def test_provider_registration_is_independent_and_fail_closed(change):
    data=setup(); auth,req,response,source,registration,origin=data
    registrations=(registration,)
    if change=='missing': registrations=()
    elif change=='unknown_provider': registrations=(replace(registration,provider=object()),)
    elif change=='duplicate': registrations=(registration,registration)
    elif change=='conflicting_source':
        registrations=(registration,replace(registration,authority=registration.authority.model_copy(update={'provider_id':UUID(int=900)})))
    elif change=='forged_provider_id': source.response=response.model_copy(update={'provider_id':UUID(int=900)})
    else:
        updates={'revoked':{'revoked_at':NOW,'revocation_reference':ref(90)},'expired':{'valid_until':NOW},
            'tenant':{'tenant_id':UUID(int=99)},'record_scope':{'record_types':('APPROVAL',)}}[change]
        registrations=(replace(registration,authority=registration.authority.model_copy(update=updates)),)
    result=evaluate(data,registrations=registrations)
    assert result.status=='ADMISSION_DENIED'


@pytest.mark.parametrize('change',['copied_digest','forged_flags','forged_source','unregistered_origin','caller_identity'])
def test_metadata_and_identical_digest_do_not_authenticate_provider(change):
    data=setup(); auth,req,response,source,registration,origin=data
    if change=='copied_digest':
        source.response=response.model_copy()
        assert iam.contract_digest(source.response)==iam.contract_digest(response)
    if change=='forged_flags': source.response=response.model_copy(update={'verified':True})
    if change=='forged_source':
        source.response=response.model_copy(update={'state':response.state.model_copy(update={'source_ref':ref(999)})})
    if change=='unregistered_origin':
        assert evaluate(data,origins=()).status=='ADMISSION_DENIED'; return
    if change=='caller_identity':
        assert evaluate(data,auth=replace(auth)).status=='ADMISSION_DENIED'; return
    assert evaluate(data).status=='ADMISSION_DENIED'


@pytest.mark.parametrize('change',['api_revoked','api_tenant','inactive','tenant_inactive','missing_principal','duplicate_principal',
    'missing_assignment','expired_assignment','revoked_assignment','expired_member','cross_tenant_member','missing_resource',
    'classification','resource','action','operation','policy','issuer_revoked','approval_revoked','missing_approval','other_approval'])
def test_authoritative_state_conformance_uses_existing_admission(change):
    parts=approval_fixture() if change in ('approval_revoked','missing_approval','other_approval') else fixture()
    auth,req,bundle,anchors=parts; snapshot=bundle.snapshot
    if change=='api_revoked': bundle=bundle.model_copy(update={'api_key_state':bundle.api_key_state.model_copy(update={'revoked_at':NOW,'revocation_reference':ref(90)})})
    if change=='api_tenant': bundle=bundle.model_copy(update={'api_key_state':bundle.api_key_state.model_copy(update={'tenant_id':UUID(int=99)})})
    if change in ('inactive','missing_principal','duplicate_principal'):
        people=snapshot.principals
        if change=='inactive': people=(people[0].model_copy(update={'status':'SUSPENDED'}),*people[1:])
        elif change=='missing_principal': people=people[1:]
        else: people=(*people,people[0])
        snapshot=snapshot.model_copy(update={'principals':people})
    if change=='tenant_inactive': snapshot=snapshot.model_copy(update={'tenant':snapshot.tenant.model_copy(update={'status':'SUSPENDED'})})
    if change in ('missing_assignment','expired_assignment','revoked_assignment'):
        values=() if change=='missing_assignment' else (snapshot.assignments[0].model_copy(update=
            {'valid_until':NOW} if change=='expired_assignment' else {'revoked_at':NOW,'revocation_reference':ref(90)}),)
        snapshot=snapshot.model_copy(update={'assignments':values})
    if change in ('expired_member','cross_tenant_member'):
        snapshot=snapshot.model_copy(update={'memberships':(snapshot.memberships[0].model_copy(update=
            {'valid_until':NOW} if change=='expired_member' else {'tenant_id':UUID(int=99)}),)})
    if change=='missing_resource': snapshot=snapshot.model_copy(update={'resources':()})
    if change=='classification': snapshot=snapshot.model_copy(update={'resources':(snapshot.resources[0].model_copy(update={'classification':'PUBLIC'}),)})
    if change=='resource': req=req.model_copy(update={'resource_ref':ref(99)})
    if change=='action': req=req.model_copy(update={'action':'evidence.raw.read'})
    if change=='operation': bundle=bundle.model_copy(update={'operation_sha256':'0'*64})
    if change=='policy': req=req.model_copy(update={'policy_version':'2.0'})
    if change=='issuer_revoked': anchors=(anchors[0].model_copy(update={'revoked_at':NOW,'revocation_reference':ref(90)}),*anchors[1:])
    if change=='approval_revoked': bundle=bundle.model_copy(update={'revocations':bundle.revocations.model_copy(update={'revoked_refs':(ref(21),)})})
    if change=='missing_approval': bundle=bundle.model_copy(update={'approval':None})
    if change=='other_approval':
        operation=bundle.approval.operation.model_copy(update={'operation_id':UUID(int=99)})
        bundle=bundle.model_copy(update={'approval':bundle.approval.model_copy(update={'operation':operation,'operation_sha256':iam.contract_digest(operation)})})
    bundle=bundle.model_copy(update={'snapshot':snapshot})
    result=evaluate(setup((auth,req,bundle,anchors)))
    assert result.status==('POLICY_DENY' if change=='missing_approval' else 'ADMISSION_DENIED')


@pytest.mark.parametrize('change',['mixed','missing_component','duplicate_component','stale_snapshot','stale_revocation','future',
    'race_before','race_after','failure','timeout','policy_replacement','revocation_conflict'])
def test_consistency_freshness_and_state_changes(change):
    auth,req,bundle,anchors=fixture()
    if change=='stale_snapshot': bundle=bundle.model_copy(update={'valid_until':NOW})
    if change=='stale_revocation': bundle=bundle.model_copy(update={'revocations':bundle.revocations.model_copy(update={'observed_at':NOW-timedelta(seconds=16)})})
    if change=='future': bundle=bundle.model_copy(update={'evaluated_at':NOW+timedelta(seconds=1)})
    if change=='revocation_conflict': bundle=bundle.model_copy(update={'revocations':bundle.revocations.model_copy(update={'revoked_refs':(ref(2),ref(2))})})
    data=setup((auth,req,bundle,anchors)); response,source=data[2:4]
    if change in ('mixed','missing_component','duplicate_component'):
        epochs=response.component_epochs
        if change=='mixed': epochs=(epochs[0].model_copy(update={'epoch':UUID(int=99)}),*epochs[1:])
        if change=='missing_component': epochs=epochs[1:]
        if change=='duplicate_component': epochs=(*epochs,epochs[0])
        source.response=response.model_copy(update={'component_epochs':epochs})
        origin=providers.SyntheticProviderOrigins.for_tests(source,(source.response,))
        data=(*data[:5],origin)
    if change in ('race_before','race_after','policy_replacement'):
        source.epochs=(UUID(int=99),) if change=='race_before' else (EPOCH,UUID(int=99))
    if change=='failure': source.failure='FAILURE'
    if change=='timeout': source.failure='TIMEOUT'
    assert evaluate(data).status=='ADMISSION_DENIED'


def test_admission_and_policy_cannot_be_bypassed(monkeypatch):
    data=setup(); calls=[]; original=admission.admit
    def observed(*a,**k): calls.append('admission'); return original(*a,**k)
    monkeypatch.setattr(admission,'admit',observed)
    original_policy=policy.evaluate
    def observed_policy(*a,**k): calls.append('policy'); return original_policy(*a,**k)
    monkeypatch.setattr(policy,'evaluate',observed_policy)
    assert evaluate(data).status=='POLICY_ALLOW' and calls==['admission','policy']
    def denied(*a,**k): raise RuntimeError('secret-canary')
    monkeypatch.setattr(admission,'admit',denied)
    result=evaluate(data)
    assert result.status=='ADMISSION_DENIED' and 'secret-canary' not in result.model_dump_json()


def test_admission_success_can_have_policy_denial():
    auth,req,bundle,anchors=fixture()
    rules=bundle.policy.model_copy(update={'roles':tuple(r.model_copy(update={'actions':()}) for r in bundle.policy.roles)})
    result=evaluate(setup((auth,req,bundle.model_copy(update={'policy':rules}),anchors)))
    assert result.status=='POLICY_DENY' and result.admitted is not None


def test_immutable_deterministic_audit_and_no_caller_provider_selector():
    first=evaluate(setup()); second=evaluate(setup())
    assert iam.canonical_bytes(first)==iam.canonical_bytes(second)
    with pytest.raises(ValidationError): first.status='POLICY_DENY'
    data=setup(); bridge=providers.ProtectedAuthorityBridge.for_tests((data[4],),(data[5],))
    with pytest.raises(TypeError): bridge.authorize(data[0],data[1],at=NOW,provider_id=UUID(int=300))
    assert first.audit.principal_id==UUID(int=2) and first.audit.snapshot_sha256 is not None


def test_no_network_database_filesystem_subprocess_or_gateway(monkeypatch):
    data=setup()
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
    assert evaluate(data).status=='POLICY_ALLOW'


@pytest.mark.parametrize('change',['principal_revoked','membership_revoked','provider_revoked_state','unsupported_version','model_provider_field'])
def test_revoked_state_and_model_override_never_yield_allow(change):
    auth,req,bundle,anchors=fixture()
    if change in ('principal_revoked','membership_revoked','provider_revoked_state'):
        target={'principal_revoked':2,'membership_revoked':5,'provider_revoked_state':300}[change]
        bundle=bundle.model_copy(update={'revocations':bundle.revocations.model_copy(update={'revoked_refs':(ref(target),)})})
    data=setup((auth,req,bundle,anchors))
    if change=='unsupported_version':
        source=data[3]; source.response=data[2].model_copy(update={'schema_version':'2.0'})
        data=(*data[:5],providers.SyntheticProviderOrigins.for_tests(source,(source.response,)))
    if change=='model_provider_field':
        req=req.model_copy(update={'provider_id':UUID(int=300),'verified':True})
    assert evaluate(data,request=req).status=='ADMISSION_DENIED'


def test_untrusted_provider_denies_before_retrieval_or_policy(monkeypatch):
    data=setup()
    def forbidden(*a,**k): raise AssertionError('must not reach admission')
    monkeypatch.setattr(admission,'admit',forbidden)
    assert evaluate(data,registrations=()).status=='ADMISSION_DENIED'
    assert data[3].reads==0


def test_configuration_bounds_and_response_immutability():
    data=setup()
    with pytest.raises(ValueError): providers.ProtectedAuthorityBridge.for_tests([data[4]],(data[5],))
    with pytest.raises(ValueError): providers.SyntheticProviderOrigins.for_tests(data[3],[data[2]])
    with pytest.raises(ValidationError): data[2].read_epoch=UUID(int=99)
    with pytest.raises(ValidationError): data[4].authority.record_types=('SNAPSHOT',)


def test_provider_snapshot_is_never_accepted_without_admission_policy_decision(monkeypatch):
    data=setup()
    monkeypatch.setattr(admission,'admit',lambda *a,**k:data[2])
    assert evaluate(data).status=='ADMISSION_DENIED'
