"""Offline SQL compilation and fake-session tests; no database URLs or engines."""
import builtins
from datetime import timedelta
import importlib
from pathlib import Path
import socket
import subprocess
from uuid import UUID

import pytest
import sqlalchemy
from sqlalchemy.dialects import postgresql
from app.iam import contracts as iam
from app.iam import authority_provider as providers
from app.iam import postgres_authority as postgres
from app.gateway.contracts import TrustedContext
from tests.iam.test_iam_contracts import NOW,TENANT,ref
from tests.iam.test_iam_admission import fixture
from tests.iam.test_iam_authority_provider import setup


class FakeResult:
    def __init__(self,rows,session): self.rows=rows; self.session=session
    def mappings(self): return self
    def fetchmany(self,size):
        assert size==2
        self.session.fetch_sizes.append(size)
        return self.rows[:size]


class FakeSession:
    def __init__(self):
        self.rows=([{'id':TENANT}],[{'id':UUID(int=2),'tenant_id':TENANT,'revoked_at':None}])
        self.statements=[]; self.fetch_sizes=[]; self.rollbacks=0; self.observations=0
        self.failure=None; self.rollback_failure=False
        self.forbidden_calls=[]
        self.observation=postgres.TransactionObservation(transaction_id=UUID(int=50),read_epoch=UUID(int=51),
            source_ref=ref(800),evaluated_at=NOW,observed_at=NOW,read_only=True,isolation='REPEATABLE READ')
        self.after=None
    def observe_transaction(self):
        self.observations+=1
        if self.failure=='observation': raise RuntimeError('secret-canary')
        return self.after if self.after is not None and self.observations>1 else self.observation
    def execute(self,statement):
        if self.failure=='execute': raise ConnectionError('secret-canary')
        assert statement.is_select
        index=len(self.statements); self.statements.append(statement)
        return FakeResult(self.rows[index],self)
    def rollback(self):
        self.rollbacks+=1
        if self.rollback_failure: raise RuntimeError('secret-canary')
    def __getattr__(self,name):
        if name in ('commit','flush','add','add_all','delete','merge','connection','get_bind','close'):
            self.forbidden_calls.append(name)
            raise AssertionError('forbidden database method')
        raise AttributeError(name)


def provider(session=None):
    auth,request,_,_=fixture(); session=FakeSession() if session is None else session
    instance=postgres.PostgresAuthorityProvider(session=session,authenticated=auth,
        context=TrustedContext(tenant_id=TENANT,principal_id=UUID(int=2)),source_ref=ref(800))
    return instance,auth,request,session


def denied(instance,auth,request):
    with pytest.raises(postgres.AuthorityReadError) as error: instance.read(auth,request,at=NOW)
    assert 'secret-canary' not in str(error.value)
    return error.value.code


def test_consistent_fake_session_maps_existing_models_but_never_fabricates_iam():
    instance,auth,request,session=provider()
    assert denied(instance,auth,request)=='SCHEMA_INCOMPLETE'
    assert len(session.statements)==2 and session.rollbacks==1
    assert instance.is_current(UUID(int=51)) is False


@pytest.mark.parametrize('gap',[
    'tenant_status','principal_state','role_assignments','team_memberships','team_status',
    'resource_classification','resource_assignment','issuer_authority','approval_state',
    'policy_version','revocation_state'])
def test_each_missing_authority_category_is_an_explicit_blocker(gap):
    instance,auth,request,_=provider()
    assert gap in postgres.SCHEMA_GAPS
    assert denied(instance,auth,request)=='SCHEMA_INCOMPLETE'


def test_missing_session_and_forged_authentication_fail_before_queries():
    instance,auth,request,session=provider()
    assert denied(postgres.PostgresAuthorityProvider(session=None,authenticated=auth,
        context=instance.context,source_ref=ref(800)),auth,request)=='SESSION_UNAVAILABLE'
    assert denied(instance,object(),request)=='IDENTITY_MISMATCH'
    assert not session.statements and not session.rollbacks


@pytest.mark.parametrize('change',['tenant_missing','tenant_duplicate','tenant_wrong','tenant_unknown_field','key_missing',
    'key_duplicate','key_wrong_tenant','key_wrong_principal','key_revoked','key_unknown_field','key_forged_issuer','key_verified_flag'])
def test_bounded_existing_records_cannot_supply_untrusted_iam(change):
    instance,auth,request,session=provider(); tenants,keys=session.rows
    if change=='tenant_missing': tenants=[]
    if change=='tenant_duplicate': tenants=tenants*2
    if change=='tenant_wrong': tenants=[{'id':UUID(int=99)}]
    if change=='tenant_unknown_field': tenants=[dict(tenants[0],is_active=True)]
    if change=='key_missing': keys=[]
    if change=='key_duplicate': keys=keys*2
    if change=='key_wrong_tenant': keys=[dict(keys[0],tenant_id=UUID(int=99))]
    if change=='key_wrong_principal': keys=[dict(keys[0],id=UUID(int=99))]
    if change=='key_revoked': keys=[dict(keys[0],revoked_at=NOW)]
    if change=='key_unknown_field': keys=[dict(keys[0],roles=['org_admin'])]
    if change=='key_forged_issuer': keys=[dict(keys[0],issuer='trusted')]
    if change=='key_verified_flag': keys=[dict(keys[0],verified=True)]
    session.rows=tenants,keys
    assert denied(instance,auth,request) in ('IDENTITY_MISMATCH','RECORDS_INVALID')
    assert session.rollbacks==1


def test_queries_are_exact_bounded_read_only_and_secret_free():
    instance,auth,request,session=provider(); denied(instance,auth,request)
    compiled=[s.compile(dialect=postgresql.dialect()) for s in session.statements]
    assert 'tenants.id =' in str(compiled[0])
    assert 'tenant_api_keys.tenant_id =' in str(compiled[1]) and 'tenant_api_keys.id =' in str(compiled[1])
    for statement in compiled:
        assert str(statement).startswith('SELECT ') and 'LIMIT ' in str(statement)
        assert 'key_hash' not in str(statement) and 'payload' not in str(statement)
        assert TENANT in statement.params.values() and 2 in statement.params.values()
    assert session.fetch_sizes==[2,2]


@pytest.mark.parametrize('change',['resource_tenant','executor','context_tenant','model_override'])
def test_trusted_tenant_and_principal_are_never_taken_from_request(change):
    instance,auth,request,session=provider()
    if change=='resource_tenant': request=request.model_copy(update={'resource_ref':ref(9,UUID(int=99))})
    if change=='executor': request=request.model_copy(update={'executor_ref':ref(99)})
    if change=='context_tenant': instance=postgres.PostgresAuthorityProvider(session=session,authenticated=auth,
        context=TrustedContext(tenant_id=UUID(int=99),principal_id=UUID(int=2)),source_ref=ref(800,UUID(int=99)))
    if change=='model_override': request=request.model_copy(update={'principal_id':UUID(int=99),'verified':True})
    assert denied(instance,auth,request) in ('IDENTITY_MISMATCH','INVALID_REQUEST')
    assert not session.statements


@pytest.mark.parametrize('change',['write_transaction','wrong_isolation','stale','future','wrong_source','wrong_time',
    'mixed_epoch','mixed_transaction','revocation_race','connection_failure','observation_failure','rollback_failure'])
def test_transaction_consistency_and_failure_cleanup(change):
    instance,auth,request,session=provider(); obs=session.observation
    if change in ('write_transaction','wrong_isolation','stale','future','wrong_source','wrong_time'):
        changes={'write_transaction':{'read_only':False},'wrong_isolation':{'isolation':'READ COMMITTED'},
            'stale':{'observed_at':NOW-timedelta(seconds=16)},'future':{'observed_at':NOW+timedelta(seconds=1)},
            'wrong_source':{'source_ref':ref(999)},'wrong_time':{'evaluated_at':NOW-timedelta(seconds=1)}}[change]
        session.observation=obs.model_copy(update=changes)
    if change in ('mixed_epoch','mixed_transaction','revocation_race'):
        session.after=obs.model_copy(update={'transaction_id':UUID(int=99)} if change=='mixed_transaction' else {'read_epoch':UUID(int=99)})
    if change=='connection_failure': session.failure='execute'
    if change=='observation_failure': session.failure='observation'
    if change=='rollback_failure': session.rollback_failure=True
    assert denied(instance,auth,request) in ('TRANSACTION_UNVERIFIED','READ_FAILED','CLEANUP_FAILED')
    assert session.rollbacks==1


def test_iam03b_cannot_activate_provider_or_fallback_to_synthetic(monkeypatch):
    instance,auth,request,session=provider(); data=setup()
    from dataclasses import replace
    registration=replace(data[4],provider=instance,authenticated=auth)
    bridge=providers.ProtectedAuthorityBridge.for_tests((registration,),())
    def forbidden(*a,**k): raise AssertionError('no synthetic fallback')
    monkeypatch.setattr(providers.SyntheticProvider,'for_tests',forbidden)
    result=bridge.authorize(auth,request,at=NOW)
    assert result.status=='ADMISSION_DENIED' and result.policy_decision is None
    assert not session.statements


def test_no_import_time_or_runtime_connection_filesystem_network_subprocess(monkeypatch):
    import sqlalchemy.orm
    import sqlalchemy.engine
    def forbidden(*a,**k): raise AssertionError('forbidden IO')
    guards=((builtins,'open'),(Path,'open'),(socket,'socket'),(socket,'create_connection'),
        (subprocess,'Popen'),(sqlalchemy,'create_engine'),(sqlalchemy.orm,'sessionmaker'),
        (sqlalchemy.engine.Engine,'connect'))
    for owner,name in guards: monkeypatch.setattr(owner,name,forbidden)
    for owner,name in guards:
        with pytest.raises(AssertionError,match='forbidden IO'):
            getattr(owner,name)()
    original=builtins.__import__
    def guarded(name,*a,**k):
        if name in ('app.db','app.config','app.core.config','app.auth','app.iam.auth') or name.startswith(('psycopg','httpx','ollama')):
            raise AssertionError('forbidden import')
        return original(name,*a,**k)
    monkeypatch.setattr(builtins,'__import__',guarded)
    importlib.reload(postgres)
    # Reload replaces strict contract classes; build observations from the current class.
    instance,auth,request,session=provider()
    assert denied(instance,auth,request)=='SCHEMA_INCOMPLETE'


@pytest.mark.parametrize('field,value',[
    ('action','*'),('action','roles.*'),('action','evidence.unknown'),
    ('policy_version','0.0'),('policy_version','2.0')])
def test_unsupported_request_metadata_is_rejected_without_session_side_effects(field,value):
    instance,auth,request,session=provider()
    request=request.model_copy(update={field:value})
    assert denied(instance,auth,request)=='INVALID_REQUEST'
    assert not session.statements and not session.observations and not session.rollbacks
    assert not session.forbidden_calls


@pytest.mark.parametrize('field',['tenant_id','api_key_id'])
@pytest.mark.parametrize('value',[None,'not-a-uuid',1])
def test_invalid_authenticated_identifiers_never_reach_session(field,value):
    from dataclasses import replace
    instance,auth,request,session=provider()
    invalid=replace(auth,**{field:value})
    instance=replace(instance,authenticated=invalid)
    assert denied(instance,invalid,request)=='IDENTITY_MISMATCH'
    assert not session.statements and not session.observations and not session.rollbacks


@pytest.mark.parametrize('change',['missing_observation','missing_revision','invalid_revision','missing_source',
    'missing_time','missing_isolation','missing_read_only','numeric_read_only','claimed_issuer','claimed_provenance'])
def test_incomplete_or_claimed_transaction_authority_has_exact_denial(change):
    instance,auth,request,session=provider()
    changes={'missing_revision':{'read_epoch':None},'invalid_revision':{'read_epoch':'not-a-revision'},
        'missing_source':{'source_ref':None},'missing_time':{'observed_at':None},
        'missing_isolation':{'isolation':None},'missing_read_only':{'read_only':None},
        'numeric_read_only':{'read_only':1},'claimed_issuer':{'issuer_ref':ref(600)},
        'claimed_provenance':{'provenance':'verified'}}
    session.observation=None if change=='missing_observation' else session.observation.model_copy(update=changes[change])
    assert denied(instance,auth,request)=='TRANSACTION_UNVERIFIED'
    assert not session.statements and session.rollbacks==1 and not session.forbidden_calls


@pytest.mark.parametrize('shape',['none','dict','generator','scalar_row','nonmapping_row','missing_field','invalid_uuid'])
def test_unexpected_query_shapes_have_exact_denial_and_cleanup(monkeypatch,shape):
    instance,auth,request,session=provider()
    class KeyedNonMapping:
        def __iter__(self): return iter(('id',))
        def __getitem__(self,key): return TENANT
    shapes={'none':None,'dict':{'id':TENANT},'generator':iter(({'id':TENANT},)),
        'scalar_row':[TENANT],'nonmapping_row':[KeyedNonMapping()],
        'missing_field':[{}],'invalid_uuid':[{'id':str(TENANT)}]}
    tenant_rows=session.rows[0]
    monkeypatch.setattr(FakeResult,'fetchmany',
        lambda self,size:shapes[shape] if self.rows is tenant_rows else self.rows[:size])
    assert denied(instance,auth,request)=='RECORDS_INVALID'
    assert session.rollbacks==1 and not session.forbidden_calls


def test_real_sqlalchemy_row_mappings_remain_supported_without_connections():
    from sqlalchemy.engine import Row
    from sqlalchemy.engine.result import SimpleResultMetaData
    instance,auth,request,session=provider()
    tenant=Row(SimpleResultMetaData(['id']),None,{'id':0},(TENANT,))._mapping
    key=Row(SimpleResultMetaData(['id','tenant_id','revoked_at']),None,
        {'id':0,'tenant_id':1,'revoked_at':2},(UUID(int=2),TENANT,None))._mapping
    session.rows=([tenant],[key])
    assert denied(instance,auth,request)=='SCHEMA_INCOMPLETE'
    assert session.rollbacks==1 and not session.forbidden_calls


@pytest.mark.parametrize('field',['issuer_ref','provenance','authority_revision','assignments','snapshot'])
def test_identity_rows_cannot_smuggle_authority_or_revision(field):
    instance,auth,request,session=provider()
    tenant,keys=session.rows
    session.rows=(tenant,[dict(keys[0],**{field:'fabricated'})])
    assert denied(instance,auth,request)=='RECORDS_INVALID'
    assert session.rollbacks==1 and not session.forbidden_calls


@pytest.mark.parametrize('gap',['authority_provenance','authority_revision'])
def test_production_provenance_and_revision_remain_explicit_schema_blockers(gap):
    instance,auth,request,session=provider()
    assert gap in postgres.SCHEMA_GAPS
    assert denied(instance,auth,request)=='SCHEMA_INCOMPLETE'
    assert session.rollbacks==1 and not session.forbidden_calls


@pytest.mark.parametrize('epoch',[None,'fabricated',UUID(int=0),UUID(int=51)])
def test_currency_always_denies_without_touching_session(epoch):
    instance,_,_,session=provider()
    assert instance.is_current(epoch) is False
    assert not session.statements and not session.observations and not session.rollbacks


@pytest.mark.parametrize('failure,rollback_failure,reason',[
    (None,False,'SCHEMA_INCOMPLETE'),('execute',False,'READ_FAILED'),
    ('observation',False,'TRANSACTION_UNVERIFIED'),('execute',True,'CLEANUP_FAILED')])
def test_repeated_denials_are_deterministic_and_preserve_dedicated_cleanup(failure,rollback_failure,reason):
    codes=[]
    for _ in range(2):
        instance,auth,request,session=provider()
        session.failure=failure; session.rollback_failure=rollback_failure
        codes.append(denied(instance,auth,request))
        assert session.rollbacks==1 and not session.forbidden_calls
    assert codes==[reason,reason]
