"""AI-04A: synthetic inference only; deterministic clock and cancellation."""
import builtins
from datetime import timedelta
import json
from pathlib import Path
import socket
import subprocess

import pytest
from pydantic import ValidationError

from app.analysts import inference as inference
from app.analysts import evaluation as evaluation
from tests.analysts.test_analyst_contracts import NOW
from tests.analysts.test_analyst_protocol import fixture


def configuration():
    endpoint=inference.EndpointPolicy(endpoint_id='fake-endpoint',runtime_id='fake',location='IN_PROCESS',approved=True)
    model=inference.ModelDescriptor(model_id='synthetic-a',family='synthetic-family',runtime_id='fake',
        endpoint_id=endpoint.endpoint_id,artifact_identity='synthetic-fixture-v1',
        deployment='LOCAL_SELF_HOSTED',capabilities=('CHAT','JSON_SCHEMA','STREAMING'),
        max_context_tokens=65536,max_output_tokens=8192,memory_mib=128,cpu_ms=1000,
        approval='DEVELOPMENT_APPROVED',evaluation='OFFLINE_SYNTHETIC',
        token_accounting='SYNTHETIC_UTF8_BYTES_V1')
    registry=inference.ModelRegistry(models=(model,),endpoints=(endpoint,))
    profiles=tuple(inference.AnalystModelProfile(tier=tier,model_id=model.model_id,
        configuration_version=1,max_context_tokens=65536,max_output_tokens=8192,
        temperature=0.0,request_timeout_ms=1000,overall_deadline_ms=2000,
        max_concurrent_requests=1,streaming=True,max_input_bytes=65536,
        max_output_bytes=8192,max_chunks=8) for tier in ('L1','L2','L3'))
    return inference.InferenceConfiguration(registry=registry,profiles=profiles)


def setup(tier='L1'):
    context,task,snapshot,package,response=fixture(tier)
    provider=inference.FakeModelProvider(steps=(inference.FakeStep(data=response,final=True),))
    return dict(context=context,task=task,snapshot=snapshot,package=package,
        configuration=configuration(),provider=provider,
        admission=inference.AdmissionController(),control=inference.InferenceControl(now=lambda:NOW))


def request(args):
    return inference.prepare_request(args['context'],args['task'],args['snapshot'],args['package'],
                                     args['configuration'],at=NOW)


@pytest.mark.parametrize('tier',['L1','L2','L3'])
def test_valid_fake_inference_preserves_analyst_validators(tier):
    args=setup(tier); result=inference.run_inference(**args)
    assert result.status=='COMPLETED' and result.executable is False
    assert result.parsed.evaluation.outcome=='VALID'
    assert result.classification=='SYNTHETIC / TEST ONLY'
    assert args['provider'].calls==1 and args['admission'].in_flight==0


@pytest.mark.parametrize('field,value',[
    ('deployment','CLOUD'),('schema_version','2.0'),('max_context_tokens',0),
    ('capabilities',('CHAT','CHAT')),('runtime_id','https://cloud.invalid'),
    ('max_output_tokens',999999),('production_approved',True)])
def test_invalid_model_contracts(field,value):
    data=configuration().registry.models[0].model_dump(); data[field]=value
    with pytest.raises(ValueError): inference.ModelDescriptor.model_validate(data)


@pytest.mark.parametrize('kind',['duplicate','unapproved','unevaluated','capabilities','endpoint','profile','version'])
def test_registry_and_profile_conflicts_fail_closed(kind):
    args=setup(); config=args['configuration']; model=config.registry.models[0]
    if kind=='duplicate': registry=config.registry.model_copy(update={'models':(model,model)})
    else:
        changes={'unapproved':{'approval':'UNAPPROVED'},'unevaluated':{'evaluation':'UNEVALUATED'},
            'capabilities':{'capabilities':('CHAT',)},'endpoint':{'endpoint_id':'unknown'}}.get(kind,{})
        registry=config.registry.model_copy(update={'models':(model.model_copy(update=changes),)})
    profiles=config.profiles
    if kind=='profile': profiles=(profiles[0],profiles[0],profiles[2])
    args['configuration']=config.model_copy(update={'registry':registry,'profiles':profiles})
    if kind=='version': args['configuration']=config.model_copy(update={'schema_version':'9.0'})
    assert inference.run_inference(**args).status=='DENIED'
    assert args['provider'].calls==0


@pytest.mark.parametrize('changes',[
    {'host':'example.invalid','port':11434,'scheme':'http','location':'LOOPBACK'},
    {'host':'127.0.0.1','port':11434,'scheme':'ftp','location':'LOOPBACK'},
    {'redirects':True},{'ambient_proxy':True},{'dns_substitution':True},
    {'url':'http://user:password@example.invalid'}, {'location':'CLOUD'}])
def test_endpoint_policy_rejects_unsafe_destinations(changes):
    data=configuration().registry.endpoints[0].model_dump(); data.update(changes)
    with pytest.raises(ValueError): inference.EndpointPolicy.model_validate(data)


def test_proposed_loopback_policy_never_enables_a_live_provider():
    args=setup(); config=args['configuration']
    endpoint=inference.EndpointPolicy(endpoint_id='ollama-dev',runtime_id='ollama',location='LOOPBACK',
        host='127.0.0.1',port=11434,scheme='http',approved=True)
    model=config.registry.models[0].model_copy(update={'runtime_id':'ollama','endpoint_id':endpoint.endpoint_id})
    args['configuration']=config.model_copy(update={'registry':inference.ModelRegistry(models=(model,),endpoints=(endpoint,))})
    result=inference.run_inference(**args)
    assert result.status=='DENIED' and args['provider'].calls==0


def test_independent_model_selection_and_deterministic_request_binding():
    args=setup('L2'); config=args['configuration']; first=config.registry.models[0]
    second=first.model_copy(update={'model_id':'other-family-model','family':'different-family','artifact_identity':'other-fixture-v1'})
    profiles=tuple(profile.model_copy(update={'model_id':second.model_id}) if profile.tier=='L2'
                   else profile for profile in config.profiles)
    args['configuration']=inference.InferenceConfiguration(
        registry=inference.ModelRegistry(models=(first,second),endpoints=config.registry.endpoints),profiles=profiles)
    prepared=request(args)
    assert prepared.model.model_id=='other-family-model'
    assert prepared.request_id==request(args).request_id
    assert prepared.request_sha256==request(args).request_sha256
    assert inference.run_inference(**args).status=='COMPLETED'
    with pytest.raises(ValidationError): profiles[0].temperature=1.0


@pytest.mark.parametrize('field,value',[
    ('model_id','unknown'),('model_id','https://cloud.invalid'),('max_input_bytes',100),
    ('max_context_tokens',100),('max_output_tokens',1),('max_output_bytes',512),
    ('configuration_version',0),('temperature',float('nan'))])
def test_model_injection_and_profile_limits(field,value):
    args=setup(); config=args['configuration']
    args['configuration']=config.model_copy(update={'profiles':(
        config.profiles[0].model_copy(update={field:value}),*config.profiles[1:])})
    assert inference.run_inference(**args).status in ('DENIED','FAILED')


@pytest.mark.parametrize('fault',['WRONG_REQUEST','WRONG_SNAPSHOT','MODEL_FALLBACK','CHUNK_HASH','SEQUENCE','MALFORMED'])
def test_provider_binding_and_malformed_frames(fault):
    args=setup(); args['provider']=args['provider'].model_copy(update={'fault':fault})
    result=inference.run_inference(**args)
    assert result.status=='DENIED' and result.parsed is None
    assert args['admission'].in_flight==0


@pytest.mark.parametrize('kind',['invalid_json','wrong_task','fake_citation','contradiction','escalation','grants','unsupported_claim','model_override'])
def test_fake_output_cannot_bypass_ai03_and_ai02(kind):
    args=setup(); data=json.loads(args['provider'].steps[0].data)
    if kind=='wrong_task': data['result']['task_id']='00000000-0000-0000-0000-000000000099'
    if kind=='fake_citation': data['citations'][0]['content_sha256']='0'*64
    if kind=='contradiction': data['claims'][0]['value']='192.0.2.99'
    if kind=='escalation': data['result']['escalation']='L3'
    if kind=='grants': data['result']['grants']=['all']
    if kind=='unsupported_claim': data['claims'][0]['kind']='VERIFIED_THREAT'
    if kind=='model_override': data['model_id']='unregistered-provider'
    raw=b'not-json' if kind=='invalid_json' else json.dumps(data).encode()
    args['provider']=inference.FakeModelProvider(steps=(inference.FakeStep(data=raw,final=True),))
    result=inference.run_inference(**args)
    assert result.status=='DENIED' and result.reason=='MODEL_OUTPUT_REJECTED'
    assert result.parsed.status in ('MALFORMED','REJECTED')


def test_complete_stream_and_no_acceptance_of_partial_or_extra_chunks():
    args=setup(); raw=args['provider'].steps[0].data
    args['provider']=inference.FakeModelProvider(steps=(
        inference.FakeStep(data=raw[:80]),inference.FakeStep(data=raw[80:],final=True)))
    assert inference.run_inference(**args).status=='COMPLETED'
    for steps in ((inference.FakeStep(data=raw),),
        (inference.FakeStep(data=raw,final=True),inference.FakeStep(data=b'',final=True))):
        args['provider']=inference.FakeModelProvider(steps=steps)
        assert inference.run_inference(**args).status=='DENIED'


@pytest.mark.parametrize('kind',['bytes','chunks','streaming_disabled'])
def test_stream_budgets(kind):
    args=setup()
    if kind=='bytes': steps=(inference.FakeStep(data=b'x'*8193,final=True),)
    else: steps=tuple(inference.FakeStep(data=b'x',final=i==8) for i in range(9))
    if kind=='streaming_disabled':
        config=args['configuration']; args['configuration']=config.model_copy(update={'profiles':(
            config.profiles[0].model_copy(update={'streaming':False}),*config.profiles[1:])})
    args['provider']=inference.FakeModelProvider(steps=steps)
    assert inference.run_inference(**args).status=='DENIED'


@pytest.mark.parametrize('event,status',[('FAILURE','FAILED'),('CANCEL','CANCELLED')])
def test_provider_failures_are_sanitized_and_slots_released(event,status):
    args=setup(); args['provider']=inference.FakeModelProvider(steps=(inference.FakeStep(event=event),))
    result=inference.run_inference(**args)
    assert result.status==status and 'canary' not in result.model_dump_json()
    assert args['provider'].calls==1
    assert args['admission'].in_flight==0


def test_timeout_deadline_and_cancellation_before_acceptance():
    args=setup(); step=args['provider'].steps[0].model_copy(update={'elapsed_ms':1001})
    args['provider']=inference.FakeModelProvider(steps=(step,))
    assert inference.run_inference(**args).status=='TIMED_OUT'
    args=setup(); args['control']=inference.InferenceControl(now=lambda:NOW,cancelled=lambda:True)
    assert inference.run_inference(**args).status=='CANCELLED' and args['provider'].calls==0
    args=setup(); calls=0
    def cancel_later():
        nonlocal calls
        calls+=1
        return calls>=5
    args['control']=inference.InferenceControl(now=lambda:NOW,cancelled=cancel_later)
    assert inference.run_inference(**args).status=='CANCELLED'


def test_concurrency_limit_and_request_isolation():
    args=setup(); prepared=request(args)
    assert args['admission'].acquire(prepared)
    assert not args['admission'].acquire(prepared)
    assert inference.run_inference(**args).status=='BUSY' and args['provider'].calls==0
    args['admission'].release(prepared)
    assert inference.run_inference(**args).status=='COMPLETED'


def test_wrong_tenant_and_forged_configuration_deny_before_provider():
    args=setup(); args['context']=args['context'].model_copy(update={'principal_id':args['task'].task_id})
    assert inference.run_inference(**args).status=='DENIED' and args['provider'].calls==0
    args=setup(); args['configuration']=args['configuration'].model_copy(update={'provider_url':'https://cloud.invalid'})
    assert inference.run_inference(**args).status=='DENIED' and args['provider'].calls==0


def test_forbidden_io_live_models_and_gateway(monkeypatch):
    args=setup()
    from app.gateway import tool_gateway
    import httpx
    def forbidden(*args,**kwargs): raise AssertionError('forbidden I/O')
    original_import=builtins.__import__
    def restricted(name,*args,**kwargs):
        if name.startswith(('sqlalchemy','psycopg','ollama','vllm')) or name in ('app.db','app.config','app.core.config'):
            raise AssertionError('forbidden import')
        return original_import(name,*args,**kwargs)
    for owner,name in ((builtins,'open'),(Path,'open'),(socket,'socket'),(socket,'create_connection'),
        (subprocess,'Popen'),(httpx.Client,'send'),(tool_gateway,'execute')):
        monkeypatch.setattr(owner,name,forbidden)
    monkeypatch.setattr(builtins,'__import__',restricted)
    assert inference.run_inference(**args).status=='COMPLETED'


@pytest.mark.parametrize('times,expected',[
    ((0,-1),'DENIED'), ((0,0,0,0,1500),'TIMED_OUT'),
    ((0,0,0,0,0,2500),'TIMED_OUT')])
def test_clock_rollback_provider_timeout_and_post_parse_deadline(times,expected):
    args=setup(); readings=iter(times)
    last=times[-1]
    args['control']=inference.InferenceControl(now=lambda:NOW+timedelta(milliseconds=next(readings,last)))
    result=inference.run_inference(**args)
    assert result.status==expected and result.parsed is None
    assert args['admission'].in_flight==0


def test_task_deadline_is_an_upper_bound_on_profile_deadline():
    args=setup(); args['task']=args['task'].model_copy(update={'deadline':NOW+timedelta(milliseconds=500)})
    args['package']=evaluation.assemble_input(args['context'],args['task'],args['snapshot'],at=NOW)
    prepared=request(args)
    assert prepared.deadline_at==args['task'].deadline
    step=args['provider'].steps[0].model_copy(update={'elapsed_ms':501})
    args['provider']=inference.FakeModelProvider(steps=(step,))
    assert inference.run_inference(**args).status=='TIMED_OUT'


@pytest.mark.parametrize('changes',[{'schema_version':'2.0'},{'temperature':float('inf')},
    {'request_timeout_ms':3000},{'max_concurrent_requests':0},{'structured_output':'text'},
    {'streaming':'yes'},{'provider_url':'https://cloud.invalid'}])
def test_bad_profile_versions_and_resources_deny_without_invocation(changes):
    args=setup(); config=args['configuration']
    args['configuration']=config.model_copy(update={'profiles':(
        config.profiles[0].model_copy(update=changes),*config.profiles[1:])})
    assert inference.run_inference(**args).status=='DENIED' and args['provider'].calls==0


def test_unknown_token_accounting_cannot_authorize_context_size():
    args=setup(); config=args['configuration']
    model=config.registry.models[0].model_copy(update={'token_accounting':'UNVERIFIED'})
    args['configuration']=config.model_copy(update={'registry':config.registry.model_copy(update={'models':(model,)})})
    assert inference.run_inference(**args).status=='DENIED' and args['provider'].calls==0


def test_model_artifact_aliases_cannot_bypass_registry_identity():
    config=configuration(); model=config.registry.models[0]
    with pytest.raises(ValueError):
        inference.ModelRegistry(models=(model,model.model_copy(update={'model_id':'alias'})),endpoints=config.registry.endpoints)


def test_global_capacity_and_per_model_admission_are_shared_across_tiers():
    first=setup('L1'); other=setup('L2'); gate=inference.AdmissionController(max_in_flight=1)
    first['admission']=other['admission']=gate
    held=request(first)
    assert gate.acquire(held)
    assert inference.run_inference(**other).status=='BUSY'
    assert other['provider'].calls==0 and gate.in_flight==1
    forged=held.model_copy(update={'request_sha256':'0'*64})
    with pytest.raises(ValueError): gate.release(forged)
    assert gate.in_flight==1
    gate.release(held)
    assert inference.run_inference(**other).status=='COMPLETED'


def test_more_permissive_profile_does_not_override_an_active_lower_limit():
    first=setup('L1'); other=setup('L2'); gate=first['admission']; other['admission']=gate
    config=other['configuration']
    other['configuration']=config.model_copy(update={'profiles':(
        config.profiles[0],config.profiles[1].model_copy(update={'max_concurrent_requests':4}),config.profiles[2])})
    held=request(first); assert gate.acquire(held)
    assert inference.run_inference(**other).status=='BUSY'
    gate.release(held)
    assert inference.run_inference(**other).status=='COMPLETED'


def test_concurrency_two_slots_accept_exactly_two_distinct_requests():
    args=setup(); config=args['configuration']
    args['configuration']=config.model_copy(update={'profiles':(
        config.profiles[0].model_copy(update={'max_concurrent_requests':2}),*config.profiles[1:])})
    prepared=[]
    for millis in (0,1,2):
        prepared.append(inference.prepare_request(args['context'],args['task'],args['snapshot'],args['package'],
            args['configuration'],at=NOW+timedelta(milliseconds=millis)))
    gate=args['admission']
    assert gate.acquire(prepared[0]) and gate.acquire(prepared[1])
    assert not gate.acquire(prepared[2]) and gate.in_flight==2
    gate.release(prepared[0]); gate.release(prepared[1])
    assert gate.in_flight==0


def test_arbitrary_provider_implementations_are_not_executed():
    args=setup()
    class Unsafe:
        def generate(self,request): raise AssertionError('must not execute')
    args['provider']=Unsafe()
    result=inference.run_inference(**args)
    assert result.reason=='UNSUPPORTED_PROVIDER'


@pytest.mark.parametrize('patch',[{'request_sha256':'0'*64},{'tier':'L3'},
    {'snapshot_sha256':'0'*64},{'executable':True},{'schema_version':'2.0'}])
def test_inference_request_is_immutable_and_tamper_evident(patch):
    prepared=request(setup()); data=prepared.model_dump(); data.update(patch)
    with pytest.raises(ValueError): inference.InferenceRequest.model_validate(data)


def test_configuration_versions_are_part_of_request_identity():
    args=setup(); first=request(args); config=args['configuration']
    args['configuration']=config.model_copy(update={'profiles':(
        config.profiles[0].model_copy(update={'configuration_version':2}),*config.profiles[1:])})
    assert request(args).request_id!=first.request_id
    with pytest.raises(ValidationError): first.model.model_id='override'


def test_unknown_or_synthetic_to_live_label_from_model_is_rejected():
    args=setup(); data=json.loads(args['provider'].steps[0].data)
    data['result']['classification']='OBSERVED'
    args['provider']=inference.FakeModelProvider(steps=(inference.FakeStep(data=json.dumps(data).encode(),final=True),))
    result=inference.run_inference(**args)
    assert result.status=='DENIED' and result.classification=='SYNTHETIC / TEST ONLY'


def test_interpretive_output_is_a_completed_proposal_requiring_review():
    args=setup(); data=json.loads(args['provider'].steps[0].data)
    data['result']['observations'][0]['text']='Unverified threat intelligence hypothesis'
    args['provider']=inference.FakeModelProvider(steps=(inference.FakeStep(data=json.dumps(data).encode(),final=True),))
    result=inference.run_inference(**args)
    assert result.status=='COMPLETED' and result.parsed.evaluation.outcome=='REQUIRES_HUMAN_REVIEW'


def test_tiny_result_budget_uses_sanitized_exception_after_slot_release():
    args=setup(); args['task']=args['task'].model_copy(update={'max_output_bytes':1})
    args['package']=evaluation.assemble_input(args['context'],args['task'],args['snapshot'],at=NOW)
    with pytest.raises(ValueError,match='invalid_inference_result_budget'):
        inference.run_inference(**args)
    assert args['admission'].in_flight==0


@pytest.mark.parametrize('status,reason', [('COMPLETED','CAPACITY'),('FAILED','ACCEPTED_PROPOSAL'),
    ('BUSY','DEADLINE'),('TIMED_OUT','PROVIDER_FAILURE')])
def test_contradictory_result_contracts_are_rejected(status,reason):
    with pytest.raises(ValueError):
        inference.InferenceResult(status=status,reason=reason,request_id=None,request_sha256=None)


def test_cancellation_after_cleanup_still_prevents_acceptance():
    args=setup(); calls=0
    def cancelled():
        nonlocal calls
        calls+=1
        return calls>=6
    args['control']=inference.InferenceControl(now=lambda:NOW,cancelled=cancelled)
    result=inference.run_inference(**args)
    assert result.status=='CANCELLED' and result.parsed is None
    assert args['admission'].in_flight==0 and args['provider'].calls==1


def test_unapproved_endpoint_denies_without_provider_invocation():
    args=setup(); config=args['configuration']; registry=config.registry
    endpoint=registry.endpoints[0].model_copy(update={'approved':False})
    args['configuration']=config.model_copy(update={'registry':registry.model_copy(update={'endpoints':(endpoint,)})})
    assert inference.run_inference(**args).status=='DENIED' and args['provider'].calls==0


@pytest.mark.parametrize('value',['synthetic-secret-canary',None,False,-1])
def test_malformed_task_budget_is_never_trusted_for_result_serialization(value):
    args=setup(); args['task']=args['task'].model_copy(update={'max_output_bytes':value})
    result=inference.run_inference(**args)
    assert result.status=='DENIED' and result.reason=='INVALID_INPUT'
    assert args['provider'].calls==0 and 'canary' not in result.model_dump_json()
