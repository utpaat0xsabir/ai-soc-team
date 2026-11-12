"""AI-04B-1: every HTTP response is injected, synthetic and offline."""
import builtins
from datetime import timedelta
import json
from pathlib import Path
import socket
import subprocess

import httpx
import pytest

from app.analysts import inference as inference
from app.analysts.providers.ollama import MockedOllamaProvider
from tests.analysts.test_analyst_contracts import NOW
from tests.analysts.test_analyst_inference import setup as fake_setup


def setup(tier='L1',edit=None,status=200):
    args=fake_setup(tier); raw=args['provider'].steps[0].data.decode()
    config=args['configuration']; endpoint=inference.EndpointPolicy(endpoint_id='ollama-test',runtime_id='ollama',
        location='LOOPBACK',host='127.0.0.1',port=11434,scheme='http',approved=True)
    model=config.registry.models[0].model_copy(update={'model_id':'qwen2.5:1.5b','runtime_id':'ollama',
        'endpoint_id':endpoint.endpoint_id,'artifact_sha256':'1'*64,'artifact_identity':'synthetic-digest-fixture',
        'token_accounting':'ESTIMATED_BYTES_PER4_V1'})
    profiles=tuple(profile.model_copy(update={'model_id':model.model_id,'streaming':False,
        'max_context_tokens':8192,'max_output_tokens':512,'temperature':0.1}) for profile in config.profiles)
    args['configuration']=inference.InferenceConfiguration(
        registry=inference.ModelRegistry(models=(model,),endpoints=(endpoint,)),profiles=profiles)
    calls=[]
    def handler(request):
        calls.append(request)
        body={'model':model.model_id,'created_at':NOW.isoformat(),'done':True,'done_reason':'stop',
            'message':{'role':'assistant','content':raw},'prompt_eval_count':500,'eval_count':400}
        if edit: edit(body)
        return httpx.Response(status,json=body)
    args['provider']=MockedOllamaProvider(httpx.MockTransport(handler),args['control'])
    return args,calls


@pytest.mark.parametrize('tier',['L1','L2','L3'])
def test_valid_mock_request_and_exact_message_mapping(tier):
    args,calls=setup(tier); result=inference.run_inference(**args)
    assert result.status=='COMPLETED' and result.parsed.evaluation.outcome=='VALID'
    assert result.executable is False and len(calls)==1 and args['admission'].in_flight==0
    sent=calls[0]; body=json.loads(sent.content)
    assert str(sent.url)=='http://127.0.0.1:11434/api/chat'
    assert body['model']=='qwen2.5:1.5b' and body['stream'] is False
    assert 'tools' not in body and body['format']['additionalProperties'] is False
    assert body['options']=={'temperature':0.1,'num_ctx':8192,'num_predict':512}
    assert [message['role'] for message in body['messages']]==['system','user']
    assert sent.extensions['timeout']['connect']>0


@pytest.mark.parametrize('patch',[
    {'done':False},{'done_reason':'length'},{'model':'unapproved-fallback'},
    {'tool_calls':[]},{'message':{'role':'assistant','content':'{}','tool_calls':[]}},
    {'eval_count':513},{'prompt_eval_count':8192},{'created_at':'not-a-time'},
    {'message':{'role':'system','content':'{}'}},{'message':{'role':'assistant','content':'x'*8193}},
    {'extra_authority':True}])
def test_unexpected_incomplete_or_unsafe_wire_response(patch):
    args,calls=setup(edit=lambda body:body.update(patch))
    result=inference.run_inference(**args)
    assert result.status=='DENIED' and len(calls)==1 and result.parsed is None
    assert args['admission'].in_flight==0


@pytest.mark.parametrize('status',[301,302,307,400,401,404,429,500])
def test_http_status_never_retries_or_redirects(status):
    args,calls=setup(status=status)
    assert inference.run_inference(**args).status in ('FAILED','DENIED')
    assert len(calls)==1 and args['admission'].in_flight==0


@pytest.mark.parametrize('host',['localhost','127.0.0.2','192.0.2.1','::ffff:127.0.0.1','example.invalid'])
def test_endpoint_substitution_denied_before_transport(host):
    args,calls=setup(); config=args['configuration']; registry=config.registry
    endpoint=registry.endpoints[0].model_copy(update={'host':host})
    args['configuration']=config.model_copy(update={'registry':registry.model_copy(update={'endpoints':(endpoint,)})})
    assert inference.run_inference(**args).status=='DENIED' and not calls


def test_no_default_transport_or_transport_subclass():
    with pytest.raises(ValueError): MockedOllamaProvider(None,inference.InferenceControl(now=lambda:NOW))
    class Pretend(httpx.MockTransport): pass
    with pytest.raises(ValueError): MockedOllamaProvider(Pretend(lambda _:httpx.Response(200)),inference.InferenceControl(now=lambda:NOW))


@pytest.mark.parametrize('raw',[b'{',b'{}{}',b'{"model":"a","model":"b"}',
    b'{"message":{"content":"a","content":"b"}}',b'\xff',b'x'*65537])
def test_strict_bounded_http_envelope(raw):
    args,_=setup()
    args['provider']=MockedOllamaProvider(httpx.MockTransport(lambda _:httpx.Response(200,
        content=raw,headers={'content-type':'application/json'})),args['control'])
    assert inference.run_inference(**args).status=='DENIED'


@pytest.mark.parametrize('error',[httpx.ReadTimeout,httpx.ConnectTimeout,httpx.WriteTimeout,httpx.ConnectError])
def test_transport_failure_redaction_and_release(error):
    args,_=setup(); calls=[]
    def fail(request):
        calls.append(request)
        raise error('synthetic-secret-canary')
    args['provider']=MockedOllamaProvider(httpx.MockTransport(fail),args['control'])
    result=inference.run_inference(**args)
    assert result.status in ('TIMED_OUT','FAILED') and len(calls)==1
    assert 'canary' not in result.model_dump_json() and args['admission'].in_flight==0


@pytest.mark.parametrize('kind',['wrong_task','grant','citation','contradiction','missing_support'])
def test_mandatory_analyst_validation(kind):
    def edit(body):
        value=json.loads(body['message']['content'])
        if kind=='wrong_task': value['result']['task_id']='00000000-0000-0000-0000-000000000099'
        if kind=='grant': value['result']['grants']=['all']
        if kind=='citation': value['citations'][0]['content_sha256']='0'*64
        if kind=='contradiction': value['claims'][0]['value']='192.0.2.99'
        if kind=='missing_support': value['claims'][0].update(kind='FIELD_EQUALS',field='rule.id',value='not-supplied')
        body['message']['content']=json.dumps(value)
    args,calls=setup(edit=edit)
    assert inference.run_inference(**args).status=='DENIED' and len(calls)==1


def test_cancellation_capacity_and_timeouts_before_http():
    args,calls=setup(); args['control']=inference.InferenceControl(now=lambda:NOW,cancelled=lambda:True)
    args['provider']=MockedOllamaProvider(args['provider'].transport,args['control'])
    assert inference.run_inference(**args).status=='CANCELLED' and not calls
    args,calls=setup(); prepared=inference.prepare_request(args['context'],args['task'],args['snapshot'],args['package'],args['configuration'],at=NOW)
    assert args['admission'].acquire(prepared)
    assert inference.run_inference(**args).status=='BUSY' and not calls
    args['admission'].release(prepared)


def test_missing_artifact_and_streaming_profile_are_not_dispatchable():
    for kind in ('artifact','streaming'):
        args,calls=setup(); config=args['configuration']
        if kind=='artifact':
            model=config.registry.models[0].model_copy(update={'artifact_sha256':None})
            config=config.model_copy(update={'registry':config.registry.model_copy(update={'models':(model,)})})
        else: config=config.model_copy(update={'profiles':tuple(p.model_copy(update={'streaming':True}) for p in config.profiles)})
        args['configuration']=config
        assert inference.run_inference(**args).status=='DENIED' and not calls


def test_no_network_files_database_models_or_gateway(monkeypatch):
    args,calls=setup()
    from app.gateway import tool_gateway
    def forbidden(*args,**kwargs): raise AssertionError('forbidden access')
    original=builtins.__import__
    def restricted(name,*args,**kwargs):
        if name.startswith(('ollama','vllm','psycopg','sqlalchemy')) or name in ('app.db','app.config','app.core.config'):
            raise AssertionError('forbidden import')
        return original(name,*args,**kwargs)
    for owner,name in ((builtins,'open'),(Path,'open'),(socket,'socket'),(socket,'create_connection'),
        (subprocess,'Popen'),(tool_gateway,'execute'),(httpx.HTTPTransport,'handle_request'),
        (httpx.HTTPTransport,'__init__')):
        monkeypatch.setattr(owner,name,forbidden)
    monkeypatch.setattr(builtins,'__import__',restricted)
    assert inference.run_inference(**args).status=='COMPLETED' and len(calls)==1


def test_client_proxy_redirect_and_hook_controls(monkeypatch):
    args,calls=setup(); original=httpx.Client
    def checked_client(*positional,**kwargs):
        assert kwargs['trust_env'] is False and kwargs['follow_redirects'] is False
        assert kwargs['event_hooks']=={} and type(kwargs['transport']) is httpx.MockTransport
        timeout=kwargs['timeout']
        assert all(0<value<=1 for value in (timeout.connect,timeout.read,timeout.write,timeout.pool))
        return original(*positional,**kwargs)
    monkeypatch.setattr(httpx,'Client',checked_client)
    assert inference.run_inference(**args).status=='COMPLETED' and len(calls)==1


def test_redirect_location_is_never_followed():
    args,_=setup(); calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(302,headers={'location':'https://external.invalid/steal'})
    args['provider']=MockedOllamaProvider(httpx.MockTransport(handler),args['control'])
    assert inference.run_inference(**args).status=='FAILED' and len(calls)==1


@pytest.mark.parametrize('headers',[
    {'content-type':'text/plain'}, {'content-type':'application/json','content-encoding':'gzip'},
    {'content-type':'application/json','content-length':'65537'},
    {'content-type':'application/json','content-length':'1'},
    {'content-type':'application/json','content-length':'-1'},
    {'content-type':'application/json','transfer-encoding':'unknown'},
    {'content-type':'application/json','x-padding':'x'*8193},
    {'content-type':'application/json','content-length':'2','transfer-encoding':'chunked'}])
def test_unsafe_headers_fail_closed(headers):
    args,_=setup()
    args['provider']=MockedOllamaProvider(httpx.MockTransport(lambda _:httpx.Response(200,
        stream=httpx.ByteStream(b'{}'),headers=headers)),args['control'])
    assert inference.run_inference(**args).status=='DENIED'


def test_endpoint_ipv6_and_independent_model_profiles():
    args,calls=setup('L2'); config=args['configuration']; registry=config.registry
    endpoint=registry.endpoints[0].model_copy(update={'host':'::1'})
    second=registry.models[0].model_copy(update={'model_id':'different-family:local','family':'other',
        'artifact_identity':'other-synthetic-fixture','artifact_sha256':'2'*64})
    profiles=tuple(p.model_copy(update={'model_id':second.model_id}) if p.tier=='L2' else p for p in config.profiles)
    args['configuration']=inference.InferenceConfiguration(registry=inference.ModelRegistry(
        models=(registry.models[0],second),endpoints=(endpoint,)),profiles=profiles)
    # Reuse the synthetic fixture response with only its exact configured model changed.
    response=json.loads(args['provider'].transport.handle_request(httpx.Request('POST','http://127.0.0.1/')).content)
    response['model']=second.model_id; sent=[]
    def handler(request):
        sent.append(request)
        return httpx.Response(200,json=response)
    args['provider']=MockedOllamaProvider(httpx.MockTransport(handler),args['control'])
    assert inference.run_inference(**args).status=='COMPLETED'
    assert str(sent[0].url)=='http://[::1]:11434/api/chat'
    assert json.loads(sent[0].content)['model']==second.model_id


def test_proposed_2048_context_is_not_silently_raised():
    args,calls=setup(); config=args['configuration']
    args['configuration']=config.model_copy(update={'profiles':tuple(p.model_copy(update={'max_context_tokens':2048}) for p in config.profiles)})
    assert inference.run_inference(**args).status=='DENIED' and not calls


def test_cancellation_or_elapsed_deadline_during_mock_response():
    for expired in (False,True):
        args,_=setup(); state={'after':False}
        control=inference.InferenceControl(now=lambda:NOW+timedelta(seconds=3 if state['after'] and expired else 0),
            cancelled=lambda:state['after'] and not expired)
        original=args['provider'].transport
        def handler(request):
            response=original.handle_request(request)
            state['after']=True
            return response
        args['control']=control; args['provider']=MockedOllamaProvider(httpx.MockTransport(handler),control)
        result=inference.run_inference(**args)
        assert result.status==('TIMED_OUT' if expired else 'CANCELLED')
        assert result.parsed is None and args['admission'].in_flight==0


def test_prompt_and_model_response_are_not_logged(caplog):
    args,_=setup()
    with caplog.at_level('DEBUG'):
        result=inference.run_inference(**args)
    assert result.status=='COMPLETED'
    assert 'synthetic alert' not in caplog.text and 'EVIDENCE_LINKED' not in caplog.text
