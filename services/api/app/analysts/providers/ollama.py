"""AI-04B-1: Ollama chat wire adapter; exact injected MockTransport only.

No default/live transport, probing, model discovery, fallback, tools or retries.
This is wire-format verification, not evidence of installed runtime compatibility.
"""
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
from typing import Annotated, Literal

import httpx
from pydantic import Field, field_validator

from app.analysts import contracts as ai
from app.analysts import inference as inference
from app.analysts import protocol as protocol
from app.analysts import evaluation as evaluation
from app.gateway.contracts import _Contract
from app.analysts.providers.ollama_prompt import ACCOUNTING_VERSION, build_chat_body, optimize_prompt


MAX_WIRE_BYTES = 65536
MAX_HEADER_BYTES = 8192
Count = Annotated[int, Field(ge=0,le=2**63-1)]


class _Message(_Contract):
    role: Literal['assistant']
    content: Annotated[str, Field(min_length=1,max_length=16384)]


class _Response(_Contract):
    model: inference.Identifier
    created_at: str
    message: _Message
    done: Literal[True]
    done_reason: Literal['stop']
    prompt_eval_count: Count
    eval_count: Count
    total_duration: Count | None = None
    load_duration: Count | None = None
    prompt_eval_duration: Count | None = None
    eval_duration: Count | None = None

    @field_validator('created_at')
    @classmethod
    def aware_time(cls,value):
        if len(value)>64:
            raise ValueError('invalid_provider_time')
        ai._utc(datetime.fromisoformat(value.replace('Z','+00:00')))
        return value


@dataclass(frozen=True)
class MockedOllamaProvider:
    transport: httpx.MockTransport
    control: inference.InferenceControl
    _calls: int = field(default=0,init=False,repr=False,compare=False)

    def __post_init__(self):
        if type(self.transport) is not httpx.MockTransport or type(self.control) is not inference.InferenceControl:
            raise ValueError('mock_transport_required')

    @property
    def calls(self):
        return self._calls

    def validate_request(self,request):
        if type(self.transport) is not httpx.MockTransport:
            raise inference._Stop('DENIED','UNSUPPORTED_PROVIDER')
        return _validate_request(request)

    def generate(self,request):
        yield from _generate_chat(self,request)


def _validate_request(request):
    request = inference._trusted(request,inference.InferenceRequest)
    endpoint,model,profile = request.endpoint,request.model,request.profile
    if (model.runtime_id!='ollama'
            or endpoint.location!='LOOPBACK' or endpoint.runtime_id!='ollama' or not endpoint.approved
            or endpoint.host not in ('127.0.0.1','::1') or endpoint.scheme not in ('http','https')
            or endpoint.redirects or endpoint.ambient_proxy or endpoint.dns_substitution
            or model.artifact_sha256 is None or model.approval!='DEVELOPMENT_APPROVED'
            or model.evaluation!='OFFLINE_SYNTHETIC' or profile.streaming
            or model.token_accounting not in ('ESTIMATED_BYTES_PER4_V1',ACCOUNTING_VERSION)):
        raise inference._Stop('DENIED','UNSUPPORTED_PROVIDER')
    return request



def _generate_chat(self,request):
    request = self.validate_request(request)
    last = request.created_at
    def remaining():
        nonlocal last
        now = ai._utc(self.control.now())
        cancelled = self.control.cancelled()
        if now<last or type(cancelled) is not bool:
            raise inference._Stop('DENIED','INVALID_INPUT')
        last = now
        if cancelled:
            raise inference._Stop('CANCELLED','CANCELLED')
        seconds = (min(request.timeout_at,request.deadline_at)-now).total_seconds()
        if seconds<=0:
            raise inference._Stop('TIMED_OUT','DEADLINE')
        return seconds
    remaining()
    if request.model.token_accounting==ACCOUNTING_VERSION:
        plan = optimize_prompt(request)
        if not plan.context_fits:
            raise inference._Stop('DENIED','LIMIT_EXCEEDED')
        encoded = plan.wire_json.encode('ascii')
    else:
        encoded = evaluation._bytes(build_chat_body(request))
        if (len(encoded)>request.profile.max_input_bytes
                or (len(encoded)+3)//4+request.profile.max_output_tokens>request.profile.max_context_tokens):
            raise inference._Stop('DENIED','LIMIT_EXCEEDED')
    host = '['+request.endpoint.host+']' if request.endpoint.host=='::1' else request.endpoint.host
    url = f'{request.endpoint.scheme}://{host}:{request.endpoint.port}/api/chat'
    timeout = httpx.Timeout(remaining())
    object.__setattr__(self,'_calls',self._calls+1)
    try:
        # Explicit MockTransport is mandatory; never construct HTTPTransport.
        with httpx.Client(transport=self.transport,trust_env=False,follow_redirects=False,
                          timeout=timeout,event_hooks={}) as client:
            with client.stream('POST',url,content=encoded,headers={
                    'content-type':'application/json','accept':'application/json','accept-encoding':'identity'}) as response:
                remaining()
                if response.status_code!=200:
                    raise inference._Stop('FAILED','PROVIDER_FAILURE')
                if (sum(len(k)+len(v) for k,v in response.headers.raw)>MAX_HEADER_BYTES
                        or response.headers.get('content-type','').split(';')[0].strip().lower()!='application/json'
                        or response.headers.get('content-encoding','identity').lower()!='identity'
                        or response.headers.get('transfer-encoding','chunked').lower()!='chunked'):
                    raise inference._Stop('DENIED','INVALID_STREAM')
                declared = response.headers.get('content-length')
                if declared is not None:
                    if not declared.isascii() or not declared.isdecimal() or 'transfer-encoding' in response.headers:
                        raise inference._Stop('DENIED','INVALID_STREAM')
                    declared = int(declared)
                    if declared>MAX_WIRE_BYTES:
                        raise inference._Stop('DENIED','LIMIT_EXCEEDED')
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=4096):
                    remaining()
                    if len(raw)+len(chunk)>MAX_WIRE_BYTES:
                        raise inference._Stop('DENIED','LIMIT_EXCEEDED')
                    raw.extend(chunk)
                if declared is not None and declared!=len(raw):
                    raise inference._Stop('DENIED','INVALID_STREAM')
                remaining()
        value = protocol._strict_json(bytes(raw),MAX_WIRE_BYTES,string_limit=16384,allow_text_whitespace=True)
        if type(value) is not dict:
            raise ValueError()
        # Provider wire fields have no version tag; never accept injected ones.
        if 'schema_version' in value or type(value.get('message')) is not dict or 'schema_version' in value['message']:
            raise ValueError()
        decoded = _Response.model_validate(value)
        if decoded.model!=request.model.model_id:
            raise inference._Stop('DENIED','BINDING_MISMATCH')
        if (decoded.eval_count>request.profile.max_output_tokens
                or decoded.prompt_eval_count+request.profile.max_output_tokens>request.profile.max_context_tokens):
            raise inference._Stop('DENIED','LIMIT_EXCEEDED')
        output = decoded.message.content.encode('utf-8',errors='strict')
        if len(output)>request.profile.max_output_bytes:
            raise inference._Stop('DENIED','LIMIT_EXCEEDED')
        remaining()
        digest = hashlib.sha256(output).hexdigest()
        yield inference.ProviderFrame(request_id=request.request_id,request_sha256=request.request_sha256,
            snapshot_sha256=request.snapshot_sha256,model_id=request.model.model_id,runtime_id='ollama',
            index=0,data=output,chunk_sha256=digest,stream_sha256=digest,final=True)
    except inference._Stop:
        raise
    except httpx.TimeoutException:
        raise inference._Stop('TIMED_OUT','DEADLINE') from None
    except httpx.HTTPError:
        raise inference._Stop('FAILED','PROVIDER_FAILURE') from None
    except Exception:
        raise inference._Stop('DENIED','INVALID_STREAM') from None
