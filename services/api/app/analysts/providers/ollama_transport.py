"""Live-capable HTTP mechanics behind an unimplemented operational authority gate.

No capability issuer exists. The ordinary analyst pipeline does not admit this
provider. Only the explicitly injected MockTransport branch is testable here.
"""
from dataclasses import dataclass, field
import math

import httpx

from app.analysts import inference as inference
from app.analysts.providers.ollama import _generate_chat, _validate_request, MAX_HEADER_BYTES, MAX_WIRE_BYTES


def _require_operational_clearance(capability,request):
    # No sentinel, bool, model/JSON claim, env flag or Python object is authority.
    # A future issuer/verifier requires separate implementation and approval.
    raise ValueError('live_ollama_transport_disabled')


def _destination(request):
    url = request.url
    if (request.method!='POST' or url.scheme!='http' or url.host!='127.0.0.1'
            or url.port!=11434 or url.raw_path!=b'/api/chat' or url.fragment
            or url.username or url.password):
        raise ValueError('invalid_live_ollama_destination')
    if (len(request.content)>65536 or sum(len(k)+len(v) for k,v in request.headers.raw)>MAX_HEADER_BYTES
            or any(name in request.headers for name in ('authorization','proxy-authorization','cookie'))):
        raise ValueError('invalid_live_ollama_request')
    limits = request.extensions.get('timeout')
    if (type(limits) is not dict or set(limits)!={'connect','read','write','pool'}
            or any(type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=60
                   for value in limits.values())):
        raise ValueError('invalid_live_ollama_timeout')


class _ClosingStream(httpx.SyncByteStream):
    def __init__(self,stream,transport):
        self._stream,self._transport = stream,transport
        self._closed = False

    def __iter__(self):
        size = 0
        for chunk in self._stream:
            if type(chunk) is not bytes or size+len(chunk)>MAX_WIRE_BYTES:
                self.close()
                raise httpx.TransportError('ollama_response_limit')
            size += len(chunk)
            yield chunk

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self._stream.close()
            finally:
                self._transport.close()


@dataclass(frozen=True)
class GatedOllamaTransport(httpx.BaseTransport):
    capability: object = field(default=None,repr=False)
    _mock: httpx.MockTransport | None = field(default=None,init=False,repr=False)

    @classmethod
    def offline(cls,mock):
        if type(mock) is not httpx.MockTransport:
            raise ValueError('mock_transport_required')
        instance = cls()
        object.__setattr__(instance,'_mock',mock)
        return instance

    def handle_request(self,request):
        _destination(request)
        if self._mock is None:
            # Denies before HTTPTransport construction, TLS, DNS or any socket.
            _require_operational_clearance(self.capability,request)
            transport = httpx.HTTPTransport(retries=0,trust_env=False,
                limits=httpx.Limits(max_connections=1,max_keepalive_connections=0))
        elif type(self._mock) is httpx.MockTransport:
            transport = self._mock
        else:
            raise ValueError('mock_transport_required')
        response = None
        try:
            response = transport.handle_request(request)
            if (300<=response.status_code<400
                    or sum(len(k)+len(v) for k,v in response.headers.raw)>MAX_HEADER_BYTES):
                raise httpx.TransportError('ollama_response_rejected')
            response.stream = _ClosingStream(response.stream,transport)
            return response
        except Exception as error:
            try:
                if response is not None:
                    response.close()
            finally:
                transport.close()
            if isinstance(error,httpx.TimeoutException):
                raise httpx.TimeoutException('ollama_transport_timeout') from None
            raise httpx.TransportError('ollama_transport_failure') from None


@dataclass(frozen=True)
class GatedLiveOllamaProvider:
    control: inference.InferenceControl
    capability: object = field(default=None,repr=False)
    transport: GatedOllamaTransport = field(init=False,repr=False)
    _calls: int = field(default=0,init=False,repr=False,compare=False)

    def __post_init__(self):
        if type(self.control) is not inference.InferenceControl:
            raise ValueError('invalid_inference_control')
        object.__setattr__(self,'transport',GatedOllamaTransport(self.capability))

    @classmethod
    def offline(cls,mock,control):
        instance = cls(control=control)
        object.__setattr__(instance,'transport',GatedOllamaTransport.offline(mock))
        return instance

    @property
    def calls(self):
        return self._calls

    def validate_request(self,request):
        request = _validate_request(request)
        if (request.endpoint.host,request.endpoint.port,request.endpoint.scheme)!=('127.0.0.1',11434,'http'):
            raise ValueError('invalid_live_ollama_destination')
        if request.profile.max_concurrent_requests!=1 or type(self.transport) is not GatedOllamaTransport:
            raise ValueError('invalid_live_ollama_policy')
        if self.transport._mock is None:
            _require_operational_clearance(self.capability,request)
        return request

    def generate(self,request):
        yield from _generate_chat(self,request)
