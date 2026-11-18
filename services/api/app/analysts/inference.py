"""AI-04A: model-independent contracts, closed fake transport, no live inference.

All configuration/control/admission inputs are application-owned. There is no
Settings import, environment lookup, adapter discovery, network or model loading.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from threading import Lock
from typing import Annotated, Callable, Iterator, Literal, Protocol
from uuid import UUID, uuid5

from pydantic import Field, PrivateAttr, model_validator

from app.analysts import contracts as ai
from app.analysts import evaluation as evaluation
from app.analysts import protocol as protocol
from app.gateway.contracts import _Contract, TrustedContext


Identifier = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_.:-]{0,95}$')]
Positive = Annotated[int, Field(ge=1, le=131072)]
NAMESPACE = UUID('83ef9730-70cb-4ac5-8624-d438bf41b65b')


class EndpointPolicy(_Contract):
    endpoint_id: Identifier
    runtime_id: Identifier
    location: Literal['IN_PROCESS','LOOPBACK']
    approved: bool
    host: Literal['127.0.0.1','::1'] | None = None
    port: Annotated[int, Field(ge=1,le=65535)] | None = None
    scheme: Literal['http','https'] | None = None
    redirects: Literal[False] = False
    ambient_proxy: Literal[False] = False
    dns_substitution: Literal[False] = False
    activation: Literal['PROPOSED_ONLY'] = 'PROPOSED_ONLY'

    @model_validator(mode='after')
    def location_scope(self):
        values = (self.host,self.port,self.scheme)
        if ((self.location=='IN_PROCESS' and (any(value is not None for value in values) or self.runtime_id!='fake'))
                or (self.location=='LOOPBACK' and any(value is None for value in values))):
            raise ValueError('invalid_endpoint_policy')
        return self


class ModelDescriptor(_Contract):
    model_id: Identifier
    family: Identifier
    runtime_id: Identifier
    endpoint_id: Identifier
    artifact_identity: Identifier
    artifact_sha256: ai.Digest | None = None
    deployment: Literal['LOCAL_SELF_HOSTED']
    capabilities: Annotated[tuple[Literal['CHAT','JSON_SCHEMA','STREAMING'],...], Field(min_length=1,max_length=3)]
    max_context_tokens: Positive
    max_output_tokens: Annotated[int, Field(ge=1,le=8192)]
    structured_output: Literal['JSON_SCHEMA'] = 'JSON_SCHEMA'
    memory_mib: Annotated[int, Field(ge=1,le=32768)]
    cpu_ms: Annotated[int, Field(ge=1,le=60000)]
    approval: Literal['DEVELOPMENT_APPROVED','UNAPPROVED']
    evaluation: Literal['OFFLINE_SYNTHETIC','UNEVALUATED']
    token_accounting: Literal['SYNTHETIC_UTF8_BYTES_V1','ESTIMATED_BYTES_PER4_V1','OPTIMIZED_BYTES_PER4_OVERHEAD128_V1','UNVERIFIED']
    production_approved: Literal[False] = False

    @model_validator(mode='after')
    def limits(self):
        object.__setattr__(self,'capabilities',ai._unique(self.capabilities))
        if self.max_output_tokens>self.max_context_tokens:
            raise ValueError('invalid_model_limits')
        return self


class ModelRegistry(_Contract):
    models: Annotated[tuple[ModelDescriptor,...], Field(min_length=1,max_length=16)]
    endpoints: Annotated[tuple[EndpointPolicy,...], Field(min_length=1,max_length=16)]

    @model_validator(mode='after')
    def allowlist(self):
        ai._unique(tuple(item.model_id for item in self.models))
        identities = tuple((item.runtime_id,item.endpoint_id,item.artifact_sha256 or item.artifact_identity)
                           for item in self.models)
        if len(set(identities))!=len(identities):
            raise ValueError('duplicate_model_artifact')
        ai._unique(tuple(item.endpoint_id for item in self.endpoints))
        endpoints = {item.endpoint_id:item for item in self.endpoints}
        for model in self.models:
            endpoint = endpoints.get(model.endpoint_id)
            if (model.approval!='DEVELOPMENT_APPROVED' or model.evaluation!='OFFLINE_SYNTHETIC'
                    or not {'CHAT','JSON_SCHEMA'} <= set(model.capabilities)
                    or endpoint is None or not endpoint.approved or endpoint.runtime_id!=model.runtime_id):
                raise ValueError('unapproved_registry_entry')
        object.__setattr__(self,'models',tuple(sorted(self.models,key=lambda item:item.model_id)))
        object.__setattr__(self,'endpoints',tuple(sorted(self.endpoints,key=lambda item:item.endpoint_id)))
        return self


class AnalystModelProfile(_Contract):
    tier: ai.Tier
    model_id: Identifier
    model_schema_version: Literal['1.0'] = '1.0'
    configuration_version: Annotated[int, Field(ge=1,le=2147483647)]
    max_context_tokens: Positive
    max_output_tokens: Annotated[int, Field(ge=1,le=8192)]
    temperature: Annotated[float, Field(ge=0,le=2,allow_inf_nan=False)]
    request_timeout_ms: Annotated[int, Field(ge=1,le=60000)]
    overall_deadline_ms: Annotated[int, Field(ge=1,le=120000)]
    max_concurrent_requests: Annotated[int, Field(ge=1,le=4)]
    streaming: bool
    structured_output: Literal['JSON_SCHEMA'] = 'JSON_SCHEMA'
    max_input_bytes: Annotated[int, Field(ge=1,le=65536)]
    max_output_bytes: Annotated[int, Field(ge=1,le=16384)]
    max_chunks: Annotated[int, Field(ge=1,le=64)]

    @model_validator(mode='after')
    def time_limits(self):
        if self.request_timeout_ms>self.overall_deadline_ms or self.max_output_tokens>self.max_context_tokens:
            raise ValueError('invalid_profile_limits')
        return self


class InferenceConfiguration(_Contract):
    registry: ModelRegistry
    profiles: tuple[AnalystModelProfile,AnalystModelProfile,AnalystModelProfile]

    @model_validator(mode='after')
    def assignments(self):
        if {item.tier for item in self.profiles}!={'L1','L2','L3'}:
            raise ValueError('conflicting_tier_profiles')
        models = {item.model_id:item for item in self.registry.models}
        for profile in self.profiles:
            model = models.get(profile.model_id)
            if (model is None or profile.max_context_tokens>model.max_context_tokens
                    or profile.max_output_tokens>model.max_output_tokens
                    or (profile.streaming and 'STREAMING' not in model.capabilities)):
                raise ValueError('unsupported_profile')
        object.__setattr__(self,'profiles',tuple(sorted(self.profiles,key=lambda item:item.tier)))
        return self


def _hash(data):
    return hashlib.sha256(evaluation._bytes(data)).hexdigest()


def _request_identity(data):
    data = dict(data)
    data.pop('request_id',None); data.pop('request_sha256',None)
    identity = uuid5(NAMESPACE,_hash(data))
    data['request_id'] = str(identity)
    return identity,_hash(data)


def _trusted(value,contract):
    ai._bounded(value)
    protocol._model_fields(value)
    if type(value) is not contract:
        raise ValueError('invalid_trusted_inference_contract')
    # Validate typed fields before serialization, so forged copies cannot emit
    # Pydantic serializer warnings containing rejected caller values.
    return contract.model_validate(value)


class InferenceRequest(_Contract):
    request_id: UUID
    request_sha256: ai.Digest
    tenant_id: UUID
    principal_id: UUID
    task_id: UUID
    tier: ai.Tier
    snapshot_id: UUID
    snapshot_sha256: ai.Digest
    prompt: protocol.PromptEnvelope
    registry_sha256: ai.Digest
    configuration_sha256: ai.Digest
    model: ModelDescriptor
    profile: AnalystModelProfile
    endpoint: EndpointPolicy
    created_at: datetime
    timeout_at: datetime
    deadline_at: datetime
    classification: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    executable: Literal[False] = False

    @model_validator(mode='after')
    def integrity(self):
        expected_id,expected_hash = _request_identity(self.model_dump(mode='json'))
        if (self.request_id!=expected_id or self.request_sha256!=expected_hash
                or self.task_id!=self.prompt.task_id or self.tier!=self.prompt.tier
                or self.tier!=self.profile.tier or self.profile.model_id!=self.model.model_id
                or self.endpoint.endpoint_id!=self.model.endpoint_id
                or self.snapshot_id!=self.prompt.snapshot_id or self.snapshot_sha256!=self.prompt.snapshot_sha256
                or self.prompt.classification!=self.classification
                or not ai._utc(self.created_at)<ai._utc(self.timeout_at)<=ai._utc(self.deadline_at)):
            raise ValueError('invalid_inference_binding')
        return self


def _prepare_request(context: TrustedContext, task: ai.AnalystTask, snapshot: ai.EvidenceSnapshot,
                    package: evaluation.AnalystInput, configuration: InferenceConfiguration,
                    *, at: datetime, forbidden_values: tuple[str,...] = ()) -> InferenceRequest:
    """Trusted configuration selects a model; model messages never select it."""
    configuration = _trusted(configuration,InferenceConfiguration)
    context = _trusted(context,TrustedContext)
    task = _trusted(task,ai.AnalystTask)
    snapshot = _trusted(snapshot,ai.EvidenceSnapshot)
    package = _trusted(package,evaluation.AnalystInput)
    context,task,snapshot = ai.validate_inputs(context,task,snapshot,at=at)
    if task.classification!='SYNTHETIC / TEST ONLY':
        raise ValueError('synthetic_only')
    profile = next(item for item in configuration.profiles if item.tier==task.tier)
    model = next(item for item in configuration.registry.models if item.model_id==profile.model_id)
    endpoint = next(item for item in configuration.registry.endpoints if item.endpoint_id==model.endpoint_id)
    prompt = protocol.render_prompt(context,task,snapshot,package,at=at,
        max_prompt_bytes=profile.max_input_bytes,forbidden_values=forbidden_values)
    prompt_units = len(ai.canonical_bytes(prompt))
    optimized_accounting = model.token_accounting=='OPTIMIZED_BYTES_PER4_OVERHEAD128_V1' and model.runtime_id=='ollama'
    if optimized_accounting:
        pass  # The exact outgoing projection is assessed after request binding.
    elif model.token_accounting=='ESTIMATED_BYTES_PER4_V1' and model.runtime_id=='ollama':
        prompt_units = (prompt_units+3)//4
    elif model.token_accounting!='SYNTHETIC_UTF8_BYTES_V1':
        raise ValueError('unverified_token_accounting')
    # Explicit estimates/synthetic units, never tokenizer-verified claims.
    if not optimized_accounting and prompt_units+profile.max_output_tokens>profile.max_context_tokens:
        raise ValueError('context_budget_exceeded')
    at = ai._utc(at)
    deadline = min(task.deadline,at+timedelta(milliseconds=profile.overall_deadline_ms))
    draft = InferenceRequest.model_construct(request_id=UUID(int=0),request_sha256='0'*64,
        tenant_id=context.tenant_id,principal_id=context.principal_id,task_id=task.task_id,tier=task.tier,
        snapshot_id=snapshot.snapshot_id,snapshot_sha256=snapshot.snapshot_sha256,prompt=prompt,
        registry_sha256=ai._digest(configuration.registry),configuration_sha256=ai._digest(configuration),
        model=model,profile=profile,endpoint=endpoint,created_at=at,
        timeout_at=min(deadline,at+timedelta(milliseconds=profile.request_timeout_ms)),deadline_at=deadline)
    data = draft.model_dump(mode='json')
    identity,digest = _request_identity(data)
    data.update(request_id=str(identity),request_sha256=digest)
    result = InferenceRequest.model_validate_json(evaluation._bytes(data))
    if len(ai.canonical_bytes(result))>min(task.max_input_bytes,profile.max_input_bytes):
        raise ValueError('input_budget_exceeded')
    if optimized_accounting:
        from app.analysts.providers.ollama_prompt import optimize_prompt
        if not optimize_prompt(result).context_fits:
            raise ValueError('context_budget_exceeded')
    return result


def prepare_request(context: TrustedContext, task: ai.AnalystTask, snapshot: ai.EvidenceSnapshot,
                    package: evaluation.AnalystInput, configuration: InferenceConfiguration,
                    *, at: datetime, forbidden_values: tuple[str,...] = ()) -> InferenceRequest:
    try:
        return _prepare_request(context,task,snapshot,package,configuration,at=at,
                                forbidden_values=forbidden_values)
    except Exception:
        raise ValueError('invalid_inference_request') from None


@dataclass(frozen=True)
class InferenceControl:
    now: Callable[[],datetime]
    cancelled: Callable[[],bool] = lambda: False


class AdmissionController:
    """Process-local shared admission; no model loading, worker or queue."""
    def __init__(self,max_in_flight=4):
        if type(max_in_flight) is not int or not 1<=max_in_flight<=4:
            raise ValueError('invalid_capacity')
        self._limit = max_in_flight
        self._active = {}
        self._lock = Lock()

    @property
    def in_flight(self):
        with self._lock:
            return len(self._active)

    def acquire(self,request):
        key = (request.endpoint.endpoint_id,request.model.runtime_id,
               request.model.artifact_sha256 or request.model.artifact_identity)
        with self._lock:
            peers = [value[1] for value in self._active.values() if value[0]==key]
            limit = min((request.profile.max_concurrent_requests,*peers))
            if request.request_id in self._active or len(self._active)>=self._limit or len(peers)>=limit:
                return False
            self._active[request.request_id] = (key,request.profile.max_concurrent_requests,request.request_sha256)
            return True

    def release(self,request):
        with self._lock:
            held = self._active.get(request.request_id)
            if held is None or held[2]!=request.request_sha256:
                raise ValueError('invalid_admission_release')
            del self._active[request.request_id]


class ProviderFrame(_Contract):
    request_id: UUID
    request_sha256: ai.Digest
    snapshot_sha256: ai.Digest
    model_id: Identifier
    runtime_id: Identifier
    index: Annotated[int, Field(ge=0,le=63)]
    data: Annotated[bytes, Field(max_length=32768)]
    chunk_sha256: ai.Digest
    stream_sha256: ai.Digest
    final: bool
    elapsed_ms: Annotated[int, Field(ge=0,le=120000)] = 0


class LocalInferenceProvider(Protocol):
    def generate(self,request: InferenceRequest) -> Iterator[ProviderFrame]: ...


class FakeStep(_Contract):
    data: Annotated[bytes, Field(max_length=32768)] = b''
    final: bool = False
    elapsed_ms: Annotated[int, Field(ge=0,le=120000)] = 0
    event: Literal['DATA','FAILURE','CANCEL'] = 'DATA'


class _Stop(Exception):
    pass


class FakeModelProvider(_Contract):
    steps: Annotated[tuple[FakeStep,...], Field(min_length=1,max_length=64)]
    fault: Literal['NONE','WRONG_REQUEST','WRONG_SNAPSHOT','MODEL_FALLBACK','CHUNK_HASH','SEQUENCE','MALFORMED'] = 'NONE'
    _calls: int = PrivateAttr(default=0)

    @property
    def calls(self):
        return self._calls

    def generate(self,request):
        # Snapshot the closed script before yielding; validation never delegates
        # execution to an injected subclass or mutable external adapter.
        plan = FakeModelProvider.model_validate(dict(self.__dict__))
        self._calls += 1
        stream = hashlib.sha256()
        for index,step in enumerate(plan.steps):
            if step.event=='FAILURE':
                raise RuntimeError('synthetic-provider-error-canary')
            if step.event=='CANCEL':
                raise _Stop('CANCELLED','CANCELLED')
            stream.update(step.data)
            frame = ProviderFrame(request_id=request.request_id,request_sha256=request.request_sha256,
                snapshot_sha256=request.snapshot_sha256,model_id=request.model.model_id,
                runtime_id=request.model.runtime_id,index=index,data=step.data,
                chunk_sha256=hashlib.sha256(step.data).hexdigest(),stream_sha256=stream.hexdigest(),
                final=step.final,elapsed_ms=step.elapsed_ms)
            patch = {'WRONG_REQUEST':{'request_sha256':'0'*64},'WRONG_SNAPSHOT':{'snapshot_sha256':'0'*64},
                'MODEL_FALLBACK':{'model_id':'unregistered-cloud-fallback'},'CHUNK_HASH':{'chunk_sha256':'0'*64},
                'SEQUENCE':{'index':63},'MALFORMED':{'data':'not-bytes'}}.get(plan.fault,{})
            yield frame.model_copy(update=patch)


class InferenceResult(_Contract):
    status: Literal['COMPLETED','DENIED','FAILED','CANCELLED','TIMED_OUT','BUSY']
    reason: Literal['ACCEPTED_PROPOSAL','INVALID_INPUT','UNSUPPORTED_PROVIDER','LIMIT_EXCEEDED',
        'BINDING_MISMATCH','INVALID_STREAM','MODEL_OUTPUT_REJECTED','MISSING_EVIDENCE','PROVIDER_FAILURE','DEADLINE','CANCELLED','CAPACITY']
    request_id: UUID | None
    request_sha256: ai.Digest | None
    parsed: protocol.ParseResult | None = None
    classification: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    source: Literal['FAKE_MODEL / TEST ONLY'] = 'FAKE_MODEL / TEST ONLY'
    executable: Literal[False] = False

    @model_validator(mode='after')
    def proposed(self):
        reasons = {'COMPLETED':('ACCEPTED_PROPOSAL',),
            'DENIED':('INVALID_INPUT','UNSUPPORTED_PROVIDER','LIMIT_EXCEEDED','BINDING_MISMATCH','INVALID_STREAM','MODEL_OUTPUT_REJECTED','MISSING_EVIDENCE'),
            'FAILED':('PROVIDER_FAILURE',),'CANCELLED':('CANCELLED',),'TIMED_OUT':('DEADLINE',),'BUSY':('CAPACITY',)}
        if self.reason not in reasons[self.status] or (self.request_id is None)!=(self.request_sha256 is None):
            raise ValueError('invalid_inference_result')
        if self.status=='COMPLETED' and (self.request_id is None or self.parsed is None or self.parsed.status!='ACCEPTED'):
            raise ValueError('invalid_inference_result')
        if self.parsed is not None and self.status!='COMPLETED' and (
                self.reason!='MODEL_OUTPUT_REJECTED' or self.parsed.status=='ACCEPTED'):
            raise ValueError('invalid_inference_result')
        return self


@dataclass(frozen=True, slots=True)
class InferenceExecutionReceipt:
    """In-process record of a completed synthetic inference.

    Not cryptographic attestation or execution authorization.
    Never serialize this object directly into external responses.
    """

    request: InferenceRequest
    result: InferenceResult
    proposed_only: Literal[True] = True
    executable: Literal[False] = False


def _run_inference(context: TrustedContext, task: ai.AnalystTask, snapshot: ai.EvidenceSnapshot,
                  package: evaluation.AnalystInput, configuration: InferenceConfiguration,
                  provider: LocalInferenceProvider, admission: AdmissionController, control: InferenceControl,
                  *, forbidden_values: tuple[str,...] = (),
                  _receipt_sink: list[InferenceExecutionReceipt] | None = None) -> InferenceResult:
    """Closed fake/script and mock-HTTP implementations only; no live transport."""
    request,acquired = None,False
    parsed = None
    try:
        if type(control) is not InferenceControl or type(admission) is not AdmissionController:
            raise _Stop('DENIED','INVALID_INPUT')
        started = ai._utc(control.now())
        request = prepare_request(context,task,snapshot,package,configuration,at=started,
                                  forbidden_values=forbidden_values)
        mocked_ollama = False
        if type(provider) is FakeModelProvider:
            if request.model.runtime_id!='fake' or request.endpoint.location!='IN_PROCESS':
                raise _Stop('DENIED','UNSUPPORTED_PROVIDER')
            protocol._model_fields(provider)
            FakeModelProvider.model_validate(dict(provider.__dict__))
        else:
            # One code-owned import, not plugin discovery or a model-selected path.
            from app.analysts.providers.ollama import MockedOllamaProvider
            if type(provider) is not MockedOllamaProvider or provider.control is not control:
                raise _Stop('DENIED','UNSUPPORTED_PROVIDER')
            provider.validate_request(request)
            mocked_ollama = True
        last,simulated = started,0
        def checkpoint(generating=False):
            nonlocal last
            observed = ai._utc(control.now())
            cancelled = control.cancelled()
            if observed<last or type(cancelled) is not bool:
                raise _Stop('DENIED','INVALID_INPUT')
            last = observed
            if cancelled:
                raise _Stop('CANCELLED','CANCELLED')
            effective = max(observed,started+timedelta(milliseconds=simulated))
            if effective>=request.deadline_at or (generating and effective>=request.timeout_at):
                raise _Stop('TIMED_OUT','DEADLINE')
            return effective
        checkpoint(True)
        if not admission.acquire(request):
            raise _Stop('BUSY','CAPACITY')
        acquired = True
        body = bytearray(); stream = hashlib.sha256(); complete = False; count = 0
        for raw in provider.generate(request):
            checkpoint(True)
            if type(raw) is not ProviderFrame:
                raise _Stop('DENIED','INVALID_STREAM')
            try:
                protocol._model_fields(raw)
                frame = ProviderFrame.model_validate(dict(raw.__dict__))
            except Exception:
                raise _Stop('DENIED','INVALID_STREAM') from None
            simulated += frame.elapsed_ms
            checkpoint(True)
            if (frame.request_id!=request.request_id or frame.request_sha256!=request.request_sha256
                    or frame.snapshot_sha256!=request.snapshot_sha256 or frame.model_id!=request.model.model_id
                    or frame.runtime_id!=request.model.runtime_id):
                raise _Stop('DENIED','BINDING_MISMATCH')
            if (complete or frame.index!=count or count>=request.profile.max_chunks
                    or (not request.profile.streaming and (count!=0 or not frame.final))):
                raise _Stop('DENIED','INVALID_STREAM')
            output_limit = min(task.max_output_bytes,request.profile.max_output_bytes)
            if not mocked_ollama:
                output_limit = min(output_limit,request.profile.max_output_tokens)
            if len(body)+len(frame.data)>output_limit:
                raise _Stop('DENIED','LIMIT_EXCEEDED')
            stream.update(frame.data)
            if frame.chunk_sha256!=hashlib.sha256(frame.data).hexdigest() or frame.stream_sha256!=stream.hexdigest():
                raise _Stop('DENIED','INVALID_STREAM')
            body.extend(frame.data); count += 1; complete = frame.final
        if not complete:
            raise _Stop('DENIED','INVALID_STREAM')
        acceptance_time = checkpoint(True)
        parsed = protocol.parse_response(context,task,snapshot,bytes(body),at=acceptance_time,
                                         forbidden_values=forbidden_values)
        checkpoint()
        status,reason = ('COMPLETED','ACCEPTED_PROPOSAL') if parsed.status=='ACCEPTED' else ('DENIED','MODEL_OUTPUT_REJECTED')
        if mocked_ollama and parsed.evaluation is not None and parsed.evaluation.outcome=='INSUFFICIENT_EVIDENCE':
            status,reason,parsed = 'DENIED','MISSING_EVIDENCE',None
    except _Stop as stopped:
        status,reason = stopped.args
        parsed = None
    except Exception:
        status,reason = ('DENIED','INVALID_INPUT') if request is None or not acquired else ('FAILED','PROVIDER_FAILURE')
        parsed = None
    finally:
        if acquired:
            admission.release(request)
    result = InferenceResult(status=status,reason=reason,parsed=parsed,
        request_id=None if request is None else request.request_id,
        request_sha256=None if request is None else request.request_sha256)
    if result.status=='COMPLETED':
        try:
            checkpoint()  # Cancellation/deadline still apply after slot cleanup.
        except _Stop as stopped:
            result = InferenceResult(status=stopped.args[0],reason=stopped.args[1],
                request_id=result.request_id,request_sha256=result.request_sha256)
        except Exception:
            result = InferenceResult(status='FAILED',reason='PROVIDER_FAILURE',
                request_id=result.request_id,request_sha256=result.request_sha256)
    if (type(task) is ai.AnalystTask and type(task.max_output_bytes) is int
            and 1<=task.max_output_bytes<=16384):
        limit = min(task.max_output_bytes,16384 if request is None else request.profile.max_output_bytes)
        if len(ai.canonical_bytes(result))>limit:
            result = InferenceResult(status='DENIED',reason='LIMIT_EXCEEDED',request_id=result.request_id,
                request_sha256=result.request_sha256)
            if len(ai.canonical_bytes(result))>limit:
                raise ValueError('invalid_inference_result_budget') from None
    # Capture only the final successful result, after all checks.
    # The caller must treat this as in-process execution evidence,
    # never as an independently authenticated credential.
    if (
        _receipt_sink is not None
        and result.status == 'COMPLETED'
        and request is not None
    ):
        _receipt_sink.append(
            InferenceExecutionReceipt(
                request=request,
                result=result,
            )
        )

    return result


def run_inference(
    context: TrustedContext,
    task: ai.AnalystTask,
    snapshot: ai.EvidenceSnapshot,
    package: evaluation.AnalystInput,
    configuration: InferenceConfiguration,
    provider: LocalInferenceProvider,
    admission: AdmissionController,
    control: InferenceControl,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> InferenceResult:
    """Public inference interface; no caller-supplied receipt sink."""

    return _run_inference(
        context,
        task,
        snapshot,
        package,
        configuration,
        provider,
        admission,
        control,
        forbidden_values=forbidden_values,
    )


def run_inference_with_receipt(
    context: TrustedContext,
    task: ai.AnalystTask,
    snapshot: ai.EvidenceSnapshot,
    package: evaluation.AnalystInput,
    configuration: InferenceConfiguration,
    provider: LocalInferenceProvider,
    admission: AdmissionController,
    control: InferenceControl,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> tuple[InferenceResult, InferenceExecutionReceipt | None]:
    """Run inference and capture the code-owned successful request."""

    receipts: list[InferenceExecutionReceipt] = []

    result = _run_inference(
        context,
        task,
        snapshot,
        package,
        configuration,
        provider,
        admission,
        control,
        forbidden_values=forbidden_values,
        _receipt_sink=receipts,
    )

    if len(receipts) == 1:
        return result, receipts[0]

    return result, None
