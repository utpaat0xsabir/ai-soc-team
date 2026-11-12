"""Versioned Ollama wire projection; internal authority and schemas stay intact."""
import json
import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_validator

from app.analysts import contracts as ai
from app.analysts import evaluation as evaluation
from app.gateway.contracts import _Contract


ACCOUNTING_VERSION = 'OPTIMIZED_BYTES_PER4_OVERHEAD128_V1'
CHAT_OVERHEAD_UNITS = 128


def strip_schema_titles(schema):
    """Strip annotation keywords, never keys/data inside properties/const/enum."""
    ai._bounded(schema)
    mappings = {'$defs','definitions','properties','patternProperties','dependentSchemas'}
    sequences = {'allOf','anyOf','oneOf','prefixItems'}
    children = {'items','additionalProperties','unevaluatedProperties','unevaluatedItems',
                'contains','not','if','then','else','propertyNames','contentSchema'}
    def visit(node):
        if type(node) is bool:
            return node
        if type(node) is not dict:
            raise ValueError('invalid_schema_node')
        result = {}
        for key,value in node.items():
            if key=='title':
                if type(value) is not str:
                    raise ValueError('invalid_schema_annotation')
            elif key in mappings:
                result[key] = {name:visit(child) for name,child in value.items()}
            elif key in sequences:
                result[key] = [visit(child) for child in value]
            elif key in children:
                result[key] = visit(value)
            else:
                # Clone without traversing schema-like objects in actual data values.
                result[key] = json.loads(evaluation._bytes(value))
        return result
    return visit(schema)


def build_chat_body(request,*,optimized=False):
    schema = json.loads(request.prompt.output_schema_json)
    if optimized:
        schema = strip_schema_titles(schema)
    return {'model':request.model.model_id,'stream':False,
        'messages':[{'role':message.role,'content':message.content} for message in request.prompt.messages],
        'format':schema,'options':{'temperature':request.profile.temperature,
            'num_ctx':request.profile.max_context_tokens,'num_predict':request.profile.max_output_tokens}}


class OllamaPromptPlan(_Contract):
    optimization_version: Literal['title-only-v1'] = 'title-only-v1'
    accounting_version: Literal['OPTIMIZED_BYTES_PER4_OVERHEAD128_V1'] = ACCOUNTING_VERSION
    request_sha256: ai.Digest
    original_prompt_sha256: ai.Digest
    wire_sha256: ai.Digest
    wire_json: Annotated[str, Field(min_length=1,max_length=65536)]
    internal_prompt_bytes: Annotated[int, Field(ge=1,le=65536)]
    wire_bytes: Annotated[int, Field(ge=1,le=65536)]
    input_estimated_units: Annotated[int, Field(ge=1,le=16384)]
    chat_overhead_units: Literal[128] = CHAT_OVERHEAD_UNITS
    output_reserve_units: Annotated[int, Field(ge=1,le=8192)]
    total_estimated_units: Annotated[int, Field(ge=1,le=24704)]
    context_ceiling: Annotated[int, Field(ge=1,le=131072)]
    context_fits: bool
    native_tokenizer_verified: Literal[False] = False
    operational_admission: Literal['BLOCKED'] = 'BLOCKED'
    executable: Literal[False] = False

    @model_validator(mode='after')
    def accounting(self):
        encoded = self.wire_json.encode('utf-8')
        units = (len(encoded)+3)//4
        total = units+self.chat_overhead_units+self.output_reserve_units
        if (len(encoded)!=self.wire_bytes or hashlib.sha256(encoded).hexdigest()!=self.wire_sha256
                or units!=self.input_estimated_units or total!=self.total_estimated_units
                or self.context_fits!=(total<=self.context_ceiling)):
            raise ValueError('invalid_prompt_accounting')
        return self


def optimize_prompt(request):
    from app.analysts import inference as inference
    try:
        request = inference._trusted(request,inference.InferenceRequest)
        if (request.model.runtime_id!='ollama' or request.model.token_accounting!=ACCOUNTING_VERSION
                or request.profile.streaming):
            raise ValueError()
        encoded = evaluation._bytes(build_chat_body(request,optimized=True))
        if len(encoded)>min(request.profile.max_input_bytes,request.prompt.max_prompt_bytes):
            raise ValueError()
        units = (len(encoded)+3)//4
        total = units+CHAT_OVERHEAD_UNITS+request.profile.max_output_tokens
        return OllamaPromptPlan(request_sha256=request.request_sha256,
            original_prompt_sha256=ai._digest(request.prompt),wire_sha256=hashlib.sha256(encoded).hexdigest(),
            wire_json=encoded.decode('ascii'),wire_bytes=len(encoded),internal_prompt_bytes=len(ai.canonical_bytes(request.prompt)),
            input_estimated_units=units,output_reserve_units=request.profile.max_output_tokens,
            total_estimated_units=total,context_ceiling=request.profile.max_context_tokens,
            context_fits=total<=request.profile.max_context_tokens)
    except Exception:
        raise ValueError('invalid_optimized_prompt') from None


def validate_plan(request,plan):
    try:
        from app.analysts import protocol as protocol
        ai._bounded(plan); protocol._model_fields(plan)
        if type(plan) is not OllamaPromptPlan:
            raise ValueError()
        checked = OllamaPromptPlan.model_validate(plan)
        if ai.canonical_bytes(checked)!=ai.canonical_bytes(optimize_prompt(request)):
            raise ValueError()
        return checked
    except Exception:
        raise ValueError('invalid_optimized_prompt') from None
