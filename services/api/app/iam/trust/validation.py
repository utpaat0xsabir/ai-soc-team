"""Pure structure and explicit-context comparisons; never return an IAM ALLOW."""
from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ValidationError

from .contracts import RECORD_TYPES, ProvenanceEnvelope, TrustBinding
from .denials import StructuralCode, StructuralError


def _validation_code(error):
    codes = []
    for detail in error.errors(include_input=False, include_context=False, include_url=False):
        kind, loc = detail['type'], detail['loc']
        if kind in StructuralCode._value2member_map_:
            code = StructuralCode(kind)
        elif kind == 'missing': code = StructuralCode.MISSING_REQUIRED_FIELD
        elif kind == 'value_error' and detail['msg'] == 'Value error, iam_tenant_mismatch':
            code = StructuralCode.INVALID_TENANT_BINDING
        elif 'schema_version' in loc: code = StructuralCode.UNSUPPORTED_SCHEMA_VERSION
        elif 'deployment_type' in loc: code = StructuralCode.INVALID_DEPLOYMENT_TYPE
        elif 'tenant_id' in loc: code = StructuralCode.INVALID_TENANT_BINDING
        elif 'issuer_ref' in loc: code = StructuralCode.INVALID_ISSUER_REFERENCE
        elif 'root_policy_version' in loc: code = StructuralCode.INVALID_ROOT_POLICY_VERSION
        elif 'required_quorum' in loc or 'custodians' in loc and kind in ('too_short', 'too_long', 'tuple_type'):
            code = StructuralCode.INVALID_QUORUM_CONFIGURATION
        elif 'checkpoint_ref' in loc: code = StructuralCode.INVALID_CHECKPOINT_REFERENCE
        elif 'recovery_journal_ref' in loc: code = StructuralCode.INVALID_RECOVERY_JOURNAL_REFERENCE
        elif 'issued_at' in loc or 'expires_at' in loc: code = StructuralCode.INVALID_TIMESTAMP
        elif 'authority_scope' in loc: code = StructuralCode.INVALID_AUTHORITY_SCOPE
        elif 'authority_revision' in loc: code = StructuralCode.INVALID_AUTHORITY_REVISION
        elif 'operation' in loc: code = StructuralCode.UNSUPPORTED_OPERATION
        elif kind in ('uuid_type', 'uuid_parsing', 'string_pattern_mismatch') or any(
                field in loc for field in ('trust_domain_id', 'deployment_id', 'customer_authority_id',
                                          'provider_identity_id', 'root_policy_id', 'payload_id', 'operation_id')):
            code = StructuralCode.INVALID_IDENTIFIER
        else: code = StructuralCode.MALFORMED_PROVENANCE_ENVELOPE
        codes.append(code)
    # Enumeration order is fixed, independent of field/input ordering.
    return next(code for code in StructuralCode if code in codes)


def _input(value, depth=0):
    if depth > 16:
        raise StructuralError(StructuralCode.MALFORMED_PROVENANCE_ENVELOPE)
    if isinstance(value, BaseModel):
        # model_copy/model_construct can bypass validation and hide extra fields
        # from model_dump. Inspect the stored fields before revalidation.
        if set(vars(value)) - set(type(value).model_fields) or value.__pydantic_extra__:
            raise StructuralError(StructuralCode.MALFORMED_PROVENANCE_ENVELOPE)
        value = vars(value)
    if type(value) is dict:
        return {k:_input(v, depth + 1) for k,v in value.items()}
    if type(value) is tuple:
        return tuple(_input(v, depth + 1) for v in value)
    return value


def checked(model_type, data):
    if model_type not in (*RECORD_TYPES, TrustBinding):
        raise StructuralError(StructuralCode.MALFORMED_PROVENANCE_ENVELOPE)
    try:
        if type(data) is model_type or type(data) is dict:
            data = _input(data)
        if type(data) is not dict:
            raise StructuralError(StructuralCode.MALFORMED_PROVENANCE_ENVELOPE)
        return model_type.model_validate(data)
    except StructuralError:
        raise
    except ValidationError as error:
        code = _validation_code(error)
    except (ValueError, TypeError, RecursionError):
        code = StructuralCode.MALFORMED_PROVENANCE_ENVELOPE
    raise StructuralError(code) from None


@dataclass(frozen=True)
class StructuralAssessment:
    record: object
    status: Literal['STRUCTURAL_ONLY'] = field(default='STRUCTURAL_ONLY', init=False)


def validate_structure(model_type, data, *, expected_binding, issuer_ids):
    """Issuer IDs are an explicit structural registry, not authenticated issuers.

    Caller supplies context; comparing attacker-controlled context to itself proves
    nothing. No clock, signature verifier, storage, session or policy is consulted.
    """
    context = checked(TrustBinding, expected_binding)
    record = checked(model_type, data)
    if record.binding.tenant_id != context.tenant_id:
        raise StructuralError(StructuralCode.INVALID_TENANT_BINDING)
    if record.binding != context:
        raise StructuralError(StructuralCode.INVALID_DEPLOYMENT_BINDING)
    if (type(issuer_ids) is not tuple or len(issuer_ids) > 64
            or any(type(i) is not UUID or i.int == 0 for i in issuer_ids)
            or len(set(issuer_ids)) != len(issuer_ids)):
        raise StructuralError(StructuralCode.INVALID_ISSUER_REFERENCE)
    if type(record) is ProvenanceEnvelope and record.issuer_ref.reference_id not in issuer_ids:
        raise StructuralError(StructuralCode.INVALID_ISSUER_REFERENCE)
    return StructuralAssessment(record)
