"""TRUST02-JSON-1: bounded canonical ASCII JSON, not a signature protocol."""
from datetime import datetime, timezone
import json
from uuid import UUID

from .contracts import RECORD_TYPES
from .denials import StructuralCode, StructuralError
from .validation import checked

MAX_PAYLOAD_BYTES = 65536


def _value(value):
    if type(value) is UUID: return str(value)
    if type(value) is datetime:
        return value.astimezone(timezone.utc).isoformat(timespec='microseconds')
    if isinstance(value, dict): return {k:_value(v) for k,v in value.items()}
    if isinstance(value, (tuple, list)): return [_value(v) for v in value]
    return value


def canonical_bytes(record):
    """Revalidate copies/constructed instances before producing structural bytes."""
    if type(record) not in RECORD_TYPES:
        raise StructuralError(StructuralCode.MALFORMED_PROVENANCE_ENVELOPE)
    record = checked(type(record), record)
    raw = json.dumps(_value(record.model_dump()), sort_keys=True, ensure_ascii=True,
                     allow_nan=False, separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise StructuralError(StructuralCode.NONCANONICAL_REPRESENTATION)
    return raw


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise StructuralError(StructuralCode.NONCANONICAL_REPRESENTATION)
        result[key] = value
    return result


def _typed_json(value, field=None, depth=0):
    # Decode only the JSON representations required by these exact contracts.
    if depth > 16:
        raise StructuralError(StructuralCode.NONCANONICAL_REPRESENTATION)
    if isinstance(value, dict): return {k:_typed_json(v, k, depth + 1) for k,v in value.items()}
    if isinstance(value, list): return tuple(_typed_json(v, depth=depth + 1) for v in value)
    uuid_fields = {'trust_domain_id', 'deployment_id', 'tenant_id', 'customer_authority_id',
                   'provider_identity_id', 'reference_id', 'operation_id', 'payload_id', 'scope_id'}
    if type(value) is str:
        try:
            if field in uuid_fields: return UUID(value)
            if field in ('issued_at', 'expires_at'): return datetime.fromisoformat(value)
        except ValueError:
            pass  # Strict model validation assigns the field-specific denial.
    return value


def _reject_constant(_):
    raise ValueError()


def parse_canonical(model_type, payload):
    """Accept only exact canonical bytes; never last-key-wins or numeric aliases."""
    if type(payload) is not bytes or len(payload) > MAX_PAYLOAD_BYTES:
        raise StructuralError(StructuralCode.NONCANONICAL_REPRESENTATION)
    try:
        parsed = json.loads(payload.decode('ascii'), object_pairs_hook=_pairs,
                            parse_constant=_reject_constant)
        if type(parsed) is not dict: raise ValueError()
    except (ValueError, UnicodeError, RecursionError):
        raise StructuralError(StructuralCode.NONCANONICAL_REPRESENTATION) from None
    record = checked(model_type, _typed_json(parsed))
    if canonical_bytes(record) != payload:
        raise StructuralError(StructuralCode.NONCANONICAL_REPRESENTATION)
    return record
