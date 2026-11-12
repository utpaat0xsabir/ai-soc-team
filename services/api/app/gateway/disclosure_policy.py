"""TG-03A: offline IP disclosure assessment, never authorization to execute.

Trusted callers supply authentication, policies, provider identities, consent and
usage snapshots plus evaluation time. No configuration, clock, storage, I/O or
adapter is consulted. ALLOW is not a dispatch token or durable quota reservation.
Other payload types, real egress and consent persistence require later approval.
"""

import hashlib
import json
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.gateway.contracts import ToolRequest, TrustedContext
from app.integrations.wazuh import gateway as wazuh_gateway


Identifier = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_.-]{0,63}$')]
Version = Annotated[str, Field(pattern=r'^[0-9]{1,3}\.[0-9]{1,3}$')]
Category = Literal['LOCAL_READ', 'LOCAL_ANALYSIS', 'EXTERNAL_LOOKUP',
    'EXTERNAL_SUBMISSION', 'ACTIVE_PROBE', 'REMOTE_COLLECTION', 'RESPONSE_ACTION']
DataCategory = Literal['PUBLIC_IP', 'TENANT_IP', 'SYNTHETIC_ALERT_QUERY']
Reason = Literal['AUTHORIZED', 'INVALID_INPUT', 'MISSING_POLICY', 'UNKNOWN_PROVIDER',
    'AMBIGUOUS_AUTHORITY', 'UNAUTHORIZED', 'UNSUPPORTED_OPERATION', 'CONSENT_REQUIRED',
    'CONSENT_INVALID', 'LIMIT_EXCEEDED', 'DATA_NOT_MINIMIZED']
MAX_RECORDS = 16
MAX_EVALUATION_BYTES = 65536
MATRIX_VERSION = '1.0'
PROFILE_CLASSIFICATION = {
    'mock_lookup': ('LOCAL_READ', 'lookup', 'R0'),
    'local_query': ('LOCAL_READ', 'query', 'R1'),
    'hunt': ('LOCAL_READ', 'hunt', 'R1'),
    'local_transform': ('LOCAL_ANALYSIS', 'transform', 'R1'),
    'offline_analysis': ('LOCAL_ANALYSIS', 'analyze', 'R2'),
    'rule_draft': ('LOCAL_ANALYSIS', 'draft', 'R1'),
    'external_lookup': ('EXTERNAL_LOOKUP', 'lookup', 'R2'),
    'submission': ('EXTERNAL_SUBMISSION', 'submit', 'R3'),
    'active_scan': ('ACTIVE_PROBE', 'scan', 'R3'),
    'remote_collect': ('REMOTE_COLLECTION', 'collect', 'R3'),
    'response': ('RESPONSE_ACTION', 'respond', 'R4'),
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _aware(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('invalid_time')
    return value.astimezone(timezone.utc)


class _Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid',
                              hide_input_in_errors=True, revalidate_instances='always')
    schema_version: Literal['1.0'] = '1.0'


class Destination(_Contract):
    """Opaque provider/account/destination identity, never a network URL."""
    provider_id: Identifier
    provider_version: Version
    account_id: Identifier
    destination_id: Identifier
    audience: Literal['TENANT_LOCAL', 'EXTERNAL']


class DisclosureField(_Contract):
    name: Annotated[str, Field(min_length=1, max_length=32)]
    category: DataCategory
    value: Annotated[str, Field(min_length=1, max_length=256)]


class _Binding(_Contract):
    matrix_version: Literal['1.0'] = '1.0'
    request: ToolRequest
    destination: Destination
    category: Category
    profile: Identifier
    risk: Literal['R0', 'R1', 'R2', 'R3', 'R4']


class DisclosureScope(_Binding):
    permitted_categories: Annotated[tuple[DataCategory, ...], Field(min_length=1, max_length=3)]
    permitted_fields: Annotated[tuple[Literal['ip', 'integration_id', 'source_index', 'query_context'], ...], Field(min_length=1, max_length=3)]

    @field_validator('permitted_categories', 'permitted_fields')
    @classmethod
    def unique_sorted(cls, values):
        if len(set(values)) != len(values):
            raise ValueError('duplicate_scope')
        return tuple(sorted(values))


class DisclosureIntent(_Binding):
    payload: Annotated[tuple[DisclosureField, ...], Field(min_length=1, max_length=8)]
    expected_output_bytes: Annotated[int, Field(ge=0, le=1048576)]


class ResourceCeilings(_Contract):
    max_input_bytes: Annotated[int, Field(ge=1, le=32768)]
    max_output_bytes: Annotated[int, Field(ge=1, le=1048576)]
    max_disclosures: Annotated[int, Field(ge=0, le=100)]
    max_disclosure_bytes: Annotated[int, Field(ge=0, le=3276800)]


class _Validity(_Contract):
    valid_from: datetime
    valid_until: datetime

    _utc_times = field_validator('valid_from', 'valid_until')(_aware)

    @model_validator(mode='after')
    def ordered(self):
        if self.valid_from >= self.valid_until:
            raise ValueError('invalid_validity')
        return self


class DisclosurePolicy(_Validity):
    policy_id: UUID
    scope: DisclosureScope
    ceilings: ResourceCeilings
    active: bool


class ConsentState(_Validity):
    """Trusted application snapshot; not a user/model consent assertion."""
    consent_id: UUID
    policy_id: UUID
    policy_version: Literal['1.0']
    scope: DisclosureScope
    ceilings: ResourceCeilings
    status: Literal['ACTIVE', 'REVOKED']


class DisclosureUsage(_Contract):
    """Caller-attested counters for exactly this consent window; never updated."""
    tenant_id: UUID
    principal_id: UUID
    destination: Destination
    consent_id: UUID
    window_start: datetime
    window_end: datetime
    used_disclosures: Annotated[int, Field(ge=0, le=1000000000)]
    used_disclosure_bytes: Annotated[int, Field(ge=0, le=1000000000)]

    _utc_times = field_validator('window_start', 'window_end')(_aware)

    @model_validator(mode='after')
    def ordered(self):
        if self.window_start >= self.window_end:
            raise ValueError('invalid_usage_window')
        return self


class DisclosureInputs(_Contract):
    """Trusted caller-supplied assessment inputs, never part of tool payloads."""
    intent: DisclosureIntent
    policies: Annotated[tuple[DisclosurePolicy, ...], Field(max_length=MAX_RECORDS)]
    providers: Annotated[tuple[Destination, ...], Field(max_length=MAX_RECORDS)]
    consents: Annotated[tuple[ConsentState, ...], Field(max_length=MAX_RECORDS)]
    usage: DisclosureUsage | None
    at: datetime

    _utc_time = field_validator('at')(_aware)


class EgressDecision(_Contract):
    outcome: Literal['ALLOW', 'DENY']
    reason: Reason
    executable: Literal[False] = False
    evaluated_at: datetime | None
    evaluation_sha256: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')] | None

    @field_validator('evaluated_at')
    @classmethod
    def aware_or_absent(cls, value):
        return None if value is None else _aware(value)

    @model_validator(mode='after')
    def consistent(self):
        allowed = self.outcome == 'ALLOW'
        if (allowed != (self.reason == 'AUTHORIZED')
                or allowed != (self.evaluation_sha256 is not None)
                or (allowed and self.evaluated_at is None)):
            raise ValueError('invalid_decision')
        return self


class DisclosureValidationError(ValueError):
    """A constant reason code only; never proposed field values."""


def _deny(reason):
    raise DisclosureValidationError(reason)


def _snapshot(value, contract):
    """Bound reconstruction before serialization, including nested forged models."""
    allowed = (TrustedContext, ToolRequest, Destination, DisclosureField, DisclosureScope,
        DisclosureIntent, ResourceCeilings, DisclosurePolicy, ConsentState, DisclosureUsage,
        DisclosureInputs)
    nodes = 0

    def data(item, depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 8 or nodes > 2048:
            _deny('LIMIT_EXCEEDED')
        if type(item) in allowed:
            if item.model_extra or set(item.__dict__) != set(type(item).model_fields):
                _deny('INVALID_INPUT')
            return {key: data(val, depth + 1) for key, val in item.__dict__.items()}
        if type(item) is tuple:
            if len(item) > MAX_RECORDS:
                _deny('LIMIT_EXCEEDED')
            return tuple(data(val, depth + 1) for val in item)
        if type(item) is str:
            if len(item) > 1024:
                _deny('LIMIT_EXCEEDED')
            return item
        if item is None:
            return None
        if type(item) in (UUID, datetime, int, bool):
            return item
        _deny('INVALID_INPUT')

    if type(value) is not contract:
        _deny('INVALID_INPUT')
    return contract.model_validate(data(value))


def _operation(intent):
    expected = PROFILE_CLASSIFICATION.get(intent.profile)
    if (expected != (intent.category, intent.request.operation, intent.risk)
            or intent.category not in ('LOCAL_READ', 'LOCAL_ANALYSIS', 'EXTERNAL_LOOKUP')):
        _deny('UNSUPPORTED_OPERATION')
    external = intent.category == 'EXTERNAL_LOOKUP'
    if (intent.destination.audience == 'EXTERNAL') != external:
        _deny('UNSUPPORTED_OPERATION')
    return external


def _matches(intent, scope):
    return all(getattr(intent, key) == getattr(scope, key) for key in _Binding.model_fields)


def _validate_synthetic_search(intent, scope):
    if (intent.category != 'LOCAL_READ' or intent.profile != 'local_query' or intent.risk != 'R1'
            or len(intent.payload) != 3 or scope.permitted_categories != ('SYNTHETIC_ALERT_QUERY',)
            or scope.permitted_fields != ('integration_id', 'query_context', 'source_index')):
        _deny('DATA_NOT_MINIMIZED')
    fields = {item.name: item.value for item in intent.payload}
    if (set(fields) != set(scope.permitted_fields)
            or any(item.category != 'SYNTHETIC_ALERT_QUERY' for item in intent.payload)
            or fields['integration_id'] != intent.request.target):
        _deny('DATA_NOT_MINIMIZED')
    binding = wazuh_gateway.WazuhSourceBinding(tenant_id=intent.request.tenant_id,
        principal_id=intent.request.principal_id, integration_id=UUID(intent.request.target),
        source_index=fields['source_index'], source_scope='DEDICATED_SYNTHETIC')
    # This checks proposal shape; only the gateway verifies trusted source ownership.
    wazuh_gateway._parse_search(intent.request, binding)
    if fields['query_context'] != dict(intent.request.parameters)['query_context']:
        _deny('DATA_NOT_MINIMIZED')


def validate_disclosure(intent: DisclosureIntent, scope: DisclosureScope,
                        ceilings: ResourceCeilings) -> int:
    """Validate IP or closed synthetic-query fields; return only their byte count.

    Parameters are local control metadata only. No parameter or other request
    context is implicitly part of the disclosure. This does not grant authority.
    """
    try:
        intent = _snapshot(intent, DisclosureIntent)
        scope = _snapshot(scope, DisclosureScope)
        ceilings = _snapshot(ceilings, ResourceCeilings)
        external = _operation(intent)
        if not _matches(intent, scope):
            _deny('UNAUTHORIZED')
        if intent.request.capability_id == wazuh_gateway.CAPABILITY_ID:
            _validate_synthetic_search(intent, scope)
        else:
            controls = {'purpose': 'investigation', 'format': 'summary'}
            if intent.profile == 'mock_lookup':
                if (intent.request.capability_id != 'mock.ip_reputation'
                        or intent.request.capability_version != '1.0'
                        or intent.request.parameters != (('dataset', 'synthetic-v1'),)):
                    _deny('UNAUTHORIZED')
                controls = {'dataset': 'synthetic-v1'}
            if any(controls.get(key) != value for key, value in intent.request.parameters):
                _deny('DATA_NOT_MINIMIZED')
            if len(intent.payload) != 1:
                _deny('DATA_NOT_MINIMIZED')
            field = intent.payload[0]
            if (field.name != 'ip' or field.name not in scope.permitted_fields
                    or field.category not in ('PUBLIC_IP', 'TENANT_IP')
                    or field.category not in scope.permitted_categories
                    or field.value != intent.request.target):
                _deny('DATA_NOT_MINIMIZED')
            address = ip_address(field.value)
            public = (address.is_global and not address.is_multicast and not address.is_reserved
                      and not address.is_private and not address.is_loopback and not address.is_link_local
                      and not address.is_unspecified and not getattr(address, 'is_site_local', False)
                      and not getattr(address, 'ipv4_mapped', None)
                      and not getattr(address, 'sixtofour', None) and not getattr(address, 'teredo', None))
            if ((field.category == 'PUBLIC_IP' and not public)
                    or (external and (field.category != 'PUBLIC_IP' or not public))):
                _deny('DATA_NOT_MINIMIZED')
        payload_bytes = len(_canonical([item.model_dump(mode='json') for item in intent.payload]))
        if (len(_canonical(intent.model_dump(mode='json'))) > ceilings.max_input_bytes
                or intent.expected_output_bytes > ceilings.max_output_bytes
                or (external and payload_bytes > ceilings.max_disclosure_bytes)):
            _deny('LIMIT_EXCEEDED')
        return payload_bytes
    except DisclosureValidationError:
        raise
    except Exception:
        raise DisclosureValidationError('INVALID_INPUT') from None


def _evaluation_bytes(context, intent, *, policies, providers, consents, usage, at):
    """Canonical binding shared by assessment and the gateway's decision check."""
    snapshots = [context, intent, *policies, *providers, *consents]
    if usage is not None:
        snapshots.append(usage)
    return _canonical({'at': at.isoformat(),
        'inputs': [item.model_dump(mode='json') for item in snapshots]})


def evaluate_disclosure(context: TrustedContext, intent: DisclosureIntent, *,
                        policies=None, providers=None, consents=(), usage=None,
                        at: datetime) -> EgressDecision:
    """Pure fail-closed assessment at a caller-supplied trusted time.

    Policies are the explicit capability/version/operation allowlist, providers
    are the destination allowlist, and consent/usage are trusted snapshots.
    An ALLOW never calls TG-01 or a tool and cannot be reused as execution consent.
    """
    evaluated_at = None
    try:
        evaluated_at = _aware(at)
        context = _snapshot(context, TrustedContext)
        intent = _snapshot(intent, DisclosureIntent)
        external = _operation(intent)
        if (intent.request.tenant_id != context.tenant_id
                or intent.request.principal_id != context.principal_id):
            _deny('UNAUTHORIZED')
        if policies is None:
            _deny('MISSING_POLICY')
        for records in (policies, providers, consents):
            if type(records) is not tuple or len(records) > MAX_RECORDS:
                _deny('INVALID_INPUT')
        if not policies:
            _deny('MISSING_POLICY')
        policies = tuple(_snapshot(item, DisclosurePolicy) for item in policies)
        providers = tuple(_snapshot(item, Destination) for item in providers)
        consents = tuple(_snapshot(item, ConsentState) for item in consents)
        if (len({item.policy_id for item in policies}) != len(policies)
                or len({item.destination_id for item in providers}) != len(providers)
                or len({item.consent_id for item in consents}) != len(consents)):
            _deny('AMBIGUOUS_AUTHORITY')
        if intent.destination not in providers:
            _deny('UNKNOWN_PROVIDER')
        if any(item.scope.request.tenant_id != context.tenant_id
               or item.scope.request.principal_id != context.principal_id for item in policies):
            _deny('UNAUTHORIZED')
        matching = tuple(item for item in policies if _matches(intent, item.scope))
        if len(matching) > 1:
            _deny('AMBIGUOUS_AUTHORITY')
        if not matching:
            _deny('UNAUTHORIZED')
        policy, = matching
        if not policy.active or not policy.valid_from <= evaluated_at < policy.valid_until:
            _deny('UNAUTHORIZED')
        effective = policy.ceilings
        consent = None
        if external:
            if not consents:
                _deny('CONSENT_REQUIRED')
            if len(consents) != 1:
                _deny('AMBIGUOUS_AUTHORITY')
            consent, = consents
            if (consent.status != 'ACTIVE' or consent.scope != policy.scope
                    or consent.policy_id != policy.policy_id
                    or consent.policy_version != policy.schema_version
                    or not policy.valid_from <= consent.valid_from < consent.valid_until <= policy.valid_until
                    or not consent.valid_from <= evaluated_at < consent.valid_until):
                _deny('CONSENT_INVALID')
            effective = ResourceCeilings(**{key: min(getattr(policy.ceilings, key),
                getattr(consent.ceilings, key)) for key in ResourceCeilings.model_fields
                if key != 'schema_version'})
            usage = _snapshot(usage, DisclosureUsage)
            if (usage.tenant_id != context.tenant_id or usage.principal_id != context.principal_id
                    or usage.destination != intent.destination or usage.consent_id != consent.consent_id
                    or usage.window_start != consent.valid_from or usage.window_end != consent.valid_until):
                _deny('CONSENT_INVALID')
            if effective.max_output_bytes > 262144:
                _deny('LIMIT_EXCEEDED')
        elif consents or usage is not None or effective.max_disclosures or effective.max_disclosure_bytes:
            _deny('UNAUTHORIZED')
        payload_bytes = validate_disclosure(intent, policy.scope, effective)
        if external and (usage.used_disclosures + 1 > effective.max_disclosures
                or usage.used_disclosure_bytes + payload_bytes > effective.max_disclosure_bytes):
            _deny('LIMIT_EXCEEDED')
        serialized = _evaluation_bytes(context, intent, policies=policies, providers=providers,
            consents=consents, usage=usage, at=evaluated_at)
        if len(serialized) > MAX_EVALUATION_BYTES:
            _deny('LIMIT_EXCEEDED')
        return EgressDecision(outcome='ALLOW', reason='AUTHORIZED', evaluated_at=evaluated_at,
                             evaluation_sha256=hashlib.sha256(serialized).hexdigest())
    except DisclosureValidationError as error:
        reason = error.args[0]
    except Exception:
        reason = 'INVALID_INPUT'
    return EgressDecision(outcome='DENY', reason=reason, evaluated_at=evaluated_at,
                         evaluation_sha256=None)
