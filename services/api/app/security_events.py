"""Pure, versioned event derivation from an explicit evidence snapshot.

No ORM access or I/O. Callers supply authenticated tenant context and snapshot
metadata from a trusted store; a matching content hash is integrity, not proof
of authenticity. Descriptions/attributes remain untrusted text.
"""

from datetime import datetime, timezone
import hmac
from ipaddress import ip_address
import math
import re
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.evidence import calculate_evidence_hash
from app.wazuh import parse_wazuh_timestamp


Text = Annotated[str, Field(min_length=1, max_length=4096)]
Port = Annotated[int, Field(ge=0, le=65535)]
NAMESPACE = UUID('c4136cf6-5e26-45d2-af26-12e91c9aab4b')
MAX_PAYLOAD_BYTES = 1_048_576
MAX_PAYLOAD_NODES = 10_000
MAX_PAYLOAD_DEPTH = 20


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('invalid_security_event')
    return value.astimezone(timezone.utc)


def _ip(value):
    if type(value) is not str or '%' in value:
        raise ValueError('invalid_security_event')
    return str(ip_address(value))


class _Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid', hide_input_in_errors=True)


class EventEndpoint(_Contract):
    ip: Text | None = None
    port: Port | None = None

    _validate_ip = field_validator('ip')(lambda value: None if value is None else _ip(value))


class EventAgent(_Contract):
    id: Text | None = None
    name: Text | None = None
    ip: Text | None = None

    _validate_ip = field_validator('ip')(lambda value: None if value is None else _ip(value))


class EventRule(_Contract):
    id: Text | None = None
    level: Annotated[int, Field(ge=0, le=15)] | None = None
    description: Text | None = None
    groups: Annotated[tuple[Text, ...], Field(max_length=100)] | None = None


class NormalizedSecurityEvent(_Contract):
    schema_version: Literal['1.0'] = '1.0'
    normalizer_version: Literal['1.0'] = '1.0'
    event_id: UUID
    tenant_id: UUID
    evidence_id: UUID
    evidence_sha256: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
    source_system: Annotated[str, Field(min_length=1, max_length=100)]
    source_reference: Annotated[str, Field(min_length=1, max_length=500)]
    event_time: datetime
    ingested_at: datetime | None = None
    category: Text | None = None
    severity: Annotated[int, Field(ge=0, le=100)] | None = None
    source: EventEndpoint | None = None
    destination: EventEndpoint | None = None
    agent: EventAgent | None = None
    rule: EventRule | None = None
    # Sorted immutable key/value pairs; deliberately no arbitrary raw payload.
    attributes: Annotated[tuple[tuple[Text, Text], ...], Field(max_length=10)] = ()

    _event_utc = field_validator('event_time')(_utc)
    _ingestion_utc = field_validator('ingested_at')(lambda value: None if value is None else _utc(value))


class _Evidence(_Contract):
    # Only explicit snapshots, never live ORM objects or implicit lazy loads.
    model_config = ConfigDict(strict=True, frozen=True, extra='ignore', hide_input_in_errors=True)
    id: UUID
    tenant_id: UUID
    evidence_type: Literal['observation']
    source_type: Literal['wazuh']
    source_reference: Annotated[str, Field(min_length=1, max_length=500)]
    collector_name: Annotated[str, Field(min_length=1, max_length=150)]
    collector_version: Annotated[str, Field(min_length=1, max_length=100)]
    trust_level: Literal['unverified', 'source_verified', 'system_verified']
    event_time: datetime | None
    collected_at: datetime | None = None
    payload: dict
    content_sha256: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]

    _event_utc = field_validator('event_time')(lambda value: None if value is None else _utc(value))
    _collection_utc = field_validator('collected_at')(lambda value: None if value is None else _utc(value))


def _bounded_json(payload):
    """Reject cycles/deep/large/non-JSON data before serialization or hashing.

    Budget is conservative JSON UTF-8 size including worst-case string escaping.
    Iteration stops at the budget; no copying or unbounded serialization first.
    """
    nodes = 0
    budget = MAX_PAYLOAD_BYTES

    def visit(value, depth):
        nonlocal nodes, budget
        nodes += 1
        if nodes > MAX_PAYLOAD_NODES or depth > MAX_PAYLOAD_DEPTH:
            raise ValueError('invalid_security_event')
        if type(value) is str:
            if len(value) > MAX_PAYLOAD_BYTES:
                raise ValueError('invalid_security_event')
            budget -= 2 + max(len(value.encode('utf-8')), len(value) * 6)
        elif type(value) is dict:
            budget -= 2 + 2 * len(value)
            if budget < 0:
                raise ValueError('invalid_security_event')
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError('invalid_security_event')
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif type(value) is list:
            budget -= 2 + len(value)
            if budget < 0:
                raise ValueError('invalid_security_event')
            for item in value:
                visit(item, depth + 1)
        elif value is None or type(value) is bool:
            budget -= 5
        elif type(value) is int:
            if value.bit_length() > 64:
                raise ValueError('invalid_security_event')
            budget -= 21
        elif type(value) is float and math.isfinite(value):
            budget -= 32
        else:
            raise ValueError('invalid_security_event')
        if budget < 0:
            raise ValueError('invalid_security_event')

    visit(payload, 0)


def _object(parent, key):
    if key not in parent:
        return {}
    value = parent[key]
    if type(value) is not dict:
        raise ValueError('invalid_security_event')
    return value


def _text(value):
    if type(value) is not str or not value.strip() or len(value) > 4096:
        raise ValueError('invalid_security_event')
    return value


def _fields(source, names):
    return {name: _text(source[name]) for name in names if name in source}


def _endpoint(data, prefix):
    fields = {}
    if prefix + 'ip' in data:
        fields['ip'] = _ip(data[prefix + 'ip'])
    if prefix + 'port' in data:
        port = data[prefix + 'port']
        if type(port) is str and re.fullmatch(r'[0-9]{1,5}', port):
            port = int(port)
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError('invalid_security_event')
        fields['port'] = port
    return EventEndpoint(**fields) if fields else None


def normalize_wazuh_evidence(evidence: dict, *, tenant_id: UUID) -> NormalizedSecurityEvent:
    """Derive one event; any invalid input raises only a safe fixed error.

    Identity includes tenant, evidence ID/hash and adapter version, excluding
    collection time. Severity v1 = round-half-up(level * 100 / 15), no confidence
    or category inference. Missing optional fields stay None; malformed supplied
    mapped fields are rejected. Unknown JSON fields stay only in original evidence.
    """
    try:
        if type(evidence) is not dict or type(tenant_id) is not UUID:
            raise ValueError('invalid_security_event')
        _bounded_json(evidence.get('payload'))
        snapshot = _Evidence.model_validate(evidence)
        if snapshot.tenant_id != tenant_id:
            raise ValueError('invalid_security_event')
        digest = calculate_evidence_hash(**snapshot.model_dump(include={
            'evidence_type', 'source_type', 'source_reference', 'collector_name',
            'collector_version', 'trust_level', 'event_time', 'payload'}))
        if not hmac.compare_digest(digest, snapshot.content_sha256):
            raise ValueError('invalid_security_event')
        raw = _object(snapshot.payload, 'raw_document')
        source = _object(raw, '_source')
        index, document_id = _text(raw['_index']), _text(raw['_id'])
        reference = index + '/' + document_id
        if snapshot.source_reference != reference:
            prefix, integration_id, suffix = snapshot.source_reference.split(':', 2)
            if prefix != 'integration' or str(UUID(integration_id)) != integration_id or suffix != reference:
                raise ValueError('invalid_security_event')
        timestamp = parse_wazuh_timestamp(source.get('timestamp'))
        timestamp = _utc(timestamp)
        if snapshot.event_time is not None and snapshot.event_time != timestamp:
            raise ValueError('invalid_security_event')
        rule = _object(source, 'rule')
        rule_fields = _fields(rule, ('id', 'description'))
        if 'level' in rule:
            if type(rule['level']) is not int or not 0 <= rule['level'] <= 15:
                raise ValueError('invalid_security_event')
            rule_fields['level'] = rule['level']
        if 'groups' in rule:
            groups = rule['groups']
            if type(groups) is not list or len(groups) > 100:
                raise ValueError('invalid_security_event')
            rule_fields['groups'] = tuple(_text(group) for group in groups)
        agent = _object(source, 'agent')
        agent_fields = _fields(agent, ('id', 'name'))
        if 'ip' in agent:
            agent_fields['ip'] = _ip(agent['ip'])
        data = _object(source, 'data')
        manager = _object(source, 'manager')
        attributes = _fields(source, ('location',))
        if 'name' in manager:
            attributes['manager_name'] = _text(manager['name'])
        return NormalizedSecurityEvent(
            event_id=uuid5(NAMESPACE, f'1.0:{tenant_id}:{snapshot.id}:{digest}'),
            tenant_id=tenant_id, evidence_id=snapshot.id, evidence_sha256=digest,
            source_system='wazuh', source_reference=snapshot.source_reference,
            event_time=timestamp, ingested_at=snapshot.collected_at,
            category=_text(source['category']) if 'category' in source else None,
            severity=(rule['level'] * 100 + 7) // 15 if 'level' in rule else None,
            source=_endpoint(data, 'src'), destination=_endpoint(data, 'dst'),
            agent=EventAgent(**agent_fields) if agent_fields else None,
            rule=EventRule(**rule_fields) if rule_fields else None,
            attributes=tuple(sorted(attributes.items())),
        )
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError('invalid_security_event') from None
