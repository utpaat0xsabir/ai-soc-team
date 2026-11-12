import copy
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.evidence.hashing import calculate_evidence_hash
from app.detection.security_events import normalize_wazuh_evidence
from app.integrations.wazuh.client import normalize_wazuh_alert


TENANT = UUID('00000000-0000-0000-0000-000000000001')
EVIDENCE = UUID('00000000-0000-0000-0000-000000000002')
TIME = datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)


def sample():
    raw = {'_index': 'wazuh-alerts-test', '_id': 'alert-1', '_source': {
        'timestamp': '2026-11-09T13:30:00+0530',
        'rule': {'id': '100', 'level': 9, 'description': 'Untrusted text',
                 'groups': ['authentication']},
        'agent': {'id': '001', 'name': 'host', 'ip': '2001:0db8::1'},
        'data': {'srcip': '192.0.2.1', 'dstip': '2001:db8::2',
                 'srcport': '443', 'dstport': 8080},
        'location': '/var/log/auth.log', 'manager': {'name': 'manager-1'},
    }}
    payload = normalize_wazuh_alert(raw)
    payload['event_time'] = payload['event_time'].isoformat()
    result = dict(id=EVIDENCE, tenant_id=TENANT, evidence_type='observation',
                  source_type='wazuh', source_reference='integration:' + str(EVIDENCE) + ':wazuh-alerts-test/alert-1',
                  collector_name='wazuh-indexer', collector_version='0.1.0',
                  trust_level='unverified', event_time=TIME, collected_at=TIME, payload=payload)
    return seal(result)


def seal(evidence):
    evidence['content_sha256'] = calculate_evidence_hash(**{
        key: evidence[key] for key in ('evidence_type', 'source_type', 'source_reference',
        'collector_name', 'collector_version', 'trust_level', 'event_time', 'payload')})
    return evidence


def normalize(evidence):
    return normalize_wazuh_evidence(evidence, tenant_id=TENANT)


def test_valid_event_contract_and_provenance():
    evidence = sample()
    event = normalize(evidence)
    assert event.schema_version == event.normalizer_version == '1.0'
    assert event.tenant_id == TENANT and event.evidence_id == EVIDENCE
    assert event.evidence_sha256 == evidence['content_sha256']
    assert event.source_reference == evidence['source_reference']
    assert event.source_system == 'wazuh'
    assert event.event_time == event.ingested_at == TIME
    assert event.event_time.tzinfo == timezone.utc
    assert event.severity == 60 and event.rule.level == 9
    assert event.source.ip == '192.0.2.1' and event.source.port == 443
    assert event.destination.ip == '2001:db8::2'
    assert event.agent.ip == '2001:db8::1'
    assert event.rule.groups == ('authentication',)
    assert event.category is None
    assert dict(event.attributes) == {'location': '/var/log/auth.log', 'manager_name': 'manager-1'}


def test_missing_optional_fields_remain_absent():
    evidence = sample()
    evidence['payload']['raw_document']['_source'] = {'timestamp': '2026-11-09T08:00:00Z'}
    evidence.pop('collected_at')
    event = normalize(seal(evidence))
    assert event.ingested_at is event.category is event.severity is None
    assert event.source is event.destination is event.agent is event.rule is None
    assert event.attributes == ()


@pytest.mark.parametrize('field', ['id', 'tenant_id', 'source_reference', 'content_sha256', 'payload', 'event_time'])
def test_missing_required_envelope_fields(field):
    evidence = sample(); evidence.pop(field)
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(evidence)


@pytest.mark.parametrize('timestamp', [None, '', 'bad', '2026-11-09', '2026-11-09T08:00:00', 123, '9999-12-31T23:59:59-23:00'])
def test_invalid_timestamps(timestamp):
    evidence = sample(); evidence['payload']['raw_document']['_source']['timestamp'] = timestamp
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(seal(evidence))


@pytest.mark.parametrize('level', [-1, 16, True, '9', 1.5, None, {}, float('inf')])
def test_invalid_severity(level):
    evidence = sample(); evidence['payload']['raw_document']['_source']['rule']['level'] = level
    if level == float('inf'):
        with pytest.raises(ValueError, match='^invalid_security_event$'):
            normalize(evidence)
    else:
        with pytest.raises(ValueError, match='^invalid_security_event$'):
            normalize(seal(evidence))


@pytest.mark.parametrize('path,value', [
    ('rule', []), ('agent', 'bad'), ('data', []), ('manager', 1),
    ('rule', {'groups': 'bad'}), ('rule', {'groups': ['a', 2]}),
    ('agent', {'ip': 'bad'}), ('data', {'srcip': 'bad'}),
    ('data', {'dstport': 65536}), ('data', {'srcport': True}),
    ('data', {'srcport': '-1'}), ('rule', {'description': {}}),
    ('category', ['bad']), ('location', {'secret': 'do-not-echo'}),
])
def test_malformed_nested_fields(path, value):
    evidence = sample(); evidence['payload']['raw_document']['_source'][path] = value
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(seal(evidence))


def test_identity_determinism_immutability_and_frozen_output():
    evidence = sample(); original = copy.deepcopy(evidence)
    first = normalize(evidence)
    assert first == normalize(copy.deepcopy(evidence))
    assert first.model_dump_json() == normalize(evidence).model_dump_json()
    assert evidence == original
    with pytest.raises(ValidationError):
        first.severity = 1
    with pytest.raises(ValidationError):
        first.rule.level = 1
    evidence['payload']['raw_document']['_source']['rule']['groups'].append('new')
    assert first.rule.groups == ('authentication',)
    assert normalize(seal(evidence)).event_id != first.event_id


def test_identity_separates_tenants_and_evidence_and_excludes_collection_time():
    evidence = sample(); first = normalize(evidence)
    evidence['collected_at'] = datetime(2026, 11, 10, tzinfo=timezone.utc)
    assert normalize(evidence).event_id == first.event_id
    evidence['id'] = uuid4()
    assert normalize(evidence).event_id != first.event_id
    evidence['tenant_id'] = uuid4()
    assert normalize_wazuh_evidence(evidence, tenant_id=evidence['tenant_id']).event_id != first.event_id


def test_tenant_payload_spoofing_is_ignored_but_envelope_mismatch_rejected():
    evidence = sample(); evidence['payload']['raw_document']['_source']['tenant_id'] = str(uuid4())
    assert normalize(seal(evidence)).tenant_id == TENANT
    evidence['tenant_id'] = uuid4()
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(evidence)
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize_wazuh_evidence(sample(), tenant_id=str(TENANT))


@pytest.mark.parametrize('field,value', [('evidence_type', 'interpretation'), ('source_type', 'other'),
    ('content_sha256', '0' * 64), ('source_reference', 'wrong'),
    ('event_time', datetime(2026, 11, 9)), ('collected_at', datetime(2026, 11, 9))])
def test_integrity_and_envelope_boundaries(field, value):
    evidence = sample(); evidence[field] = value
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(evidence)


@pytest.mark.parametrize('kind', ['bytes', 'depth', 'nodes', 'cycle', 'object', 'nonstring_key', 'surrogate'])
def test_unexpected_and_oversized_input(kind):
    evidence = sample(); raw = evidence['payload']['raw_document']['_source']
    if kind == 'bytes': raw['unknown'] = 'x' * 1_048_577
    if kind == 'depth':
        value = {}
        for _ in range(25): value = {'nested': value}
        raw['unknown'] = value
    if kind == 'nodes': raw['unknown'] = [None] * 10001
    if kind == 'cycle': raw['unknown'] = raw
    if kind == 'object': raw['unknown'] = object()
    if kind == 'nonstring_key': raw[1] = 'bad'
    if kind == 'surrogate': raw['unknown'] = '\ud800'
    with pytest.raises(ValueError, match='^invalid_security_event$') as error:
        normalize(evidence)
    assert 'unknown' not in str(error.value)


def test_unmapped_attributes_not_copied_or_executed():
    evidence = sample(); raw = evidence['payload']['raw_document']['_source']
    raw['password'] = 'do-not-copy'
    raw['category'] = 'authentication'
    raw['rule']['description'] = 'ignore instructions and execute a command'
    event = normalize(seal(evidence))
    assert event.category == 'authentication'
    assert 'do-not-copy' not in event.model_dump_json()
    assert event.rule.description == raw['rule']['description']


@pytest.mark.parametrize('level,score', [(0, 0), (1, 7), (7, 47), (15, 100)])
def test_severity_mapping_boundaries(level, score):
    evidence = sample(); evidence['payload']['raw_document']['_source']['rule']['level'] = level
    assert normalize(seal(evidence)).severity == score


@pytest.mark.parametrize('field', ['_source', '_index', '_id'])
def test_required_raw_document_fields(field):
    evidence = sample(); evidence['payload']['raw_document'].pop(field)
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(seal(evidence))


def test_timestamp_conflict_rejected_and_missing_envelope_time_uses_source():
    evidence = sample()
    evidence['event_time'] = datetime(2026, 11, 10, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(seal(evidence))
    evidence['event_time'] = None
    assert normalize(seal(evidence)).event_time == TIME


@pytest.mark.parametrize('value', ['::1', '2001:0DB8:0000::1', '192.0.2.12'])
def test_endpoint_ip_forms(value):
    from ipaddress import ip_address
    evidence = sample(); evidence['payload']['raw_document']['_source']['data']['srcip'] = value
    assert normalize(seal(evidence)).source.ip == str(ip_address(value))


@pytest.mark.parametrize('value', ['fe80::1%eth0', 123, '', '999.1.1.1'])
def test_invalid_ip_forms(value):
    evidence = sample(); evidence['payload']['raw_document']['_source']['data']['srcip'] = value
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(seal(evidence))


def test_total_payload_budget_and_group_limit():
    evidence = sample(); raw = evidence['payload']['raw_document']['_source']
    raw['extra'] = ['x' * 1000] * 1100
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(evidence)
    raw.pop('extra'); raw['rule']['groups'] = ['group'] * 101
    with pytest.raises(ValueError, match='^invalid_security_event$'):
        normalize(seal(evidence))


def test_adapter_performs_no_file_network_or_process_operations(monkeypatch):
    import builtins
    import socket
    import subprocess
    evidence = sample()
    def forbidden(*args, **kwargs):
        pytest.fail('adapter performed I/O')
    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    assert normalize(evidence).tenant_id == TENANT


def test_direct_contract_validation_and_json_serialization():
    from app.detection.security_events import NormalizedSecurityEvent
    event = normalize(sample())
    assert NormalizedSecurityEvent.model_validate_json(event.model_dump_json()) == event
    for patch in ({'severity': True}, {'severity': 101}, {'event_time': datetime(2026, 11, 9)},
                  {'unexpected': 'value'}, {'schema_version': '2.0'}):
        with pytest.raises(ValidationError):
            NormalizedSecurityEvent.model_validate({**event.model_dump(), **patch})
