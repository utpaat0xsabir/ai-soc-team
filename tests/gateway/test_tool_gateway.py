"""TG-01 regressions with explicit TG-03B disclosure authority for dispatch."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.gateway import tool_gateway as gateway
from app.gateway import disclosure_policy as disclosure


TENANT, PRINCIPAL, REQUEST = UUID(int=1), UUID(int=2), UUID(int=3)


def inputs():
    context = gateway.TrustedContext(tenant_id=TENANT, principal_id=PRINCIPAL)
    request = gateway.ToolRequest(request_id=REQUEST, tenant_id=TENANT,
        principal_id=PRINCIPAL, capability_id='mock.ip_reputation', capability_version='1.0',
        operation='lookup', target='192.0.2.1', parameters=(('dataset', 'synthetic-v1'),))
    grant = gateway.ToolGrant(grant_id=UUID(int=4), tenant_id=TENANT, principal_id=PRINCIPAL,
        capability_id=request.capability_id, capability_version='1.0', operation='lookup',
        target=request.target, parameters=request.parameters, risk='passive',
        read_only=True, disclosure_consent=False)
    return context, request, (grant,)


def authorization(request):
    # Invalid-request tests still receive a separate valid disclosure fixture;
    # only the dispatcher decides whether either input authorizes the operation.
    try:
        request = gateway._checked(request, gateway.ToolRequest)
    except ValueError:
        request = inputs()[1]
    now = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)
    destination = gateway.MOCK_DESTINATION
    scope = disclosure.DisclosureScope(request=request, destination=destination,
        category='LOCAL_READ', profile='mock_lookup', risk='R0',
        permitted_categories=('TENANT_IP',), permitted_fields=('ip',))
    limits = disclosure.ResourceCeilings(max_input_bytes=32768, max_output_bytes=2048,
        max_disclosures=0, max_disclosure_bytes=0)
    policy = disclosure.DisclosurePolicy(policy_id=UUID(int=41), scope=scope,
        ceilings=limits, active=True, valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1))
    intent = disclosure.DisclosureIntent(request=request, destination=destination,
        category='LOCAL_READ', profile='mock_lookup', risk='R0',
        payload=(disclosure.DisclosureField(name='ip', category='TENANT_IP', value=request.target),),
        expected_output_bytes=2048)
    return disclosure.DisclosureInputs(intent=intent, policies=(policy,),
        providers=(destination,), consents=(), usage=None, at=now)


def execute(context=None, request=None, policy=None, registry=None):
    default_context, default_request, default_policy = inputs()
    audit, evidence = [], []
    result = gateway.execute(context or default_context, request or default_request,
        policy=default_policy if policy is None else policy,
        registry=(gateway.MOCK_CAPABILITY,) if registry is None else registry,
        audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request or default_request))
    return result, audit, evidence


def spy(monkeypatch):
    calls = []
    original = gateway.mock_ip_reputation
    def adapter(target):
        calls.append(target)
        return original(target)
    monkeypatch.setattr(gateway, 'mock_ip_reputation', adapter)
    return calls


def test_success_is_synthetic_deterministic_and_evidence_bound():
    result, audit, evidence = execute()
    repeated, _, _ = execute()
    assert result == repeated and result.label == 'SYNTHETIC / TEST ONLY'
    assert result.verdict == 'unknown' and result.source == 'mock.ip_reputation'
    assert result.tenant_id == TENANT and result.principal_id == PRINCIPAL
    assert result.request_id == REQUEST and result.capability_version == '1.0'
    assert len(result.request_sha256) == len(result.result_sha256) == 64
    assert evidence == [result] and audit[0].outcome == 'allowed'
    assert audit[0].request_sha256 == result.request_sha256
    assert gateway.ToolResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize('change', [
    {'tenant_id': UUID(int=9)}, {'principal_id': UUID(int=9)},
    {'capability_id': 'shell'}, {'capability_version': '2.0'},
    {'operation': 'submit'}, {'target': '192.0.2.2'},
    {'parameters': (('dataset', 'other'),)},
])
def test_modified_requests_deny_before_dispatch(monkeypatch, change):
    calls = spy(monkeypatch)
    context, request, policy = inputs()
    audit, evidence = [], []
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request.model_copy(update=change), policy=policy,
            registry=(gateway.MOCK_CAPABILITY,), audit_sink=audit, evidence_sink=evidence,
            disclosure=authorization(request))
    assert calls == [] and evidence == [] and audit[0].outcome == 'denied'


@pytest.mark.parametrize('change', [
    {'tenant_id': UUID(int=9)}, {'principal_id': UUID(int=9)},
    {'capability_id': 'other'}, {'capability_version': '2.0'}, {'operation': 'scan'},
    {'target': '192.0.2.2'}, {'parameters': (('dataset', 'other'),)},
    {'risk': 'active'}, {'read_only': False}, {'disclosure_consent': True},
])
def test_grants_bind_every_authorization_dimension(monkeypatch, change):
    calls = spy(monkeypatch)
    context, request, policy = inputs()
    with pytest.raises(gateway.GatewayError):
        execute(context, request, (policy[0].model_copy(update=change),))
    assert calls == []


@pytest.mark.parametrize('kind', ['missing_policy', 'empty_policy', 'missing_registry',
    'empty_registry', 'duplicate_registry', 'duplicate_grant', 'conflicting_grant',
    'duplicate_authorization', 'mixed_tenant', 'unregistered_capability'])
def test_absent_or_ambiguous_authority_denies(monkeypatch, kind):
    calls = spy(monkeypatch)
    context, request, policy = inputs()
    registry = (gateway.MOCK_CAPABILITY,)
    if kind == 'missing_policy': policy = None
    if kind == 'empty_policy': policy = ()
    if kind == 'missing_registry': registry = None
    if kind == 'empty_registry': registry = ()
    if kind == 'duplicate_registry': registry *= 2
    if kind == 'duplicate_grant': policy *= 2
    if kind == 'conflicting_grant': policy += (policy[0].model_copy(update={'target': '192.0.2.2'}),)
    if kind == 'duplicate_authorization': policy += (policy[0].model_copy(update={'grant_id': uuid4()}),)
    if kind == 'mixed_tenant': policy += (policy[0].model_copy(update={'grant_id': uuid4(), 'tenant_id': uuid4()}),)
    if kind == 'unregistered_capability': registry = (gateway.MOCK_CAPABILITY.model_copy(update={'version': '2.0'}),)
    audit, evidence = [], []
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request, policy=policy, registry=registry,
                        audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    assert calls == [] and evidence == [] and audit[0].outcome == 'denied'


@pytest.mark.parametrize('field,value', [
    ('target', 'https://example.test'), ('target', 'x' * 10000),
    ('target', 'fe80::1%eth0'), ('parameters', (('dataset', 'x' * 10000),)),
    ('parameters', (('dataset', 'synthetic-v1'),) * 2),
    ('schema_version', '2.0'), ('tenant_id', str(TENANT)),
    ('authority', 'admin'), ('grants', ('all',)), ('tier', 'L3'),
])
def test_untrusted_request_validation(field, value):
    _, request, _ = inputs()
    with pytest.raises(ValidationError):
        gateway.ToolRequest.model_validate({**request.model_dump(), field: value})


def test_ipv6_canonicalization_and_parameter_order():
    _, request, policy = inputs()
    data = {**request.model_dump(), 'target': '2001:0db8::0001'}
    request = gateway.ToolRequest.model_validate(data)
    grant = gateway.ToolGrant.model_validate({**policy[0].model_dump(), 'target': '2001:db8::1'})
    result, _, _ = execute(request=request, policy=(grant,))
    assert result.target == '2001:db8::1'
    other = gateway.ToolRequest.model_validate({**request.model_dump(),
        'parameters': (('z', 'last'), ('a', 'first'))})
    assert other.parameters == (('a', 'first'), ('z', 'last'))


def test_contracts_are_frozen_and_nested_values_are_immutable():
    context, request, policy = inputs()
    result, audit, _ = execute()
    for contract in (context, request, policy[0], gateway.MOCK_CAPABILITY, result, audit[0]):
        with pytest.raises(ValidationError):
            contract.schema_version = '1.0'
        assert type(contract).model_validate_json(contract.model_dump_json()) == contract
    with pytest.raises(TypeError): request.parameters[0] = ('dataset', 'other')


@pytest.mark.parametrize('kind', ['raw_dict', 'forged_instance', 'extra_authority', 'mutable_parameters'])
def test_bypassed_model_validation_is_rechecked(monkeypatch, kind):
    calls = spy(monkeypatch)
    context, request, policy = inputs()
    if kind == 'raw_dict': request = request.model_dump()
    if kind == 'forged_instance': request = gateway.ToolRequest.model_construct(**{**request.model_dump(), 'target': 'x' * 10000})
    if kind == 'extra_authority': request.__dict__['authority'] = 'admin'
    if kind == 'mutable_parameters': request = request.model_copy(update={'parameters': [['dataset', 'synthetic-v1']]})
    with pytest.raises(gateway.GatewayError): execute(context, request, policy)
    assert calls == []


@pytest.mark.parametrize('kind', ['wrong_target', 'wrong_label', 'live_source', 'oversized', 'raw_dict', 'exception'])
def test_unsafe_adapter_output_never_reaches_evidence(monkeypatch, kind):
    calls = []
    def unsafe(target):
        calls.append(target)
        if kind == 'exception': raise RuntimeError('SECRET upstream message')
        observation = gateway.ToolObservation(target=target)
        if kind == 'wrong_target': return observation.model_copy(update={'target': '192.0.2.99'})
        if kind == 'wrong_label': return observation.model_copy(update={'label': 'LIVE'})
        if kind == 'live_source': return observation.model_copy(update={'source': 'provider'})
        if kind == 'oversized': return observation.model_copy(update={'verdict': 'x' * 100000})
        return observation.model_dump()
    monkeypatch.setattr(gateway, 'mock_ip_reputation', unsafe)
    context, request, policy = inputs(); audit, evidence = [], []
    with pytest.raises(gateway.GatewayError) as error:
        gateway.execute(context, request, policy=policy, registry=(gateway.MOCK_CAPABILITY,),
                        audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    assert len(calls) == 1 and evidence == [] and audit[0].outcome == 'denied'
    assert 'SECRET' not in str(error.value) + repr(audit)


@pytest.mark.parametrize('kind', ['input_budget', 'output_budget', 'policy_limit', 'full_audit', 'full_evidence', 'aliased_sinks', 'callback_sink'])
def test_limits_and_sink_boundaries(monkeypatch, kind):
    calls = spy(monkeypatch)
    context, request, policy = inputs(); audit, evidence = [], []
    if kind == 'input_budget': monkeypatch.setattr(gateway, 'MAX_INPUT_BYTES', 1)
    if kind == 'output_budget': monkeypatch.setattr(gateway, 'MAX_OUTPUT_BYTES', 1)
    if kind == 'policy_limit': policy *= 33
    if kind == 'full_audit': audit = [None] * gateway.MAX_SINK_ITEMS
    if kind == 'full_evidence': evidence = [None] * gateway.MAX_SINK_ITEMS
    if kind == 'aliased_sinks': evidence = audit
    if kind == 'callback_sink': evidence = lambda item: pytest.fail('callback invoked')
    before = list(evidence) if type(evidence) is list else None
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request, policy=policy, registry=(gateway.MOCK_CAPABILITY,),
                        audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    if before is not None:
        assert evidence == before
    else:
        assert callable(evidence)
    assert len(calls) == (1 if kind == 'output_budget' else 0)


def test_result_digest_tampering_rejected():
    result, _, _ = execute()
    for change in ({'request_sha256': 'a' * 64}, {'result_sha256': 'a' * 64}, {'target': '192.0.2.99'}):
        with pytest.raises(ValidationError):
            gateway.ToolResult.model_validate({**result.model_dump(), **change})


def test_request_identity_replay_and_conflict_deny_without_second_dispatch(monkeypatch):
    calls = spy(monkeypatch)
    context, request, policy = inputs(); audit, evidence = [], []
    args = dict(policy=policy, registry=(gateway.MOCK_CAPABILITY,), audit_sink=audit,
                evidence_sink=evidence, disclosure=authorization(request))
    gateway.execute(context, request, **args)
    for duplicate in (request, request.model_copy(update={'target': '192.0.2.99'})):
        with pytest.raises(gateway.GatewayError): gateway.execute(context, duplicate, **args)
    assert calls == [request.target] and len(evidence) == 1


@pytest.mark.parametrize('kind', ['context_dict', 'forged_context', 'missing_consent',
    'registry_flags', 'registry_dict', 'invalid_audit_entry', 'invalid_evidence_entry'])
def test_trusted_boundaries_fail_closed(monkeypatch, kind):
    calls = spy(monkeypatch)
    context, request, policy = inputs(); audit, evidence = [], []
    registry = (gateway.MOCK_CAPABILITY,)
    if kind == 'context_dict': context = context.model_dump()
    if kind == 'forged_context': context = context.model_copy(update={'tenant_id': str(TENANT)})
    if kind == 'missing_consent':
        data = policy[0].model_dump(); data.pop('disclosure_consent')
        policy = (gateway.ToolGrant.model_construct(**data),)
    if kind == 'registry_flags': registry = (gateway.MOCK_CAPABILITY.model_copy(update={'external_disclosure': True}),)
    if kind == 'registry_dict': registry = (gateway.MOCK_CAPABILITY.model_dump(),)
    if kind == 'invalid_audit_entry': audit.append({'outcome': 'allowed'})
    if kind == 'invalid_evidence_entry': evidence.append({'label': 'LIVE'})
    before = list(evidence)
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request, policy=policy, registry=registry,
                        audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    assert calls == [] and evidence == before


def test_identity_scope_is_tenant_and_principal_not_global():
    context, request, policy = inputs(); audit, evidence = [], []
    gateway.execute(context, request, policy=policy, registry=(gateway.MOCK_CAPABILITY,),
                    audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    context = context.model_copy(update={'tenant_id': uuid4(), 'principal_id': uuid4()})
    identity = dict(tenant_id=context.tenant_id, principal_id=context.principal_id)
    request = request.model_copy(update=identity)
    grant = policy[0].model_copy(update=identity)
    result = gateway.execute(context, request, policy=(grant,), registry=(gateway.MOCK_CAPABILITY,),
                    audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    assert len(evidence) == len(audit) == 2
    assert result.request_sha256 != evidence[0].request_sha256


def test_denied_attempt_contains_no_raw_target_parameters_or_exception():
    context, request, policy = inputs(); audit, evidence = [], []
    request = request.model_copy(update={'parameters': (('dataset', 'SECRET'),)})
    with pytest.raises(gateway.GatewayError, match='^gateway_denied$'):
        gateway.execute(context, request, policy=policy, registry=(gateway.MOCK_CAPABILITY,),
                        audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    assert 'SECRET' not in audit[0].model_dump_json()
    assert request.target not in audit[0].model_dump_json() and evidence == []


def test_aggregate_policy_byte_limit_without_changing_configuration(monkeypatch):
    calls = spy(monkeypatch)
    context, request, policy = inputs()
    large_parameters = tuple((str(i), 'x' * 128) for i in range(8))
    policy += tuple(policy[0].model_copy(update={'grant_id': uuid4(),
        'target': f'192.0.2.{i + 2}', 'parameters': large_parameters}) for i in range(31))
    with pytest.raises(gateway.GatewayError): execute(context, request, policy)
    assert calls == []


def test_failure_does_not_change_existing_evidence_or_success_audit(monkeypatch):
    context, request, policy = inputs(); audit, evidence = [], []
    args = dict(policy=policy, registry=(gateway.MOCK_CAPABILITY,),
                audit_sink=audit, evidence_sink=evidence, disclosure=authorization(request))
    gateway.execute(context, request, **args)
    first_result, first_event = evidence[0], audit[0]
    def broken(target): raise RuntimeError('private failure')
    monkeypatch.setattr(gateway, 'mock_ip_reputation', broken)
    next_request = request.model_copy(update={'request_id': uuid4()})
    args['disclosure'] = authorization(next_request)
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, next_request, **args)
    assert evidence == [first_result] and audit[0] == first_event
    assert len(audit) == 2 and audit[1].outcome == 'denied'


def test_no_file_network_process_database_secret_or_dynamic_imports(monkeypatch):
    import builtins
    import importlib
    import io
    import os
    import socket
    import subprocess
    from pathlib import Path
    context, request, policy = inputs()
    def forbidden(*args, **kwargs): pytest.fail('forbidden I/O')
    for obj, name in ((builtins, 'open'), (io, 'open'), (Path, 'open'),
        (socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
        (subprocess, 'Popen'), (os, 'system'), (os, 'getenv'), (importlib, 'import_module')):
        monkeypatch.setattr(obj, name, forbidden)
    original_import = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name.split('.')[0] in ('sqlalchemy', 'psycopg', 'httpx', 'requests', 'openai', 'app'):
            pytest.fail('forbidden import')
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    result, _, _ = execute(context, request, policy)
    assert result.label == 'SYNTHETIC / TEST ONLY'
