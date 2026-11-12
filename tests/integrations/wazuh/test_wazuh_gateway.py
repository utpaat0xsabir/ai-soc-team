"""TG-04A: fake-only Wazuh search through both existing gateway policy layers."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.gateway import disclosure_policy as disclosure
from app.gateway import tool_gateway as gateway
from app.integrations.wazuh import gateway as wazuh


NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)


def setup(*, size=2, offset=0):
    binding = wazuh.WazuhSourceBinding(tenant_id=UUID(int=1), principal_id=UUID(int=2),
        integration_id=UUID(int=10), source_index=wazuh.SYNTHETIC_INDEX,
        source_scope='DEDICATED_SYNTHETIC')
    request = gateway.ToolRequest(request_id=UUID(int=100 + offset), tenant_id=binding.tenant_id,
        principal_id=binding.principal_id, capability_id='wazuh.alerts.search',
        capability_version='1.0', operation='query', target=str(binding.integration_id),
        parameters=wazuh.search_parameters(binding, size=size, offset=offset))
    grant = gateway.ToolGrant(grant_id=UUID(int=20), **{key: getattr(request, key)
        for key in gateway._Operation.model_fields}, risk='R1', read_only=True, disclosure_consent=False)
    destination = gateway.WAZUH_FAKE_DESTINATION
    scope = disclosure.DisclosureScope(request=request, destination=destination,
        category='LOCAL_READ', profile='local_query', risk='R1',
        permitted_categories=('SYNTHETIC_ALERT_QUERY',),
        permitted_fields=('integration_id', 'query_context', 'source_index'))
    limits = disclosure.ResourceCeilings(max_input_bytes=32768, max_output_bytes=2048,
        max_disclosures=0, max_disclosure_bytes=0)
    policy = disclosure.DisclosurePolicy(policy_id=UUID(int=30), scope=scope, ceilings=limits,
        active=True, valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=1))
    values = dict(integration_id=request.target, source_index=binding.source_index,
                  query_context=dict(request.parameters)['query_context'])
    intent = disclosure.DisclosureIntent(request=request, destination=destination,
        category='LOCAL_READ', profile='local_query', risk='R1', expected_output_bytes=2048,
        payload=tuple(disclosure.DisclosureField(name=key, category='SYNTHETIC_ALERT_QUERY', value=value)
                      for key, value in sorted(values.items())))
    checked = disclosure.DisclosureInputs(intent=intent, policies=(policy,), providers=(destination,),
        consents=(), usage=None, at=NOW)
    return dict(context=gateway.TrustedContext(tenant_id=binding.tenant_id, principal_id=binding.principal_id),
        request=request, policy=(grant,), registry=(gateway.WAZUH_ALERT_SEARCH,),
        disclosure=checked, wazuh_bindings=(binding,), wazuh_client=wazuh.FakeWazuhClient(binding=binding),
        audit_sink=[], evidence_sink=[])


def align_request(args, request):
    """Authorize a proposed request in fixtures so deeper validation is exercised."""
    args['request'] = request
    args['policy'] = (args['policy'][0].model_copy(update={key: getattr(request, key)
        for key in gateway._Operation.model_fields}),)
    checked = args['disclosure']; policy = checked.policies[0]
    args['disclosure'] = checked.model_copy(update={
        'intent': checked.intent.model_copy(update={'request': request}),
        'policies': (policy.model_copy(update={'scope': policy.scope.model_copy(update={'request': request})}),)})


def test_authorized_synthetic_search_has_bounded_provenance_and_audit():
    args = setup(); result = gateway.execute(**args)
    assert args['wazuh_client'].calls == 1
    assert result.source == 'wazuh.alerts.search' and result.label == 'SYNTHETIC / TEST ONLY'
    assert result.integration_id == UUID(int=10) and result.source_index == wazuh.SYNTHETIC_INDEX
    assert len(result.alerts) == 2 and result.total == 4 and result.next_offset == 2
    assert all(alert.label == 'SYNTHETIC / TEST ONLY' for alert in result.alerts)
    assert result.alerts[0].source_reference == wazuh.SYNTHETIC_INDEX + '/synthetic-alert-001'
    assert args['evidence_sink'] == [result] and args['audit_sink'][0].code == 'synthetic_search_completed'
    assert wazuh.WazuhSearchResult.model_validate_json(result.model_dump_json()) == result
    assert len(result.request_sha256) == len(result.result_sha256) == 64


@pytest.mark.parametrize('kind', ['no_grant', 'no_disclosure', 'no_binding', 'no_client',
    'cross_tenant', 'wrong_principal', 'wrong_integration', 'unknown_source', 'unproven_source',
    'duplicate_binding', 'conflicting_binding', 'forged_binding', 'unknown_capability',
    'wrong_version', 'modified_parameters', 'duplicate_registration', 'conflicting_registration',
    'invalid_policy', 'oversized_input', 'unsupported_operation', 'external_classification',
    'invalid_sink', 'full_sink'])
def test_denied_search_never_calls_fake_client(kind):
    args = setup(); client = args['wazuh_client']; binding = args['wazuh_bindings'][0]
    if kind == 'no_grant': args['policy'] = ()
    elif kind == 'no_disclosure': args['disclosure'] = None
    elif kind == 'no_binding': args['wazuh_bindings'] = ()
    elif kind == 'no_client': args['wazuh_client'] = None
    elif kind == 'cross_tenant': args['wazuh_bindings'] = (binding.model_copy(update={'tenant_id': UUID(int=99)}),)
    elif kind == 'wrong_principal': args['context'] = args['context'].model_copy(update={'principal_id': UUID(int=99)})
    elif kind == 'wrong_integration': args['wazuh_bindings'] = (binding.model_copy(update={'integration_id': UUID(int=99)}),)
    elif kind == 'unknown_source': args['wazuh_bindings'] = (binding.model_copy(update={'source_index': 'wazuh-alerts-other'}),)
    elif kind == 'unproven_source': args['wazuh_bindings'] = (binding.model_copy(update={'source_scope': 'shared-unverified'}),)
    elif kind == 'duplicate_binding': args['wazuh_bindings'] *= 2
    elif kind == 'conflicting_binding': args['wazuh_bindings'] += (binding.model_copy(update={'tenant_id': UUID(int=99)}),)
    elif kind == 'forged_binding': args['wazuh_bindings'] = (binding.model_dump(),)
    elif kind == 'unknown_capability': args['request'] = args['request'].model_copy(update={'capability_id': 'wazuh.admin'})
    elif kind == 'wrong_version': args['request'] = args['request'].model_copy(update={'capability_version': '2.0'})
    elif kind == 'modified_parameters': args['request'] = args['request'].model_copy(update={'parameters': (('size', '1'),)})
    elif kind == 'duplicate_registration': args['registry'] *= 2
    elif kind == 'conflicting_registration': args['registry'] += (gateway.WAZUH_ALERT_SEARCH.model_copy(update={'external_disclosure': True}),)
    elif kind == 'invalid_policy': args['disclosure'] = args['disclosure'].model_copy(update={'policies': ()})
    elif kind == 'oversized_input': args['request'] = args['request'].model_copy(update={'parameters': (('query', 'SECRET' * 10000),)})
    elif kind == 'unsupported_operation': args['request'] = args['request'].model_copy(update={'operation': 'respond'})
    elif kind == 'external_classification': args['disclosure'] = args['disclosure'].model_copy(update={
        'intent': args['disclosure'].intent.model_copy(update={'category': 'EXTERNAL_LOOKUP', 'profile': 'external_lookup', 'risk': 'R2'})})
    elif kind == 'invalid_sink': args['evidence_sink'] = lambda item: pytest.fail('sink callback')
    elif kind == 'full_sink': args['audit_sink'] = [None] * gateway.MAX_SINK_ITEMS
    with pytest.raises(gateway.GatewayError) as error: gateway.execute(**args)
    assert client.calls == 0 and 'SECRET' not in str(error.value)
    if type(args['evidence_sink']) is list: assert args['evidence_sink'] == []


@pytest.mark.parametrize('patch', [
    {'size': '0'}, {'size': '3'}, {'size': '02'}, {'offset': '5'}, {'offset': '-1'},
    {'query_context': '0' * 64}, {'index': 'wazuh-alerts-other'}, {'dsl': '{"match_all":{}}'}])
def test_exact_query_binding_rejects_expansion_even_with_a_matching_grant(patch):
    args = setup(); parameters = {**dict(args['request'].parameters), **patch}
    request = args['request'].model_copy(update={'parameters': tuple(sorted(parameters.items()))})
    align_request(args, request)
    with pytest.raises(gateway.GatewayError): gateway.execute(**args)
    assert args['wazuh_client'].calls == 0 and args['evidence_sink'] == []


def test_context_cannot_be_reused_for_another_page_or_integration():
    first = setup(); second = setup(offset=2)
    parameters = dict(second['request'].parameters)
    parameters['query_context'] = dict(first['request'].parameters)['query_context']
    align_request(second, second['request'].model_copy(update={'parameters': tuple(sorted(parameters.items()))}))
    with pytest.raises(gateway.GatewayError): gateway.execute(**second)
    assert second['wazuh_client'].calls == 0


@pytest.mark.parametrize('kind', ['missing_label', 'wrong_label', 'secret', 'wrong_source',
    'wrong_order', 'duplicate_alert', 'wrong_total', 'wrong_offset', 'wrong_cursor',
    'oversized', 'raw_list', 'wrong_level', 'exception'])
def test_untrusted_fake_results_never_write_evidence(monkeypatch, kind):
    args = setup(); original = wazuh.FakeWazuhClient.search_alerts
    def malformed(self, **kwargs):
        data = original(self, **kwargs)
        if kind == 'missing_label': data.pop('label')
        if kind == 'wrong_label': data['label'] = 'LIVE'
        if kind == 'secret': data['items'][0]['password'] = 'SECRET'
        if kind == 'wrong_source': data['items'][0]['source_reference'] = 'other-index/private-alert'
        if kind == 'wrong_order': data['items'] = tuple(reversed(data['items']))
        if kind == 'duplicate_alert': data['items'] = (data['items'][0], data['items'][0])
        if kind == 'wrong_total': data['total'] = 999
        if kind == 'wrong_offset': data['offset'] = 1
        if kind == 'wrong_cursor': data['next_context'] = '0' * 64
        if kind == 'oversized': data['items'] = data['items'] * 10000
        if kind == 'raw_list': return []
        if kind == 'wrong_level': data['items'][0]['rule_level'] = True
        if kind == 'exception': raise RuntimeError('SECRET upstream failure')
        return data
    monkeypatch.setattr(wazuh.FakeWazuhClient, 'search_alerts', malformed)
    with pytest.raises(gateway.GatewayError) as error: gateway.execute(**args)
    assert args['wazuh_client'].calls == 1 and args['evidence_sink'] == []
    assert args['audit_sink'][0].outcome == 'denied'
    assert 'SECRET' not in str(error.value) + repr(args['audit_sink'])


def test_pagination_and_repeated_queries_are_deterministic():
    first = setup(); result = gateway.execute(**first)
    repeated = gateway.execute(**setup())
    assert result == repeated
    second = setup(offset=result.next_offset)
    second['wazuh_client'] = first['wazuh_client']
    result2 = gateway.execute(**second)
    assert dict(second['request'].parameters)['query_context'] == result.next_context
    assert result2.next_offset is None and len({a.source_reference for a in result.alerts + result2.alerts}) == 4
    assert first['wazuh_client'].calls == 2
    empty = gateway.execute(**setup(offset=4))
    assert empty.alerts == () and empty.next_context is None


def test_registry_can_explicitly_contain_both_known_capabilities():
    args = setup(); args['registry'] = (gateway.MOCK_CAPABILITY, gateway.WAZUH_ALERT_SEARCH)
    assert gateway.execute(**args).label == 'SYNTHETIC / TEST ONLY'


def test_output_ceiling_is_checked_before_evidence_write(monkeypatch):
    args = setup(); monkeypatch.setattr(gateway, 'MAX_OUTPUT_BYTES', 1)
    with pytest.raises(gateway.GatewayError): gateway.execute(**args)
    assert args['wazuh_client'].calls == 1 and args['evidence_sink'] == []


def test_only_the_closed_fake_client_is_accepted():
    args = setup()
    class NetworkClient:
        calls = 0
        def search_alerts(self, **kwargs):
            self.calls += 1
            pytest.fail('unapproved client invoked')
    client = NetworkClient(); args['wazuh_client'] = client
    with pytest.raises(gateway.GatewayError): gateway.execute(**args)
    assert client.calls == 0


def test_immutable_bindings_and_result_integrity():
    args = setup(); binding = args['wazuh_bindings'][0]
    with pytest.raises(ValidationError): binding.source_index = 'other'
    assert type(binding).model_validate_json(binding.model_dump_json()) == binding
    result = gateway.execute(**args)
    with pytest.raises(ValidationError):
        wazuh.WazuhSearchResult.model_validate({**result.model_dump(), 'offset': 1})


def test_offline_dispatch_forbids_files_network_http_processes_and_secrets(monkeypatch):
    import builtins
    import io
    import os
    import socket
    import subprocess
    from pathlib import Path
    import httpx
    args = setup()
    def forbidden(*args, **kwargs): pytest.fail('forbidden I/O')
    for obj, name in ((builtins, 'open'), (io, 'open'), (Path, 'open'),
        (socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
        (subprocess, 'Popen'), (os, 'system'), (os, 'getenv'), (httpx.Client, 'request')):
        monkeypatch.setattr(obj, name, forbidden)
    result = gateway.execute(**args)
    assert result.label == 'SYNTHETIC / TEST ONLY' and args['wazuh_client'].calls == 1


def test_new_data_category_does_not_expand_the_existing_ip_mock(monkeypatch):
    from tests.gateway.test_tool_gateway import inputs, authorization, spy
    context, request, grants = inputs(); checked = authorization(request); calls = spy(monkeypatch)
    policy = checked.policies[0]
    checked = checked.model_copy(update={
        'intent': checked.intent.model_copy(update={'payload': (checked.intent.payload[0].model_copy(
            update={'category': 'SYNTHETIC_ALERT_QUERY'}),)}),
        'policies': (policy.model_copy(update={'scope': policy.scope.model_copy(
            update={'permitted_categories': ('SYNTHETIC_ALERT_QUERY',)})}),)})
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request, policy=grants, registry=(gateway.MOCK_CAPABILITY,),
                        disclosure=checked, audit_sink=[], evidence_sink=[])
    assert calls == []


def test_client_owner_changes_after_assessment_deny_before_search(monkeypatch):
    args = setup(); original = disclosure.evaluate_disclosure
    def mutate(*a, **kw):
        result = original(*a, **kw)
        args['wazuh_client'].binding.__dict__['tenant_id'] = UUID(int=99)
        return result
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', mutate)
    with pytest.raises(gateway.GatewayError): gateway.execute(**args)
    assert args['wazuh_client'].calls == 0 and args['evidence_sink'] == []


def test_sink_history_accepts_both_result_contracts_and_preserves_source_references():
    from tests.gateway.test_tool_gateway import inputs, authorization
    args = setup(); result = gateway.execute(**args)
    assert args['audit_sink'][0].source_references == tuple(alert.source_reference for alert in result.alerts)
    context, request, grants = inputs()
    mock = gateway.execute(context, request, policy=grants, registry=(gateway.MOCK_CAPABILITY,),
        disclosure=authorization(request), audit_sink=args['audit_sink'], evidence_sink=args['evidence_sink'])
    following = setup(offset=2)
    following.update(audit_sink=args['audit_sink'], evidence_sink=args['evidence_sink'])
    gateway.execute(**following)
    assert len(args['evidence_sink']) == len(args['audit_sink']) == 3
    assert mock.label == 'SYNTHETIC / TEST ONLY'
