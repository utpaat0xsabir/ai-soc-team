"""TG-03A: typed offline proposals, never network permission or dispatch."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.gateway import disclosure_policy as disclosure
from app.gateway.tool_gateway import TrustedContext, ToolRequest


NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)
TENANT, PRINCIPAL = UUID(int=1), UUID(int=2)


def setup(local=False):
    context = TrustedContext(tenant_id=TENANT, principal_id=PRINCIPAL)
    destination = disclosure.Destination(provider_id='test-provider', provider_version='1.0',
        account_id='test-account', destination_id='test-destination',
        audience='TENANT_LOCAL' if local else 'EXTERNAL')
    request = ToolRequest(request_id=UUID(int=3), tenant_id=TENANT, principal_id=PRINCIPAL,
        capability_id='test.ip.query' if local else 'test.ip.lookup', capability_version='1.0',
        operation='query' if local else 'lookup', target='8.8.8.8',
        parameters=(('purpose', 'investigation'), ('format', 'summary')))
    scope = disclosure.DisclosureScope(request=request, destination=destination,
        category='LOCAL_READ' if local else 'EXTERNAL_LOOKUP',
        profile='local_query' if local else 'external_lookup', risk='R1' if local else 'R2',
        permitted_categories=('PUBLIC_IP',), permitted_fields=('ip',))
    limits = disclosure.ResourceCeilings(max_input_bytes=4096, max_output_bytes=2048,
        max_disclosures=0 if local else 2, max_disclosure_bytes=0 if local else 256)
    policy = disclosure.DisclosurePolicy(policy_id=UUID(int=4), scope=scope, ceilings=limits,
        valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=1), active=True)
    consent = disclosure.ConsentState(consent_id=UUID(int=5), policy_id=policy.policy_id,
        policy_version='1.0', scope=scope, ceilings=limits, status='ACTIVE',
        valid_from=policy.valid_from, valid_until=policy.valid_until)
    intent = disclosure.DisclosureIntent(request=request, destination=destination,
        category=scope.category, profile=scope.profile, risk=scope.risk,
        payload=(disclosure.DisclosureField(name='ip', category='PUBLIC_IP', value=request.target),),
        expected_output_bytes=512)
    usage = disclosure.DisclosureUsage(tenant_id=TENANT, principal_id=PRINCIPAL,
        destination=destination, consent_id=consent.consent_id,
        window_start=consent.valid_from, window_end=consent.valid_until,
        used_disclosures=0, used_disclosure_bytes=0)
    return dict(context=context, intent=intent, policies=(policy,), providers=(destination,),
                consents=() if local else (consent,), usage=None if local else usage, at=NOW)


def decision(**changes):
    args = setup(); args.update(changes)
    return disclosure.evaluate_disclosure(**args)


def test_consented_external_lookup_is_a_non_executable_deterministic_assessment():
    args = setup(); before = repr(args)
    result = disclosure.evaluate_disclosure(**args)
    assert result.outcome == 'ALLOW' and result.reason == 'AUTHORIZED'
    assert result.executable is False and len(result.evaluation_sha256) == 64
    assert result == disclosure.evaluate_disclosure(**args) and repr(args) == before


def test_valid_local_read_and_analysis_need_exact_policy_but_no_disclosure_consent():
    args = setup(local=True)
    assert disclosure.evaluate_disclosure(**args).outcome == 'ALLOW'
    for profile, operation, risk in [('local_transform', 'transform', 'R1'),
                                    ('offline_analysis', 'analyze', 'R2')]:
        request = args['intent'].request.model_copy(update={'operation': operation})
        patch = dict(request=request, category='LOCAL_ANALYSIS', profile=profile, risk=risk)
        intent = args['intent'].model_copy(update=patch)
        policy = args['policies'][0]
        scope = policy.scope.model_copy(update=patch)
        assert disclosure.evaluate_disclosure(**{**args, 'intent': intent,
            'policies': (policy.model_copy(update={'scope': scope}),)}).outcome == 'ALLOW'


@pytest.mark.parametrize('kind', ['missing', 'expired', 'future', 'revoked', 'tenant',
    'principal', 'provider', 'target', 'parameters', 'capability_version', 'policy_id',
    'policy_version', 'fields', 'categories', 'duplicate', 'conflict'])
def test_consent_cannot_be_absent_stale_or_rebound(kind):
    args = setup(); consent = args['consents'][0]; scope = consent.scope
    if kind == 'missing': args['consents'] = ()
    elif kind == 'expired': consent = consent.model_copy(update={'valid_until': NOW})
    elif kind == 'future': consent = consent.model_copy(update={'valid_from': NOW + timedelta(seconds=1)})
    elif kind == 'revoked': consent = consent.model_copy(update={'status': 'REVOKED'})
    elif kind in ('tenant', 'principal', 'target', 'parameters', 'capability_version'):
        changes = {'tenant': {'tenant_id': UUID(int=99)}, 'principal': {'principal_id': UUID(int=99)},
            'target': {'target': '1.1.1.1'}, 'parameters': {'parameters': (('format', 'summary'),)},
            'capability_version': {'capability_version': '2.0'}}[kind]
        consent = consent.model_copy(update={'scope': scope.model_copy(update={
            'request': scope.request.model_copy(update=changes)})})
    elif kind == 'provider': consent = consent.model_copy(update={'scope': scope.model_copy(update={
        'destination': scope.destination.model_copy(update={'account_id': 'other'})})})
    elif kind == 'policy_id': consent = consent.model_copy(update={'policy_id': UUID(int=99)})
    elif kind == 'policy_version': consent = consent.model_copy(update={'policy_version': '2.0'})
    elif kind == 'fields': consent = consent.model_copy(update={'scope': scope.model_copy(update={'permitted_fields': ()})})
    elif kind == 'categories': consent = consent.model_copy(update={'scope': scope.model_copy(update={'permitted_categories': ('TENANT_IP',)})})
    elif kind == 'duplicate': args['consents'] *= 2
    elif kind == 'conflict': args['consents'] += (consent.model_copy(update={'consent_id': UUID(int=99), 'status': 'REVOKED'}),)
    if kind not in ('missing', 'duplicate', 'conflict'): args['consents'] = (consent,)
    assert disclosure.evaluate_disclosure(**args).outcome == 'DENY'


@pytest.mark.parametrize('kind', ['missing_policy', 'unknown_provider', 'provider_version',
    'capability', 'version', 'tenant', 'principal', 'target', 'parameters', 'risk',
    'local_disclosure', 'read_only_confusion', 'duplicate_policy', 'conflicting_policy',
    'duplicate_provider', 'forged_context', 'inactive_policy', 'expired_policy', 'schema_version'])
def test_authorization_fails_closed(kind):
    args = setup(); intent = args['intent']; request = intent.request
    if kind == 'missing_policy': args['policies'] = None
    elif kind == 'unknown_provider': args['providers'] = ()
    elif kind == 'provider_version': intent = intent.model_copy(update={'destination': intent.destination.model_copy(update={'provider_version': '2.0'})})
    elif kind in ('capability', 'version', 'tenant', 'principal', 'target', 'parameters'):
        patch = {'capability': {'capability_id': 'other'}, 'version': {'capability_version': '2.0'},
            'tenant': {'tenant_id': UUID(int=99)}, 'principal': {'principal_id': UUID(int=99)},
            'target': {'target': '1.1.1.1'}, 'parameters': {'parameters': (('purpose', 'other'),)}}[kind]
        intent = intent.model_copy(update={'request': request.model_copy(update=patch)})
    elif kind == 'risk': intent = intent.model_copy(update={'risk': 'R0'})
    elif kind == 'local_disclosure': intent = intent.model_copy(update={'category': 'LOCAL_READ', 'profile': 'local_query', 'risk': 'R1'})
    elif kind == 'read_only_confusion': intent = intent.model_copy(update={'profile': 'mock_lookup'})
    elif kind == 'duplicate_policy': args['policies'] *= 2
    elif kind == 'conflicting_policy': args['policies'] += (args['policies'][0].model_copy(update={'active': False}),)
    elif kind == 'duplicate_provider': args['providers'] *= 2
    elif kind == 'forged_context': args['context'] = args['context'].model_dump()
    elif kind == 'inactive_policy': args['policies'] = (args['policies'][0].model_copy(update={'active': False}),)
    elif kind == 'expired_policy': args['policies'] = (args['policies'][0].model_copy(update={'valid_until': NOW}),)
    elif kind == 'schema_version': intent = intent.model_copy(update={'schema_version': '2.0'})
    args['intent'] = intent
    assert disclosure.evaluate_disclosure(**args).outcome == 'DENY'


@pytest.mark.parametrize('category,profile,operation,risk', [
    ('EXTERNAL_SUBMISSION', 'submission', 'submit', 'R3'),
    ('ACTIVE_PROBE', 'active_scan', 'scan', 'R3'),
    ('REMOTE_COLLECTION', 'remote_collect', 'collect', 'R3'),
    ('RESPONSE_ACTION', 'response', 'respond', 'R4'),
    ('UNKNOWN', 'unknown', 'unknown', 'R4')])
def test_unsupported_operations_deny_even_with_matching_proposed_policy(category, profile, operation, risk):
    args = setup(); intent = args['intent']
    patch = dict(category=category, profile=profile, risk=risk,
                 request=intent.request.model_copy(update={'operation': operation}))
    args['intent'] = intent.model_copy(update=patch)
    policy = args['policies'][0]
    args['policies'] = (policy.model_copy(update={'scope': policy.scope.model_copy(update=patch)}),)
    assert disclosure.evaluate_disclosure(**args).outcome == 'DENY'


@pytest.mark.parametrize('kind', ['extra_field', 'secret', 'category', 'private_ip',
    'target_swap', 'duplicate_field', 'oversized', 'forged_consent', 'raw_dict'])
def test_data_minimization_and_forged_payload_authority(kind):
    args = setup(); intent = args['intent']; field = intent.payload[0]
    if kind == 'extra_field': intent = intent.model_copy(update={'payload': intent.payload + (field.model_copy(update={'name': 'raw_log'}),)})
    if kind == 'secret': intent = intent.model_copy(update={'payload': (field.model_copy(update={'name': 'password', 'value': 'SECRET-CANARY'}),)})
    if kind == 'category': intent = intent.model_copy(update={'payload': (field.model_copy(update={'category': 'RAW_LOG'}),)})
    if kind == 'private_ip': intent = intent.model_copy(update={'payload': (field.model_copy(update={'value': '127.0.0.1'}),)})
    if kind == 'target_swap': intent = intent.model_copy(update={'payload': (field.model_copy(update={'value': '1.1.1.1'}),)})
    if kind == 'duplicate_field': intent = intent.model_copy(update={'payload': (field, field)})
    if kind == 'oversized': intent = intent.model_copy(update={'payload': (field.model_copy(update={'value': 'SECRET-CANARY' * 10000}),)})
    if kind == 'forged_consent': intent.__dict__['consent'] = True
    if kind == 'raw_dict': intent = intent.model_dump()
    result = disclosure.evaluate_disclosure(**{**args, 'intent': intent})
    assert result.outcome == 'DENY'
    assert 'SECRET-CANARY' not in result.model_dump_json()


@pytest.mark.parametrize('kind', ['input', 'output', 'count', 'bytes', 'missing_usage',
    'wrong_usage_tenant', 'stale_usage', 'consent_limit', 'aggregate_input'])
def test_resource_and_disclosure_ceiling_denials(kind):
    args = setup(); policy = args['policies'][0]; usage = args['usage']
    if kind in ('input', 'output'):
        limits = policy.ceilings.model_copy(update={'max_input_bytes' if kind == 'input' else 'max_output_bytes': 1})
        args['policies'] = (policy.model_copy(update={'ceilings': limits}),)
    if kind == 'count': args['usage'] = usage.model_copy(update={'used_disclosures': 2})
    if kind == 'bytes': args['usage'] = usage.model_copy(update={'used_disclosure_bytes': 256})
    if kind == 'missing_usage': args['usage'] = None
    if kind == 'wrong_usage_tenant': args['usage'] = usage.model_copy(update={'tenant_id': UUID(int=99)})
    if kind == 'stale_usage': args['usage'] = usage.model_copy(update={'window_end': NOW})
    if kind == 'consent_limit':
        consent = args['consents'][0]
        args['consents'] = (consent.model_copy(update={'ceilings': consent.ceilings.model_copy(update={'max_disclosures': 0})}),)
    if kind == 'aggregate_input': args['policies'] *= 17
    assert disclosure.evaluate_disclosure(**args).outcome == 'DENY'


def test_supplied_time_is_aware_and_half_open():
    args = setup(); consent = args['consents'][0]
    assert disclosure.evaluate_disclosure(**{**args, 'at': consent.valid_from}).outcome == 'ALLOW'
    assert disclosure.evaluate_disclosure(**{**args, 'at': consent.valid_until}).outcome == 'DENY'
    assert decision(at=NOW.replace(tzinfo=None)).outcome == 'DENY'
    assert decision(at=NOW + timedelta(minutes=1)).evaluation_sha256 != decision().evaluation_sha256


def test_contracts_are_immutable_versioned_and_canonical():
    args = setup(); intent = args['intent']; policy = args['policies'][0]
    assert intent.request.parameters == (('format', 'summary'), ('purpose', 'investigation'))
    contracts = [args['context'], intent, intent.request, intent.destination, intent.payload[0],
        policy, policy.scope, policy.ceilings, args['consents'][0], args['usage'], decision()]
    for value in contracts:
        with pytest.raises(ValidationError): value.schema_version = '2.0'
        assert type(value).model_validate_json(value.model_dump_json()) == value
    reversed_request = intent.request.model_copy(update={'parameters': tuple(reversed(intent.request.parameters))})
    assert decision(intent=intent.model_copy(update={'request': reversed_request})) == decision()


def test_minimization_is_pure_and_returns_only_byte_count():
    args = setup(); intent = args['intent']; policy = args['policies'][0]
    assert 0 < disclosure.validate_disclosure(intent, policy.scope, policy.ceilings) < 256
    bad = intent.model_copy(update={'payload': (intent.payload[0].model_copy(update={'name': 'token', 'value': 'SECRET-CANARY'}),)})
    with pytest.raises(disclosure.DisclosureValidationError) as error:
        disclosure.validate_disclosure(bad, policy.scope, policy.ceilings)
    assert 'SECRET-CANARY' not in str(error.value)


def test_consistency_with_matrix_without_loading_it_at_runtime():
    matrix = json.loads((Path(__file__).resolve().parents[2] / 'docs/security/gateway-permission-matrix.v1.json').read_text())
    assert matrix['matrix_version'] == disclosure.MATRIX_VERSION
    for name, (category, operation, risk) in disclosure.PROFILE_CLASSIFICATION.items():
        assert matrix['profiles'][name]['operation'] == operation
        assert matrix['profiles'][name]['risk'] == risk
        if category == 'EXTERNAL_LOOKUP': assert matrix['profiles'][name]['requires_disclosure_consent']


def test_policy_evaluation_performs_no_io_or_adapter_dispatch(monkeypatch):
    import builtins
    import io
    import os
    import socket
    import subprocess
    from app.gateway import tool_gateway
    args = setup(); local = setup(local=True)
    def forbidden(*args, **kwargs): pytest.fail('forbidden I/O or dispatch')
    for obj, name in ((builtins, 'open'), (io, 'open'), (Path, 'open'),
        (socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
        (subprocess, 'Popen'), (os, 'system'), (os, 'getenv'),
        (tool_gateway, 'execute'), (tool_gateway, 'mock_ip_reputation')):
        monkeypatch.setattr(obj, name, forbidden)
    assert disclosure.evaluate_disclosure(**args).outcome == 'ALLOW'
    assert disclosure.evaluate_disclosure(**local).outcome == 'ALLOW'
    assert disclosure.evaluate_disclosure(**{**args, 'consents': ()}).outcome == 'DENY'


def test_untrusted_collection_cannot_run_equality_hooks():
    calls = []
    class Untrusted:
        def __eq__(self, other): calls.append('unexpected code'); return False
    assert decision(policies=Untrusted()).outcome == 'DENY'
    assert calls == []


@pytest.mark.parametrize('address', ['10.0.0.1', '127.0.0.1', '169.254.169.254',
    '224.0.0.1', '::1', 'fe80::1', 'fec0::1', '::ffff:8.8.8.8', '2002:0808:0808::1'])
def test_nonpublic_or_ambiguous_ip_denies_despite_matching_authority(address):
    args = setup(); intent = args['intent']; policy = args['policies'][0]
    request = intent.request.model_copy(update={'target': address})
    # Build a normal request so canonical target spellings cannot cause denial.
    request = ToolRequest.model_validate(request.model_dump())
    scope = policy.scope.model_copy(update={'request': request})
    args['intent'] = intent.model_copy(update={'request': request,
        'payload': (intent.payload[0].model_copy(update={'value': request.target}),)})
    args['policies'] = (policy.model_copy(update={'scope': scope}),)
    args['consents'] = (args['consents'][0].model_copy(update={'scope': scope}),)
    assert disclosure.evaluate_disclosure(**args).outcome == 'DENY'


@pytest.mark.parametrize('patch', [{'outcome': 'ALLOW', 'reason': 'CONSENT_REQUIRED'},
    {'outcome': 'DENY', 'reason': 'AUTHORIZED'}, {'evaluated_at': NOW.replace(tzinfo=None)},
    {'evaluation_sha256': None}])
def test_decision_contract_rejects_inconsistent_claims(patch):
    result = decision()
    with pytest.raises(ValidationError):
        disclosure.EgressDecision.model_validate({**result.model_dump(), **patch})


def test_disclosure_budget_boundary_is_inclusive_without_consuming_counters():
    args = setup(); policy = args['policies'][0]
    size = disclosure.validate_disclosure(args['intent'], policy.scope, policy.ceilings)
    usage = args['usage'].model_copy(update={'used_disclosures': 1,
        'used_disclosure_bytes': policy.ceilings.max_disclosure_bytes - size})
    assert disclosure.evaluate_disclosure(**{**args, 'usage': usage}).outcome == 'ALLOW'
    assert usage.used_disclosures == 1
    usage = usage.model_copy(update={'used_disclosure_bytes': usage.used_disclosure_bytes + 1})
    assert disclosure.evaluate_disclosure(**{**args, 'usage': usage}).outcome == 'DENY'


def test_model_consent_in_parameters_never_establishes_authority():
    args = setup(); intent = args['intent']; policy = args['policies'][0]
    request = intent.request.model_copy(update={'parameters': (('consent', 'true'),)})
    scope = policy.scope.model_copy(update={'request': request})
    args['intent'] = intent.model_copy(update={'request': request})
    args['policies'] = (policy.model_copy(update={'scope': scope}),)
    args['consents'] = ()
    assert disclosure.evaluate_disclosure(**args).reason == 'CONSENT_REQUIRED'
    args['consents'] = (setup()['consents'][0].model_copy(update={'scope': scope}),)
    assert disclosure.evaluate_disclosure(**args).reason == 'DATA_NOT_MINIMIZED'


@pytest.mark.parametrize('kind', ['nested_version', 'matrix_version', 'provider_scope',
    'usage_principal', 'usage_consent', 'nested_extra', 'malformed_parameters'])
def test_nested_authority_and_contract_forgery_denials(kind):
    args = setup(); policy = args['policies'][0]; intent = args['intent']
    if kind == 'nested_version':
        args['policies'] = (policy.model_copy(update={'ceilings': policy.ceilings.model_copy(update={'schema_version': '2.0'})}),)
    if kind == 'matrix_version':
        args['intent'] = intent.model_copy(update={'matrix_version': '2.0'})
    if kind == 'provider_scope':
        args['providers'] = (intent.destination.model_copy(update={'account_id': 'unapproved'}),)
    if kind == 'usage_principal': args['usage'] = args['usage'].model_copy(update={'principal_id': UUID(int=99)})
    if kind == 'usage_consent': args['usage'] = args['usage'].model_copy(update={'consent_id': UUID(int=99)})
    if kind == 'nested_extra': intent.request.__dict__['consent'] = True
    if kind == 'malformed_parameters':
        args['intent'] = intent.model_copy(update={'request': intent.request.model_copy(update={'parameters': [['purpose', 'investigation']]})})
    assert disclosure.evaluate_disclosure(**args).outcome == 'DENY'


def test_equivalent_supplied_timezone_has_identical_decision():
    alternate = NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert decision(at=alternate) == decision(at=NOW)


def test_private_tenant_ip_can_remain_local_with_explicit_policy():
    args = setup(local=True); intent = args['intent']; policy = args['policies'][0]
    request = intent.request.model_copy(update={'target': '10.0.0.1'})
    scope = policy.scope.model_copy(update={'request': request, 'permitted_categories': ('TENANT_IP',)})
    args['intent'] = intent.model_copy(update={'request': request,
        'payload': (intent.payload[0].model_copy(update={'value': request.target, 'category': 'TENANT_IP'}),)})
    args['policies'] = (policy.model_copy(update={'scope': scope}),)
    assert disclosure.evaluate_disclosure(**args).outcome == 'ALLOW'
