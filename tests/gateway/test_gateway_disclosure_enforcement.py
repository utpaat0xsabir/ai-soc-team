"""TG-03B: both policy layers and explicit local eligibility precede dispatch."""

from datetime import datetime, timedelta, timezone
import hashlib
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.gateway import disclosure_policy as disclosure
from app.gateway import tool_gateway as gateway
from tests.gateway.test_tool_gateway import authorization, inputs, spy


NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)


def dispatch(context, request, grants, audit, evidence, **kwargs):
    return gateway.execute(context, request, policy=grants, registry=(gateway.MOCK_CAPABILITY,),
                           audit_sink=audit, evidence_sink=evidence, **kwargs)


def test_old_authorization_without_disclosure_policy_is_no_longer_sufficient(monkeypatch):
    calls = spy(monkeypatch); context, request, grants = inputs(); audit, evidence = [], []
    with pytest.raises(gateway.GatewayError):
        dispatch(context, request, grants, audit, evidence)
    assert calls == [] and evidence == [] and audit[0].outcome == 'denied'


def test_local_synthetic_dispatch_requires_two_allows_and_retains_provenance(monkeypatch):
    calls = spy(monkeypatch); context, request, grants = inputs(); audit, evidence = [], []
    checked = authorization(request)
    assert disclosure.evaluate_disclosure(context, checked.intent, policies=checked.policies,
        providers=checked.providers, consents=checked.consents, usage=checked.usage,
        at=checked.at).executable is False
    result = dispatch(context, request, grants, audit, evidence, disclosure=checked)
    assert calls == [request.target] and evidence == [result] and audit[0].outcome == 'allowed'
    assert result.label == 'SYNTHETIC / TEST ONLY' and result.verdict == 'unknown'
    assert result.source == 'mock.ip_reputation' and result.target == request.target


@pytest.mark.parametrize('kind', ['missing', 'raw_dict', 'no_policy', 'inactive', 'expired',
    'duplicate', 'conflict', 'cross_tenant', 'cross_principal', 'target', 'parameters',
    'request_id', 'capability_version', 'unknown_destination', 'extra_fields', 'oversized',
    'bad_time', 'input_ceiling', 'output_ceiling', 'forged_model_authority'])
def test_disclosure_denials_are_before_adapter_invocation(monkeypatch, kind):
    calls = spy(monkeypatch); context, request, grants = inputs(); audit, evidence = [], []
    checked = authorization(request); policy = checked.policies[0]; intent = checked.intent
    if kind == 'missing': checked = None
    elif kind == 'raw_dict': checked = checked.model_dump()
    elif kind == 'no_policy': checked = checked.model_copy(update={'policies': ()})
    elif kind == 'inactive': checked = checked.model_copy(update={'policies': (policy.model_copy(update={'active': False}),)})
    elif kind == 'expired': checked = checked.model_copy(update={'at': policy.valid_until})
    elif kind == 'duplicate': checked = checked.model_copy(update={'policies': (policy, policy)})
    elif kind == 'conflict': checked = checked.model_copy(update={'policies': (policy, policy.model_copy(update={'active': False}))})
    elif kind in ('cross_tenant', 'cross_principal', 'target', 'parameters', 'request_id', 'capability_version'):
        patch = {'cross_tenant': {'tenant_id': UUID(int=99)},
            'cross_principal': {'principal_id': UUID(int=99)}, 'target': {'target': '192.0.2.99'},
            'parameters': {'parameters': (('dataset', 'different'),)},
            'request_id': {'request_id': UUID(int=99)}, 'capability_version': {'capability_version': '2.0'}}[kind]
        checked = checked.model_copy(update={'intent': intent.model_copy(update={'request': request.model_copy(update=patch)})})
    elif kind == 'unknown_destination':
        other = intent.destination.model_copy(update={'destination_id': 'other-local'})
        checked = checked.model_copy(update={'intent': intent.model_copy(update={'destination': other}),
            'providers': (other,), 'policies': (policy.model_copy(update={'scope': policy.scope.model_copy(update={'destination': other})}),)})
    elif kind == 'extra_fields': checked = checked.model_copy(update={'intent': intent.model_copy(update={
        'payload': intent.payload + (intent.payload[0].model_copy(update={'name': 'password', 'value': 'SECRET'}),)})})
    elif kind == 'oversized': checked = checked.model_copy(update={'intent': intent.model_copy(update={
        'payload': (intent.payload[0].model_copy(update={'value': 'SECRET' * 10000}),)})})
    elif kind == 'bad_time': checked = checked.model_copy(update={'at': NOW.replace(tzinfo=None)})
    elif kind in ('input_ceiling', 'output_ceiling'):
        limits = policy.ceilings.model_copy(update={'max_input_bytes' if kind == 'input_ceiling' else 'max_output_bytes': 1})
        checked = checked.model_copy(update={'policies': (policy.model_copy(update={'ceilings': limits}),)})
    elif kind == 'forged_model_authority': request.__dict__['disclosure'] = checked
    with pytest.raises(gateway.GatewayError) as error:
        dispatch(context, request, grants, audit, evidence, disclosure=checked)
    assert calls == [] and evidence == [] and audit[0].outcome == 'denied'
    assert 'SECRET' not in str(error.value) + repr(audit)


@pytest.mark.parametrize('kind', ['grant', 'identity', 'capability', 'version', 'external_metadata'])
def test_tg01_denial_precedes_disclosure_evaluation(monkeypatch, kind):
    calls = spy(monkeypatch); context, request, grants = inputs(); audit, evidence = [], []
    checked = authorization(request)
    def forbidden(*args, **kwargs): pytest.fail('TG-03A ran after TG-01 denial')
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', forbidden)
    registry = (gateway.MOCK_CAPABILITY,)
    if kind == 'grant': grants = ()
    if kind == 'identity': context = context.model_copy(update={'tenant_id': UUID(int=99)})
    if kind == 'capability': request = request.model_copy(update={'capability_id': 'unknown'})
    if kind == 'version': request = request.model_copy(update={'capability_version': '2.0'})
    if kind == 'external_metadata': registry = (gateway.MOCK_CAPABILITY.model_copy(update={'external_disclosure': True}),)
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request, policy=grants, registry=registry,
                        audit_sink=audit, evidence_sink=evidence, disclosure=checked)
    assert calls == [] and evidence == []


@pytest.mark.parametrize('kind', ['exception', 'none', 'raw_allow', 'deny', 'forged_allow',
    'mutated_intent', 'mutated_policy', 'mutated_context', 'filled_sink', 'malformed_history',
    'stale_allow', 'wrong_bound_allow'])
def test_evaluator_failure_or_mutation_never_bypasses_dispatch_gate(monkeypatch, kind):
    calls = spy(monkeypatch); context, request, grants = inputs(); audit, evidence = [], []
    checked = authorization(request); original = disclosure.evaluate_disclosure
    def faulty(ctx, intent, **kwargs):
        result = original(ctx, intent, **kwargs)
        if kind == 'exception': raise RuntimeError('SECRET policy failure')
        if kind == 'none': return None
        if kind == 'raw_allow': return result.model_dump()
        if kind == 'deny': return disclosure.EgressDecision(outcome='DENY', reason='UNAUTHORIZED', evaluated_at=NOW, evaluation_sha256=None)
        if kind == 'forged_allow': return result.model_copy(update={'executable': True})
        if kind == 'mutated_intent': intent.request.__dict__['target'] = '192.0.2.99'
        if kind == 'mutated_policy': kwargs['policies'][0].__dict__['active'] = False
        if kind == 'mutated_context': ctx.__dict__['principal_id'] = UUID(int=99)
        if kind == 'filled_sink': evidence.extend([None] * gateway.MAX_SINK_ITEMS)
        if kind == 'malformed_history': evidence.append(None)
        if kind == 'stale_allow': return result.model_copy(update={'evaluated_at': NOW + timedelta(seconds=1)})
        if kind == 'wrong_bound_allow': return result.model_copy(update={'evaluation_sha256': '0' * 64})
        return result
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', faulty)
    with pytest.raises(gateway.GatewayError) as error:
        dispatch(context, request, grants, audit, evidence, disclosure=checked)
    assert calls == [] and all(item is None for item in evidence)
    assert 'SECRET' not in str(error.value) + repr(audit)


@pytest.mark.parametrize('state', ['missing', 'expired'])
def test_external_consent_denial_reaches_tg03a_after_valid_tg01_grant(monkeypatch, state):
    context, request, grants = inputs()
    request = request.model_copy(update={'target': '8.8.8.8'})
    grant = grants[0].model_copy(update={'target': request.target})
    checked = authorization(request)
    external = checked.intent.destination.model_copy(update={'audience': 'EXTERNAL'})
    patch = dict(category='EXTERNAL_LOOKUP', profile='external_lookup', risk='R2', destination=external)
    intent = checked.intent.model_copy(update={**patch,
        'payload': (checked.intent.payload[0].model_copy(update={'category': 'PUBLIC_IP'}),)})
    policy = checked.policies[0]
    policy = policy.model_copy(update={'scope': policy.scope.model_copy(update=patch)})
    consent = disclosure.ConsentState(consent_id=UUID(int=42), policy_id=policy.policy_id,
        policy_version='1.0', scope=policy.scope, ceilings=policy.ceilings, status='ACTIVE',
        valid_from=policy.valid_from, valid_until=NOW)
    checked = checked.model_copy(update={'intent': intent, 'policies': (policy,),
        'providers': (external,), 'consents': () if state == 'missing' else (consent,)})
    seen, calls = [], spy(monkeypatch)
    original = disclosure.evaluate_disclosure
    def observe(*args, **kwargs):
        result = original(*args, **kwargs); seen.append(result.reason); return result
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', observe)
    with pytest.raises(gateway.GatewayError):
        dispatch(context, request, (grant,), [], [], disclosure=checked)
    assert seen == ['CONSENT_REQUIRED' if state == 'missing' else 'CONSENT_INVALID']
    assert calls == []


def test_explicit_dispatch_eligibility_rejects_external_even_if_assessment_returns_allow(monkeypatch):
    context, request, grants = inputs(); checked = authorization(request)
    external = checked.intent.destination.model_copy(update={'audience': 'EXTERNAL'})
    checked = checked.model_copy(update={'intent': checked.intent.model_copy(update={
        'category': 'EXTERNAL_LOOKUP', 'profile': 'external_lookup', 'risk': 'R2', 'destination': external})})
    seen, calls = [], spy(monkeypatch)
    def allow(ctx, intent, **kwargs):
        seen.append('assessed')
        return disclosure.EgressDecision(outcome='ALLOW', reason='AUTHORIZED', evaluated_at=NOW,
            evaluation_sha256=hashlib.sha256(disclosure._evaluation_bytes(ctx, intent, **kwargs)).hexdigest())
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', allow)
    with pytest.raises(gateway.GatewayError):
        dispatch(context, request, grants, [], [], disclosure=checked)
    assert seen == ['assessed'] and calls == []


@pytest.mark.parametrize('kind', ['absent', 'expired', 'valid'])
def test_external_assessments_never_become_dispatch_permission(monkeypatch, kind):
    from tests.gateway.test_disclosure_policy import setup
    args = setup(); request = args['intent'].request
    context = args.pop('context')
    checked = disclosure.DisclosureInputs(**args)
    if kind == 'absent': checked = checked.model_copy(update={'consents': ()})
    if kind == 'expired': checked = checked.model_copy(update={'at': checked.consents[0].valid_until})
    calls = spy(monkeypatch); audit, evidence = [], []
    _, _, grants = inputs()
    grant = grants[0].model_copy(update={'capability_id': request.capability_id,
        'target': request.target, 'parameters': request.parameters})
    if kind == 'valid':
        assert disclosure.evaluate_disclosure(context, checked.intent, policies=checked.policies,
            providers=checked.providers, consents=checked.consents, usage=checked.usage, at=checked.at).outcome == 'ALLOW'
    with pytest.raises(gateway.GatewayError):
        dispatch(context, request, (grant,), audit, evidence, disclosure=checked)
    assert calls == [] and evidence == []


def test_actual_result_obeys_disclosure_output_ceiling(monkeypatch):
    calls = spy(monkeypatch); context, request, grants = inputs(); audit, evidence = [], []
    checked = authorization(request)
    checked = checked.model_copy(update={'intent': checked.intent.model_copy(update={'expected_output_bytes': 1})})
    with pytest.raises(gateway.GatewayError):
        dispatch(context, request, grants, audit, evidence, disclosure=checked)
    assert calls == [request.target] and evidence == [] and audit[0].outcome == 'denied'


def test_gateway_does_not_import_perform_io_or_pass_policy_objects_to_adapter(monkeypatch):
    import builtins
    import io
    import socket
    import subprocess
    from pathlib import Path
    context, request, grants = inputs(); checked = authorization(request)
    seen = []
    def adapter(target):
        assert type(target) is str
        seen.append(target)
        return gateway.ToolObservation(target=target)
    def forbidden(*args, **kwargs): pytest.fail('forbidden I/O')
    monkeypatch.setattr(gateway, 'mock_ip_reputation', adapter)
    for obj, name in ((builtins, 'open'), (io, 'open'), (Path, 'open'),
        (socket, 'socket'), (socket, 'create_connection'), (subprocess, 'Popen')):
        monkeypatch.setattr(obj, name, forbidden)
    result = dispatch(context, request, grants, [], [], disclosure=checked)
    assert result.label == 'SYNTHETIC / TEST ONLY' and seen == [request.target]


def test_enforcement_contract_is_immutable_versioned_and_shares_original_types():
    from app.gateway.contracts import ToolRequest, TrustedContext
    assert gateway.ToolRequest is ToolRequest and gateway.TrustedContext is TrustedContext
    _, request, _ = inputs(); checked = authorization(request)
    assert disclosure.DisclosureInputs.model_validate_json(checked.model_dump_json()) == checked
    with pytest.raises(ValidationError): checked.at = NOW + timedelta(seconds=1)
    with pytest.raises(ValidationError):
        disclosure.DisclosureInputs.model_validate({**checked.model_dump(), 'schema_version': '2.0'})


@pytest.mark.parametrize('patch', [{'capability_id': 'other'}, {'capability_version': '2.0'},
    {'parameters': (('dataset', 'not-synthetic'),)}])
def test_mock_disclosure_profile_does_not_authorize_another_capability(patch):
    context, request, _ = inputs(); checked = authorization(request)
    request = request.model_copy(update=patch)
    intent = checked.intent.model_copy(update={'request': request})
    policy = checked.policies[0]
    policy = policy.model_copy(update={'scope': policy.scope.model_copy(update={'request': request})})
    result = disclosure.evaluate_disclosure(context, intent, policies=(policy,),
        providers=checked.providers, at=NOW)
    assert result.outcome == 'DENY'


def test_caller_mutation_during_evaluation_does_not_change_dispatch_snapshot(monkeypatch):
    context, request, grants = inputs(); checked = authorization(request)
    target = request.target; calls = spy(monkeypatch); original = disclosure.evaluate_disclosure
    def mutate_caller(*args, **kwargs):
        result = original(*args, **kwargs)
        request.__dict__['target'] = '192.0.2.99'
        checked.intent.__dict__['risk'] = 'R4'
        return result
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', mutate_caller)
    result = dispatch(context, request, grants, [], [], disclosure=checked)
    assert calls == [target] and result.target == target


def test_gateway_evaluates_each_dispatch_and_accepts_no_cached_allow(monkeypatch):
    context, request, grants = inputs(); checked = authorization(request)
    calls = spy(monkeypatch); evaluations = []; original = disclosure.evaluate_disclosure
    def assess(*args, **kwargs):
        evaluations.append(True)
        if len(evaluations) == 1: return original(*args, **kwargs)
        return disclosure.EgressDecision(outcome='DENY', reason='UNAUTHORIZED',
                                         evaluated_at=NOW, evaluation_sha256=None)
    monkeypatch.setattr(disclosure, 'evaluate_disclosure', assess)
    dispatch(context, request, grants, [], [], disclosure=checked)
    with pytest.raises(gateway.GatewayError):
        dispatch(context, request, grants, [], [], disclosure=checked)
    assert len(evaluations) == 2 and calls == [request.target]
