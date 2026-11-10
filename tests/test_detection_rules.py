import copy
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.detection_rules import DetectionCondition, DetectionMatch, DetectionRule, match_event
from test_security_events import TENANT, normalize, sample


RULE = UUID('00000000-0000-0000-0000-000000000003')


def condition(field='severity', operator='gte', value=60):
    return DetectionCondition(field=field, operator=operator, value=value)


def rule(**overrides):
    return DetectionRule(**dict(dict(rule_id=RULE, tenant_id=TENANT, version=1,
        name='Example rule', conditions=(condition(),)), **overrides))


def run(rules, event=None, tenant_id=TENANT):
    return match_event(normalize(sample()) if event is None else event, rules, tenant_id=tenant_id)


def test_match_contract_evidence_and_condition_trace():
    event = normalize(sample()); detection_rule = rule()
    result, = run((detection_rule,), event)
    assert result.schema_version == result.engine_version == '1.0'
    assert result.tenant_id == TENANT and result.event_id == event.event_id
    assert result.evidence_id == event.evidence_id
    assert result.evidence_sha256 == event.evidence_sha256
    assert result.source_reference == event.source_reference
    assert result.rule_id == RULE and result.rule_version == 1
    assert len(result.rule_fingerprint) == len(result.event_fingerprint) == 64
    trace, = result.matched_conditions
    assert (trace.field, trace.operator, trace.expected, trace.actual) == ('severity', 'gte', 60, 60)
    assert DetectionMatch.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize('field,operator,value,matched', [
    ('severity', 'eq', 60, True), ('severity', 'eq', 59, False),
    ('severity', 'gt', 60, False), ('severity', 'gte', 60, True),
    ('severity', 'lt', 60, False), ('severity', 'lte', 60, True),
    ('severity', 'gt', 59, True), ('severity', 'lt', 61, True),
    ('severity', 'in', (0, 60, 100), True), ('severity', 'in', (0, 100), False),
    ('rule.id', 'eq', '100', True), ('rule.level', 'gte', 9, True),
    ('source_system', 'eq', 'wazuh', True), ('category', 'eq', 'authentication', False),
    ('agent.id', 'in', ('001', '002'), True), ('agent.name', 'eq', 'host', True),
    ('agent.ip', 'eq', '2001:db8::1', True),
    ('source.ip', 'eq', '192.0.2.1', True), ('source.port', 'eq', 443, True),
    ('destination.ip', 'eq', '2001:db8::2', True), ('destination.port', 'gte', 8080, True),
])
def test_allowlisted_comparisons(field, operator, value, matched):
    assert bool(run((rule(conditions=(condition(field, operator, value),)),))) is matched


def test_explicit_and_no_partial_match():
    assert run((rule(conditions=(condition(), condition('agent.id', 'eq', 'other'))),)) == ()
    assert len(run((rule(conditions=(condition(), condition('agent.id', 'eq', '001'))),))) == 1


@pytest.mark.parametrize('field', ['severity', 'rule.id', 'rule.level', 'agent.name',
                                    'agent.ip', 'source.ip', 'source.port', 'destination.port'])
def test_missing_fields_are_nonmatches(field):
    evidence = sample()
    evidence['payload']['raw_document']['_source'] = {'timestamp': '2026-11-09T08:00:00Z'}
    from test_security_events import seal
    event = normalize(seal(evidence))
    value = 1 if field in ('severity', 'rule.level', 'source.port', 'destination.port') else 'x'
    assert run((rule(conditions=(condition(field, 'eq', value),)),), event) == ()


@pytest.mark.parametrize('field,operator,value', [
    ('__class__', 'eq', 'x'), ('tenant_id', 'eq', str(TENANT)),
    ('attributes.tenant_id', 'eq', 'x'), ('rule.groups', 'in', ('x',)),
    ('rule.description', 'eq', 'x'), ('event_id', 'eq', 'x'),
    ('severity', 'eval', 'x'), ('severity', 'regex', '.*'),
    ('severity', 'eq', True), ('severity', 'eq', '60'), ('severity', 'eq', 60.0),
    ('severity', 'eq', None), ('severity', 'eq', -1), ('severity', 'eq', 101),
    ('rule.level', 'eq', 16), ('source.port', 'eq', 65536), ('destination.port', 'eq', -1),
    ('agent.id', 'gt', '001'), ('agent.id', 'eq', 1), ('agent.id', 'eq', ''),
    ('agent.id', 'in', ('001', 2)), ('severity', 'in', (1, True)),
    ('severity', 'in', ()), ('severity', 'in', (1, 1)),
    ('severity', 'eq', (1, 2)), ('severity', 'in', 1),
    ('agent.name', 'eq', 'x' * 257), ('agent.name', 'in', tuple(str(i) for i in range(33))),
])
def test_invalid_conditions_rejected(field, operator, value):
    with pytest.raises(ValueError):
        condition(field, operator, value)


@pytest.mark.parametrize('overrides', [
    {'conditions': ()}, {'conditions': tuple(condition('severity', 'eq', i) for i in range(17))},
    {'conditions': (condition(), condition())}, {'version': 0}, {'version': True},
    {'version': '1'}, {'version': 2 ** 31}, {'rule_id': 'not-uuid'},
    {'tenant_id': str(TENANT)}, {'name': ''}, {'name': 'x' * 129}, {'schema_version': '2.0'},
    {'unexpected': 'data'},
])
def test_invalid_rules(overrides):
    with pytest.raises(ValueError):
        rule(**overrides)


def test_rule_json_roundtrip_and_membership_canonicalization():
    first = rule(conditions=(condition('agent.id', 'in', ('002', '001')), condition()))
    second = rule(conditions=(condition(), condition('agent.id', 'in', ('001', '002'))))
    assert first == second
    assert DetectionRule.model_validate_json(first.model_dump_json()) == first
    assert run((first,)) == run((second,))


def test_result_order_and_identity_independent_of_rule_order():
    first = rule(); second = rule(rule_id=uuid4())
    forward = run((first, second)); reverse = run([second, first])
    assert forward == reverse
    assert tuple(result.rule_id for result in forward) == tuple(sorted((first.rule_id, second.rule_id)))


def test_identities_track_rule_content_version_event_and_tenant():
    original, = run((rule(),))
    variants = [rule(version=2), rule(name='Renamed'), rule(conditions=(condition('severity', 'gte', 50),))]
    for changed in variants:
        result, = run((changed,))
        assert result.match_id != original.match_id
        assert result.rule_fingerprint != original.rule_fingerprint
    event = normalize(sample()).model_copy(update={'severity': 61})
    changed, = run((rule(),), event)
    assert changed.match_id != original.match_id and changed.event_fingerprint != original.event_fingerprint
    other = uuid4(); event = event.model_copy(update={'tenant_id': other})
    changed, = run((rule(tenant_id=other),), event, tenant_id=other)
    assert changed.match_id != original.match_id


def test_collection_time_excluded_from_identity():
    event = normalize(sample())
    first, = run((rule(),), event)
    second, = run((rule(),), event.model_copy(update={'ingested_at': None}))
    assert first == second


@pytest.mark.parametrize('rules', [(rule(), rule()), (rule(), rule(version=2))])
def test_duplicate_rule_ids_rejected_before_matching(rules):
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run(rules)


def test_tenant_boundaries_rejected_including_nonmatching_rules():
    other = uuid4()
    for rules, event, trusted in [
        ((rule(tenant_id=other),), normalize(sample()), TENANT),
        ((rule(tenant_id=other, conditions=(condition('severity', 'eq', 0),)),), normalize(sample()), TENANT),
        ((rule(),), normalize(sample()).model_copy(update={'tenant_id': other}), TENANT),
        ((rule(),), normalize(sample()), str(TENANT)),
    ]:
        with pytest.raises(ValueError, match='^invalid_detection_input$'):
            run(rules, event, tenant_id=trusted)


@pytest.mark.parametrize('rules', [None, {}, 'bad', [None], [object()], [dict(rule_id=str(RULE))],
                                   tuple(rule(rule_id=uuid4()) for _ in range(101))])
def test_malformed_or_oversized_rule_sets(rules):
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run(rules)


def test_empty_rules_and_generator_rejection_without_consumption():
    assert run(()) == ()
    def rules():
        pytest.fail('unbounded generator consumed')
        yield rule()
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run(rules())


def test_aggregate_budget():
    conditions = tuple(condition(field, 'in', tuple(str(i) + 'x' * 240 for i in range(32)))
                       for field in ('agent.id', 'agent.name', 'source_system', 'category'))
    rules = tuple(rule(rule_id=uuid4(), conditions=conditions) for _ in range(100))
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run(rules)


def test_immutability_and_input_preservation():
    event = normalize(sample()); detection_rule = rule()
    before = copy.deepcopy((event, detection_rule))
    result, = run((detection_rule,), event)
    assert (event, detection_rule) == before
    for model, field, value in [(detection_rule, 'version', 2), (detection_rule.conditions[0], 'value', 0),
                                (result, 'rule_version', 2), (result.matched_conditions[0], 'actual', 0)]:
        with pytest.raises(ValidationError):
            setattr(model, field, value)


def test_forged_models_are_revalidated_before_evaluation():
    for rules, event in [
        ((rule().model_copy(update={'conditions': ()}),), normalize(sample())),
        ((rule().model_copy(update={'version': True}),), normalize(sample())),
        ((rule(),), normalize(sample()).model_copy(update={'severity': True})),
        ((rule(),), normalize(sample()).model_copy(update={'agent': {'name': object()}})),
    ]:
        with pytest.raises(ValueError, match='^invalid_detection_input$'):
            run(rules, event)


def test_malformed_event_and_safe_error():
    with pytest.raises(ValueError, match='^invalid_detection_input$') as error:
        run((rule(),), event={'secret': 'do-not-echo'})
    assert 'do-not-echo' not in str(error.value)


def test_no_dynamic_expression_or_io(monkeypatch):
    import builtins
    import socket
    import subprocess
    event = normalize(sample())
    detection_rule = rule(conditions=(condition('agent.name', 'eq', '__import__("os").system("bad")'),))
    def forbidden(*args, **kwargs):
        pytest.fail('matcher performed forbidden operation')
    monkeypatch.setattr(builtins, 'eval', forbidden)
    monkeypatch.setattr(builtins, 'exec', forbidden)
    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    assert run((detection_rule,), event) == ()


@pytest.mark.parametrize('field,maximum', [('severity', 100), ('rule.level', 15),
                                          ('source.port', 65535), ('destination.port', 65535)])
def test_numeric_extrema(field, maximum):
    event = normalize(sample())
    for value in (0, maximum):
        if '.' in field:
            parent, child = field.split('.')
            event = event.model_copy(update={parent: getattr(event, parent).model_copy(update={child: value})})
        else:
            event = event.model_copy(update={field: value})
        for operator in ('eq', 'gte', 'lte', 'in'):
            expected = (value,) if operator == 'in' else value
            assert len(run((rule(conditions=(condition(field, operator, expected),)),), event)) == 1


def test_maximum_rule_count_is_supported():
    rules = tuple(rule(rule_id=UUID(int=index + 100)) for index in range(100))
    assert len(run(rules)) == 100
    assert run(rules) == run(list(reversed(rules)))


def test_maximum_condition_count_is_supported():
    conditions = tuple(condition('severity', 'gte', value) for value in range(16))
    result, = run((rule(conditions=conditions),))
    assert len(result.matched_conditions) == 16


def test_duplicate_conditions_after_membership_canonicalization_rejected():
    with pytest.raises(ValueError):
        rule(conditions=(condition('agent.id', 'in', ('001', '002')),
                         condition('agent.id', 'in', ('002', '001'))))


def test_tenant_spoof_in_event_attributes_cannot_override_context():
    event = normalize(sample()).model_copy(update={'attributes': (('tenant_id', str(uuid4())),)})
    assert run((rule(),), event)[0].tenant_id == TENANT
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run((), event.model_copy(update={'tenant_id': uuid4()}))


@pytest.mark.parametrize('value', ['bad', 1.0, float('nan'), float('inf'), None, {'bad': 1}])
def test_rule_membership_rejects_ambiguous_elements(value):
    with pytest.raises(ValueError):
        condition('severity', 'in', (0, value))


def test_forged_condition_and_deep_or_oversized_models_are_rejected():
    detection_rule = rule()
    invalid = detection_rule.model_copy(update={
        'conditions': (condition().model_copy(update={'operator': 'eval'}),)})
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run((invalid,))
    for value in ('x' * 5000, '\ud800', object(), 2 ** 100):
        event = normalize(sample()).model_copy(update={'category': value})
        with pytest.raises(ValueError, match='^invalid_detection_input$'):
            run((rule(),), event)
    circular = {}; circular['recursive'] = circular
    event = normalize(sample()).model_copy(update={'agent': circular})
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run((rule(),), event)


def test_rule_schema_rejects_unknown_condition_keys_and_list_coercion():
    with pytest.raises(ValueError):
        DetectionCondition(field='severity', operator='eq', value=60, command='bad')
    with pytest.raises(ValueError):
        condition('severity', 'in', [1, 2])
    with pytest.raises(ValueError):
        rule(conditions=[condition()])


def test_scalar_strings_use_exact_case_sensitive_comparison():
    assert run((rule(conditions=(condition('agent.name', 'eq', 'HOST'),)),)) == ()
    assert run((rule(conditions=(condition('agent.name', 'eq', 'host '),)),)) == ()


def test_result_identity_tracks_event_and_evidence_references():
    event = normalize(sample()); first, = run((rule(),), event)
    for patch in ({'event_id': uuid4()}, {'evidence_id': uuid4()},
                  {'evidence_sha256': 'f' * 64}, {'source_reference': 'different-source'}):
        changed, = run((rule(),), event.model_copy(update=patch))
        assert changed.match_id != first.match_id


def test_rule_constructor_revalidates_nested_condition_objects():
    invalid = condition().model_copy(update={'value': True})
    with pytest.raises(ValueError):
        rule(conditions=(invalid,))
