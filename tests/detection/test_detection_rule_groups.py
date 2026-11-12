import copy
import hashlib
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.detection.rules import DetectionCondition, DetectionMatch, DetectionRule, MatchedCondition, match_event
from tests.detection.test_detection_rules import condition, rule, run
from tests.detection.test_security_events import TENANT, normalize, sample, seal


def group_condition(values=('authentication',)):
    return DetectionCondition(field='rule.groups', operator='contains_any', value=values)


def group_rule(**patch):
    values = dict(schema_version='1.1', conditions=(group_condition(),))
    values.update(patch)
    return rule(**values)


def group_event(groups):
    evidence = sample()
    raw = evidence['payload']['raw_document']['_source']
    if groups is None:
        raw['rule'].pop('groups')
    else:
        raw['rule']['groups'] = groups
    return normalize(seal(evidence))


def test_legacy_v1_fingerprints_identity_and_serialization_unchanged():
    result, = run((rule(),))
    assert result.schema_version == result.engine_version == '1.0'
    assert result.rule_fingerprint == 'a12320b60eb6d9efb64b7bd176a73a47cbd9eee0e5ebc57865c62a10af06cead'
    assert result.event_fingerprint == '3213959c1e87b8f02025f810bd2914173481cb94bb77241edab003166d1c7a66'
    assert str(result.match_id) == '1c3c2df9-a09e-5269-ab5c-64cfb6f561e6'
    assert hashlib.sha256(result.model_dump_json().encode()).hexdigest() == '27e641deab2343b1322ccec15eb510ffd1b39ea27767f58b786280fbe76515b8'


def test_versioned_group_match_and_bounded_trace():
    selected = group_rule(conditions=(group_condition(('syslog', 'authentication')),))
    result, = run((selected,), group_event(['authentication', 'syslog', 'other']))
    assert result.schema_version == result.engine_version == '1.1'
    trace, = result.matched_conditions
    assert trace.field == 'rule.groups' and trace.operator == 'contains_any'
    assert trace.expected == trace.actual == ('authentication', 'syslog')
    assert DetectionRule.model_validate_json(selected.model_dump_json()) == selected
    assert DetectionMatch.model_validate_json(result.model_dump_json()) == result
    assert result.evidence_sha256 == group_event(['authentication', 'syslog', 'other']).evidence_sha256


@pytest.mark.parametrize('groups', [None, [], ['other'], ['AUTHENTICATION'], ['auth'], ['authentication ']])
def test_missing_empty_and_nonmatching_groups(groups):
    assert run((group_rule(),), group_event(groups)) == ()


def test_missing_rule_is_a_nonmatch():
    event = normalize(sample()).model_copy(update={'rule': None})
    assert run((group_rule(),), event) == ()


def test_default_and_explicit_v1_rules_reject_extension():
    for schema in ('1.0',):
        with pytest.raises(ValueError):
            rule(schema_version=schema, conditions=(group_condition(),))
    with pytest.raises(ValueError):
        rule(conditions=(group_condition(),))


@pytest.mark.parametrize('operator,value', [('eq', 'authentication'), ('in', ('authentication',)),
    ('gt', 1), ('gte', 1), ('lt', 1), ('lte', 1), ('regex', '.*')])
def test_group_field_rejects_all_other_operators(operator, value):
    with pytest.raises(ValueError):
        condition('rule.groups', operator, value)


@pytest.mark.parametrize('field', ['agent.name', 'rule.id', 'severity', 'rule.level',
    'attributes.groups', 'full_log', 'rule.description', 'rule.mitre.id', '__class__'])
def test_contains_any_restricted_to_allowlisted_group_field(field):
    with pytest.raises(ValueError):
        condition(field, 'contains_any', ('authentication',))


@pytest.mark.parametrize('values', [(), ('x', 'x'), 'authentication', ['authentication'],
    (True,), (1,), (1.5,), (None,), ('authentication', 1), ('',), ('x' * 257,),
    tuple(str(index) for index in range(33)), ('\ud800',)])
def test_invalid_or_oversized_group_conditions(values):
    with pytest.raises(ValueError):
        group_condition(values)


def test_32_configured_values_and_100_observed_groups():
    values = tuple('group-' + str(index) for index in range(32))
    observed = list(values) + ['unmatched-' + str(index) for index in range(68)]
    result, = run((group_rule(conditions=(group_condition(values),)),), group_event(observed))
    assert len(result.matched_conditions[0].actual) == 32
    assert result.matched_conditions[0].actual == tuple(sorted(values))


def test_large_unmatched_context_is_not_copied_to_trace():
    event = group_event(['authentication'] + ['x' * 4096] * 10)
    result, = run((group_rule(),), event)
    assert result.matched_conditions[0].actual == ('authentication',)
    assert 'x' * 4096 not in result.model_dump_json()


def test_observed_duplicates_count_as_one_trace_value():
    result, = run((group_rule(),), group_event(['authentication', 'authentication']))
    assert result.matched_conditions[0].actual == ('authentication',)


def test_canonical_condition_order_and_rule_order_preserve_results():
    first = group_rule(conditions=(condition(), group_condition(('syslog', 'authentication'))))
    same = group_rule(conditions=(group_condition(('authentication', 'syslog')), condition()))
    second = group_rule(rule_id=uuid4())
    event = group_event(['syslog', 'authentication'])
    assert first == same
    assert run((first, second), event) == run((second, same), event)
    assert group_rule(conditions=(condition('severity', 'eq', 0), group_condition()))
    assert run((group_rule(conditions=(condition('severity', 'eq', 0), group_condition())),), event) == ()


def test_group_trace_order_does_not_depend_on_observed_group_order():
    selected = group_rule(conditions=(group_condition(('syslog', 'authentication')),))
    forward, = run((selected,), group_event(['syslog', 'authentication']))
    reverse, = run((selected,), group_event(['authentication', 'syslog']))
    assert forward.matched_conditions == reverse.matched_conditions
    # The unchanged v1 event contract hashes the original evidence order.
    assert forward.event_fingerprint != reverse.event_fingerprint


def test_mixed_schema_rules_and_unchanged_scalar_in_semantics():
    old = rule(conditions=(condition('agent.id', 'in', ('001', '002')),))
    new = group_rule(rule_id=uuid4())
    result = run((new, old))
    assert {item.schema_version for item in result} == {'1.0', '1.1'}
    assert next(item for item in result if item.rule_id == old.rule_id).matched_conditions[0].actual == '001'


def test_v11_can_use_original_scalar_operations():
    original, = run((rule(),))
    versioned, = run((rule(schema_version='1.1'),))
    assert versioned.schema_version == versioned.engine_version == '1.1'
    assert versioned.matched_conditions == original.matched_conditions
    assert versioned.rule_fingerprint != original.rule_fingerprint and versioned.match_id != original.match_id


def test_tenant_ownership_even_for_group_nonmatches():
    for event in (group_event(['authentication']), group_event([])):
        with pytest.raises(ValueError, match='^invalid_detection_input$'):
            match_event(event, (group_rule(tenant_id=uuid4()),), tenant_id=TENANT)
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run((group_rule(),), group_event(['authentication']).model_copy(update={'tenant_id': uuid4()}))


@pytest.mark.parametrize('groups', [('authentication', True), tuple('x' for _ in range(101)),
                                    ('x' * 4097,), 'authentication', ('\ud800',)])
def test_forged_observed_group_values_rejected(groups):
    event = normalize(sample())
    event = event.model_copy(update={'rule': event.rule.model_copy(update={'groups': groups})})
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run((group_rule(),), event)


def test_forged_v1_rule_and_mislabeled_match_rejected():
    selected = group_rule()
    with pytest.raises(ValueError, match='^invalid_detection_input$'):
        run((selected.model_copy(update={'schema_version': '1.0'}),))
    result, = run((selected,))
    for patch in ({'schema_version': '1.0', 'engine_version': '1.0'},
                  {'schema_version': '1.0'}, {'engine_version': '1.0'}):
        with pytest.raises(ValueError):
            DetectionMatch.model_validate({**result.model_dump(), **patch})


@pytest.mark.parametrize('actual', [(), ('wrong',), ('authentication', 'authentication'),
                                   ('x' * 257,), ('authentication', True)])
def test_invalid_group_match_traces_rejected(actual):
    with pytest.raises(ValueError):
        MatchedCondition(field='rule.groups', operator='contains_any',
                         expected=('authentication',), actual=actual)


def test_immutability_no_io_and_literal_values(monkeypatch):
    import builtins
    import socket
    import subprocess
    selected = group_rule(conditions=(group_condition(('authentication', '__import__("os")')),))
    event = group_event(['authentication'])
    before = copy.deepcopy((event, selected))
    def forbidden(*args, **kwargs):
        pytest.fail('forbidden operation')
    for name in ('eval', 'exec', 'open'):
        monkeypatch.setattr(builtins, name, forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    result, = run((selected,), event)
    assert (event, selected) == before
    with pytest.raises(ValidationError):
        result.matched_conditions[0].actual = ()
