import copy
import hashlib
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.detection_rules import match_event
from app.event_correlation import CorrelationPolicy, CorrelationResult, correlate_events
from test_detection_rule_groups import group_rule
from test_detection_rules import condition, rule
from test_event_correlation import START, event, policy, run
from test_security_events import TENANT


AUTO = object()


def policy11(**patch):
    return policy(schema_version='1.1', **patch)


def correlate(events, selected=None, matches=AUTO, tenant_id=TENANT):
    selected = policy11() if selected is None else selected
    if matches is AUTO:
        matches = tuple(item for source in events for item in match_event(
            source, (selected.detection_rule,), tenant_id=tenant_id))
    return correlate_events(events, selected, tenant_id=tenant_id, matches=matches)


def test_existing_correlation_profile_serialization_and_ids_unchanged():
    result = run((event(1), event(2)))
    assert hashlib.sha256(result.model_dump_json().encode()).hexdigest() == 'ef7416084fe182d8860933dc790356d65edf713985d602ce38ef381e16448f6c'
    assert str(result.groups[0].group_id) == '424fc6fd-91d8-53d5-a61a-d382c0d6d1bb'
    assert str(result.groups[0].result_id) == 'e4b48d9e-bf19-5474-9cda-b221d78c0f9f'


def test_explicit_matches_explanation_and_trace_contract():
    values = (event(1), event(2, offset=20))
    result = correlate(values)
    assert result.schema_version == result.engine_version == '1.1'
    assert (result.received_match_count, result.unique_match_count, result.match_replay_count) == (2, 2, 0)
    group, = result.groups
    assert group.schema_version == group.engine_version == '1.1'
    explanation = group.explanation
    assert explanation.reason_code == 'shared_keys_rule_window_threshold'
    assert explanation.window_semantics == 'utc_epoch_tumbling_half_open'
    assert explanation.minimum_distinct_events == explanation.observed_distinct_events == 2
    assert explanation.group_fields == ('agent.id',)
    assert explanation.detection_rule_id == rule().rule_id
    assert explanation.detection_rule_version == 1
    assert explanation.detection_rule_fingerprint == group.members[0].match.rule_fingerprint
    assert 'incident' not in explanation.statement.lower()
    assert CorrelationResult.model_validate_json(result.model_dump_json()) == result
    assert CorrelationPolicy.model_validate_json(policy11().model_dump_json()) == policy11()


def test_v11_requires_explicit_matches_and_empty_matches_do_not_get_repaired():
    values = (event(1), event(2))
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate_events(values, policy11(), tenant_id=TENANT)
    result = correlate(values, matches=())
    assert result.groups == () and result.nonmatched_event_count == 2
    assert result.unique_match_count == result.matched_event_count == 0


def test_supplied_subset_only_contributes_verified_matches():
    values = (event(1), event(2), event(3))
    matches = tuple(match_event(item, (rule(),), tenant_id=TENANT)[0] for item in values[:2])
    result = correlate(values, matches=matches)
    assert result.groups[0].event_count == 2 and result.nonmatched_event_count == 1
    assert {member.match.event_id for member in result.groups[0].members} == {item.event_id for item in values[:2]}


def test_rule_identity_grouping_is_versioned_and_missing_values_not_invented():
    selected = policy11(group_by=('rule.id',))
    assert correlate((event(1), event(2)), selected).groups[0].group_key == (('rule.id', '100'),)
    values = (event(1).model_copy(update={'rule': None}), event(2).model_copy(update={'rule': None}))
    result = correlate(values, selected)
    assert result.groups == () and result.missing_group_key_count == 2
    with pytest.raises(ValueError):
        policy(group_by=('rule.id',))


def test_distinct_rule_grouping_values_do_not_mix():
    first = event(1); second = event(2)
    second = second.model_copy(update={'rule': second.rule.model_copy(update={'id': 'other'})})
    result = correlate((first, second), policy11(group_by=('rule.id',)))
    assert result.groups == () and result.below_threshold_event_count == 2


def test_event_and_match_replays_do_not_satisfy_threshold():
    first = event(1); detection, = match_event(first, (rule(),), tenant_id=TENANT)
    result = correlate((first, first), matches=(detection, detection, copy.deepcopy(detection)))
    assert result.groups == () and result.unique_event_count == 1 and result.replay_count == 1
    assert result.unique_match_count == 1 and result.match_replay_count == 2
    assert result.below_threshold_event_count == 1


def test_input_order_independence_with_duplicate_matches():
    values = (event(1, offset=20), event(2), event(3, offset=60), event(4, offset=60))
    matches = tuple(match_event(item, (rule(),), tenant_id=TENANT)[0] for item in values)
    matches += (matches[0],)
    first = correlate(values, matches=matches)
    second = correlate(list(reversed(values)), matches=list(reversed(matches)))
    assert first == second and first.match_replay_count == 1
    assert first.groups[0].window_end == first.groups[1].window_start == START + timedelta(seconds=60)


@pytest.mark.parametrize('field,value', [
    ('event_id', uuid4()), ('evidence_id', uuid4()), ('evidence_sha256', 'f' * 64),
    ('event_fingerprint', 'f' * 64), ('source_reference', 'different'),
    ('rule_id', uuid4()), ('rule_version', 2), ('rule_fingerprint', 'f' * 64),
    ('match_id', uuid4()), ('tenant_id', uuid4()),
])
def test_broken_match_event_or_rule_references_reject(field, value):
    values = (event(1), event(2))
    matches = tuple(match_event(item, (rule(),), tenant_id=TENANT)[0] for item in values)
    forged = matches[0].model_copy(update={field: value})
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate(values, matches=(forged, matches[1]))


def test_changed_condition_trace_is_not_trusted():
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    for trace in (detection.matched_conditions[0].model_copy(update={'actual': 59}),
                  detection.matched_conditions[0].model_copy(update={'operator': 'eval'})):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            correlate((value,), matches=(detection.model_copy(update={'matched_conditions': (trace,)}),))


def test_orphan_matches_and_claims_for_nonmatching_events_reject():
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((), matches=(detection,))
    changed = value.model_copy(update={'severity': 0})
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((changed,), matches=(detection,))


def test_conflicting_duplicate_match_ids_reject_in_either_order():
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    changed = detection.model_copy(update={'source_reference': 'conflict'})
    for matches in ((detection, changed), (changed, detection)):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            correlate((value,), matches=matches)


def test_two_different_match_ids_for_one_relationship_reject():
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((value,), matches=(detection, detection.model_copy(update={'match_id': uuid4()})))


def test_pinned_detection_rule_version_and_contents_must_match():
    values = (event(1), event(2))
    matches = tuple(match_event(item, (rule(),), tenant_id=TENANT)[0] for item in values)
    for changed in (rule(version=2), rule(name='Different'), rule(conditions=(condition('severity', 'gte', 50),))):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            correlate(values, policy11(detection_rule=changed), matches=matches)


def test_group_membership_extension_is_supported_without_contract_mutation():
    selected = policy11(detection_rule=group_rule())
    result = correlate((event(1), event(2)), selected)
    assert result.groups[0].members[0].match.schema_version == '1.1'
    assert result.groups[0].members[0].match.matched_conditions[0].actual == ('authentication',)


@pytest.mark.parametrize('matches', [None, {}, 'bad', [None], [object()], [{'secret': 'do-not-echo'}]])
def test_invalid_match_inputs(matches):
    with pytest.raises(ValueError, match='^invalid_correlation_input$') as error:
        correlate((event(1),), matches=matches)
    assert 'do-not-echo' not in str(error.value)


def test_match_limits_and_generators():
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((value,), matches=(detection,) * 101)
    def unbounded():
        pytest.fail('unbounded match iterable consumed')
        yield detection
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((value,), matches=unbounded())


def test_one_policy_limit_is_explicit():
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate_events((), (policy11(), policy11()), tenant_id=TENANT, matches=())


def test_maximum_events_matches_and_groups():
    values = tuple(event(index, agent=str(index // 2)) for index in range(100))
    result = correlate(values)
    assert result.received_match_count == result.unique_match_count == 100
    assert len(result.groups) == 50


def test_per_match_trace_budget_rejects_oversized_explanations(monkeypatch):
    import app.event_correlation as module
    from test_detection_rule_groups import group_condition
    shared = tuple('x' * 250 + str(index) for index in range(31))
    conditions = tuple(group_condition(shared + ('unique-' + str(index),)) for index in range(16))
    selected = policy11(detection_rule=group_rule(conditions=conditions))
    values = tuple(event(index).model_copy(update={
        'rule': event(index).rule.model_copy(update={'groups': shared})}) for index in (1, 2))
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate(values, selected)
    monkeypatch.setattr(module, 'MAX_MATCH_TRACE_BYTES', 1_048_576)
    assert correlate(values, selected).groups[0].event_count == 2


def test_aggregate_result_trace_budget_rejects_without_truncation(monkeypatch):
    import app.event_correlation as module
    expected = ('host',) + tuple('\u03b1' * 250 + str(index) for index in range(31))
    selected = policy11(detection_rule=rule(conditions=(condition('agent.name', 'in', expected),)))
    values = tuple(event(index) for index in range(50))
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate(values, selected)
    monkeypatch.setattr(module, 'MAX_TRACE_BYTES', 4_194_304)
    assert correlate(values, selected).groups[0].event_count == 50


def test_explicit_explanation_budget(monkeypatch):
    import app.event_correlation as module
    monkeypatch.setattr(module, 'MAX_EXPLANATION_BYTES', 100)
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((event(1), event(2)))


def test_explanation_is_immutable_and_version_gated():
    result = correlate((event(1), event(2)))
    with pytest.raises(ValidationError):
        result.groups[0].explanation.minimum_distinct_events = 1
    for patch in ({'schema_version': '1.0', 'engine_version': '1.0'},
                  {'schema_version': '1.0'}, {'engine_version': '1.0'}):
        with pytest.raises(ValueError):
            CorrelationResult.model_validate({**result.model_dump(), **patch})


def test_tenant_context_enforced_even_for_empty_explicit_matches():
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((event(1).model_copy(update={'tenant_id': uuid4()}),), matches=())
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((), matches=(), tenant_id=uuid4())


def test_inputs_unchanged_and_no_external_operations(monkeypatch):
    import builtins
    import socket
    import subprocess
    from sqlalchemy.engine import Engine
    import app.wazuh as wazuh
    values = (event(1), event(2)); selected = policy11()
    matches = tuple(match_event(item, (rule(),), tenant_id=TENANT)[0] for item in values)
    before = copy.deepcopy((values, selected, matches))
    def forbidden(*args, **kwargs):
        pytest.fail('forbidden external operation')
    for name in ('open', 'eval', 'exec'):
        monkeypatch.setattr(builtins, name, forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(Engine, 'connect', forbidden)
    monkeypatch.setattr(wazuh.WazuhIndexerClient, '__init__', forbidden)
    result = correlate(values, selected, matches=matches)
    assert len(result.groups) == 1
    assert (values, selected, matches) == before


@pytest.mark.parametrize('field', ['group_id', 'result_id'])
def test_serialized_group_identity_tampering_rejected(field):
    result = correlate((event(1), event(2))).model_dump()
    result['groups'][0][field] = uuid4()
    with pytest.raises(ValueError):
        CorrelationResult.model_validate(result)


def test_membership_explanations_and_accounting_tampering_rejected():
    original = correlate((event(1), event(2))).model_dump()
    variants = []
    for field, value in [('minimum_distinct_events', 3), ('observed_distinct_events', 3),
                         ('detection_rule_id', uuid4()), ('group_fields', ('source.ip',))]:
        modified = copy.deepcopy(original)
        modified['groups'][0]['explanation'][field] = value
        variants.append(modified)
    modified = copy.deepcopy(original); modified['received_match_count'] = 3; variants.append(modified)
    modified = copy.deepcopy(original); modified['groups'][0]['group_key'] = (('agent.id', 'other'),); variants.append(modified)
    modified = copy.deepcopy(original)
    modified['groups'][0]['members'][0]['match']['matched_conditions'][0]['actual'] = 59
    variants.append(modified)
    for candidate in variants:
        with pytest.raises(ValueError):
            CorrelationResult.model_validate(candidate)


def test_result_identities_are_independently_reconstructable():
    import json
    from uuid import uuid5
    from app.event_correlation import NAMESPACE
    group, = correlate((event(1), event(2))).groups
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    reconstructed = uuid5(NAMESPACE, canonical([
        '1.1', str(TENANT), group.policy_fingerprint, group.window_start.isoformat(), group.group_key]))
    member_digest = hashlib.sha256(canonical([
        member.model_dump(mode='json') for member in group.members]).encode()).hexdigest()
    assert reconstructed == group.group_id
    assert uuid5(NAMESPACE, f'1.1:{reconstructed}:{member_digest}') == group.result_id


def test_explicit_profile_preserves_threshold_and_rule_version_isolation():
    values = (event(1), event(2))
    first = correlate(values)
    assert correlate(values, policy11(min_events=3)).groups == ()
    for selected in (policy11(version=2), policy11(detection_rule=rule(version=2))):
        changed = correlate(values, selected)
        assert changed.groups[0].group_id != first.groups[0].group_id
        assert changed.groups[0].result_id != first.groups[0].result_id


@pytest.mark.parametrize('timestamp', [None, '2026-11-09T08:00:00Z', START.replace(tzinfo=None)])
def test_invalid_event_time_not_replaced_by_ingestion_time(timestamp):
    changed = event(1).model_copy(update={'event_time': timestamp})
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((changed,), matches=())


def test_match_counts_at_limit_and_duplicate_event_conflicts():
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    result = correlate((value,), matches=(detection,) * 100)
    assert result.unique_match_count == 1 and result.match_replay_count == 99 and result.groups == ()
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((value, value.model_copy(update={'severity': 61})), matches=(detection,))


def test_zero_inputs_validates_trusted_context_and_policy_revision():
    result = correlate((), matches=())
    assert result.groups == () and result.unique_match_count == result.received_match_count == 0
    for changed in (policy11().model_copy(update={'version': True}),
                    policy11().model_copy(update={'window_seconds': 0})):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            correlate((), changed, matches=())
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate((), matches=(), tenant_id=str(TENANT))


def test_shared_budget_includes_match_claims():
    import app.event_correlation as module
    # A forged unbounded trace must fail before serialization or evaluation.
    value = event(1); detection, = match_event(value, (rule(),), tenant_id=TENANT)
    cycle = {}; cycle['cycle'] = cycle
    for patch in ({'source_reference': 'x' * (module.MAX_INPUT_BYTES + 1)},
                  {'matched_conditions': cycle}, {'matched_conditions': (object(),)}):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            correlate((value,), matches=(detection.model_copy(update=patch),))


def test_forbidden_filesystem_database_and_ai_access(monkeypatch):
    import builtins
    import io
    from pathlib import Path
    import sqlalchemy
    from sqlalchemy.orm import Session
    values = (event(1), event(2)); selected = policy11()
    matches = tuple(match_event(item, (rule(),), tenant_id=TENANT)[0] for item in values)
    def forbidden(*args, **kwargs):
        pytest.fail('external operation attempted')
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        if name.split('.')[0] in ('openai', 'anthropic', 'transformers', 'langchain'):
            forbidden()
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded_import)
    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(io, 'open', forbidden)
    monkeypatch.setattr(sqlalchemy, 'create_engine', forbidden)
    monkeypatch.setattr(Session, 'execute', forbidden)
    assert correlate(values, selected, matches=matches).groups[0].event_count == 2
