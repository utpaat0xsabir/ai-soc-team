import copy
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.detection.correlation import CorrelationPolicy, CorrelationResult, correlate_events
from tests.detection.test_detection_rules import rule
from tests.detection.test_security_events import TENANT, normalize, sample, seal


POLICY_ID = UUID('00000000-0000-0000-0000-000000000004')
START = datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)


def policy(**overrides):
    values = dict(policy_id=POLICY_ID, tenant_id=TENANT, version=1, name='Repeated alerts',
                  detection_rule=rule(), group_by=('agent.id',), window_seconds=60, min_events=2)
    values.update(overrides)
    return CorrelationPolicy(**values)


def event(index=1, *, offset=0, agent='001', severity=9):
    evidence = sample()
    evidence['id'] = UUID(int=index + 1000)
    raw = evidence['payload']['raw_document']
    raw['_id'] = 'alert-' + str(index)
    evidence['source_reference'] = raw['_index'] + '/' + raw['_id']
    timestamp = START + timedelta(seconds=offset)
    evidence['event_time'] = timestamp
    raw['_source']['timestamp'] = timestamp.isoformat()
    raw['_source']['agent']['id'] = agent
    raw['_source']['rule']['level'] = severity
    return normalize(seal(evidence))


def run(events, correlation_policy=None, tenant_id=TENANT):
    return correlate_events(events, policy() if correlation_policy is None else correlation_policy,
                            tenant_id=tenant_id)


def test_group_contract_match_and_evidence_trace():
    events = (event(1), event(2, offset=20))
    result = run(events)
    assert result.schema_version == result.engine_version == '1.0'
    assert result.tenant_id == TENANT
    assert (result.received_count, result.unique_event_count, result.replay_count) == (2, 2, 0)
    assert result.matched_event_count == 2 and result.nonmatched_event_count == 0
    assert result.missing_group_key_count == result.below_threshold_event_count == 0
    group, = result.groups
    assert group.tenant_id == TENANT and group.policy_id == POLICY_ID and group.policy_version == 1
    assert len(group.policy_fingerprint) == 64
    assert group.group_key == (('agent.id', '001'),)
    assert group.window_start == group.first_event_time == START
    assert group.window_end == START + timedelta(seconds=60)
    assert group.last_event_time == START + timedelta(seconds=20)
    assert group.event_count == 2
    assert tuple(member.event_time for member in group.members) == tuple(e.event_time for e in events)
    for member, source in zip(group.members, events):
        assert member.match.event_id == source.event_id
        assert member.match.evidence_id == source.evidence_id
        assert member.match.evidence_sha256 == source.evidence_sha256
        assert member.match.source_reference == source.source_reference
        assert member.match.rule_id == rule().rule_id
        assert member.match.matched_conditions[0].actual == 60
    assert CorrelationResult.model_validate_json(result.model_dump_json()) == result


def test_empty_input_and_threshold_accounting():
    assert run(()).groups == ()
    result = run((event(1),))
    assert result.groups == () and result.below_threshold_event_count == 1
    result = run((event(1), event(2), event(3)), policy(min_events=3))
    assert result.groups[0].event_count == 3


def test_missing_keys_and_nonmatches_counted_separately():
    missing = event(2).model_copy(update={'agent': None})
    result = run((event(1), missing, event(3, severity=0)))
    assert result.groups == ()
    assert result.unique_event_count == 3 and result.matched_event_count == 2
    assert result.nonmatched_event_count == result.missing_group_key_count == result.below_threshold_event_count == 1


def test_half_open_fixed_windows_and_subsecond_boundaries():
    result = run((event(1), event(2, offset=59.999999), event(3, offset=60), event(4, offset=119.999999)))
    assert len(result.groups) == 2
    first, second = result.groups
    assert first.window_start == START and first.window_end == second.window_start
    assert first.window_end == START + timedelta(seconds=60)
    assert [group.event_count for group in result.groups] == [2, 2]


def test_pre_epoch_windows_use_integer_arithmetic():
    earlier = datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
    events = tuple(event(index).model_copy(update={'event_time': earlier}) for index in (1, 2))
    group, = run(events).groups
    assert group.window_start == datetime(1969, 12, 31, 23, 59, tzinfo=timezone.utc)
    assert group.window_end == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_distinct_group_keys_do_not_mix():
    result = run((event(1), event(2), event(3, agent='other'), event(4, agent='other')))
    assert len(result.groups) == 2
    assert {group.group_key for group in result.groups} == {(('agent.id', '001'),), (('agent.id', 'other'),)}
    assert all(group.event_count == 2 for group in result.groups)


def test_composite_keys_and_policy_order_canonicalization():
    first = policy(group_by=('agent.id', 'source.ip'))
    second = policy(group_by=('source.ip', 'agent.id'))
    assert first == second
    assert run((event(1), event(2)), first) == run((event(2), event(1)), second)
    assert run((event(1), event(2)), first).groups[0].group_key == (
        ('agent.id', '001'), ('source.ip', '192.0.2.1'))


def test_group_and_member_order_is_deterministic():
    events = (event(1, offset=20), event(2), event(3, offset=60), event(4, offset=60),
              event(5, agent='other'), event(6, agent='other'))
    first = run(events); second = run(list(reversed(events)))
    assert first == second
    for group in first.groups:
        assert group.members == tuple(sorted(group.members, key=lambda member: (member.event_time, member.match.event_id)))


def test_replays_do_not_inflate_threshold():
    original = event(1)
    result = run((original, original, copy.deepcopy(original)))
    assert result.received_count == 3 and result.unique_event_count == 1 and result.replay_count == 2
    assert result.groups == () and result.below_threshold_event_count == 1
    result = run((original, original.model_copy(update={'ingested_at': None}), event(2)))
    assert result.groups[0].event_count == 2 and result.replay_count == 1


def test_conflicting_event_or_evidence_identity_rejects_batch():
    first = event(1)
    for changed in (first.model_copy(update={'severity': 61}),
                    first.model_copy(update={'event_id': uuid4()}),
                    event(2).model_copy(update={'evidence_id': first.evidence_id}),
                    first.model_copy(update={'evidence_sha256': 'f' * 64})):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            run((first, changed))


def test_logical_group_id_stable_but_result_identity_tracks_members():
    first = run((event(1), event(2))).groups[0]
    enlarged = run((event(1), event(2), event(3))).groups[0]
    assert enlarged.group_id == first.group_id
    assert enlarged.result_id != first.result_id
    changed = run((event(1), event(2)), policy(version=2)).groups[0]
    assert changed.group_id != first.group_id and changed.result_id != first.result_id
    changed = run((event(1), event(2)), policy(detection_rule=rule(version=2))).groups[0]
    assert changed.group_id != first.group_id


def test_tenant_boundaries_and_spoofed_attributes():
    other = uuid4()
    for events, selected, trusted in [
        ((event(1).model_copy(update={'tenant_id': other}),), policy(), TENANT),
        ((), policy(), other), ((), policy(), str(TENANT)),
        ((event(1, severity=0).model_copy(update={'tenant_id': other}),), policy(), TENANT),
    ]:
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            run(events, selected, trusted)
    spoof = event(1).model_copy(update={'attributes': (('tenant_id', str(other)),)})
    assert run((spoof, event(2))).groups[0].tenant_id == TENANT
    with pytest.raises(ValueError):
        policy(tenant_id=other)


@pytest.mark.parametrize('patch', [
    {'window_seconds': 0}, {'window_seconds': 86401}, {'window_seconds': True},
    {'window_seconds': '60'}, {'window_seconds': 1.5}, {'min_events': 1},
    {'min_events': 101}, {'min_events': True}, {'version': 0}, {'version': True},
    {'version': 2 ** 31}, {'group_by': ()}, {'group_by': ('tenant_id',)},
    {'group_by': ('attributes.tenant_id',)}, {'group_by': ('agent.id', 'agent.id')},
    {'group_by': ('agent.id', 'agent.name', 'source.ip', 'category')},
    {'group_by': ['agent.id']}, {'group_by': ('__class__',)},
    {'policy_id': 'bad'}, {'name': ''}, {'name': 'x' * 129},
    {'schema_version': '2.0'}, {'unexpected': 'data'}, {'detection_rule': None},
])
def test_invalid_policies(patch):
    with pytest.raises(ValueError):
        policy(**patch)


@pytest.mark.parametrize('events', [None, {}, 'bad', [None], [object()], [{'secret': 'do-not-echo'}]])
def test_invalid_event_input(events):
    with pytest.raises(ValueError, match='^invalid_correlation_input$') as error:
        run(events)
    assert 'do-not-echo' not in str(error.value)


def test_input_limits_and_no_generator_consumption():
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        run(tuple(event(index) for index in range(101)))
    def events():
        pytest.fail('unbounded iterable consumed')
        yield event()
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        run(events())


def test_shared_payload_budget():
    large = tuple(event(index).model_copy(update={'attributes': (('text', 'x' * 4096),) * 10})
                  for index in range(100))
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        run(large)


def test_forged_models_are_revalidated():
    for events, selected in [
        ((event().model_copy(update={'severity': True}),), policy()),
        ((event().model_copy(update={'agent': {'name': object()}}),), policy()),
        ((), policy().model_copy(update={'min_events': True})),
        ((), policy().model_copy(update={'tenant_id': uuid4()})),
    ]:
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            run(events, selected)


def test_immutability_and_inputs_unchanged():
    events = (event(1), event(2)); selected = policy()
    before = copy.deepcopy((events, selected))
    result = run(events, selected)
    assert (events, selected) == before
    for model, field, value in [(selected, 'version', 2), (result, 'received_count', 0),
                               (result.groups[0], 'event_count', 1),
                               (result.groups[0].members[0], 'event_time', START)]:
        with pytest.raises(ValidationError):
            setattr(model, field, value)


def test_no_io_or_dynamic_execution(monkeypatch):
    import builtins
    import socket
    import subprocess
    events = (event(1), event(2)); selected = policy()
    def forbidden(*args, **kwargs):
        pytest.fail('correlation performed forbidden operation')
    for name in ('eval', 'exec', 'open'):
        monkeypatch.setattr(builtins, name, forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    assert len(run(events, selected).groups) == 1


@pytest.mark.parametrize('field', ['source_system', 'agent.id', 'agent.name', 'agent.ip',
                                    'source.ip', 'destination.ip'])
def test_each_allowlisted_group_field(field):
    result = run((event(1), event(2)), policy(group_by=(field,)))
    assert len(result.groups) == 1 and result.groups[0].group_key[0][0] == field


def test_category_grouping_uses_only_explicit_category():
    selected = policy(group_by=('category',))
    result = run((event(1), event(2)), selected)
    assert result.missing_group_key_count == 2 and result.groups == ()
    values = tuple(event(index).model_copy(update={'category': 'authentication'}) for index in (1, 2))
    assert run(values, selected).groups[0].group_key == (('category', 'authentication'),)


def test_maximum_event_count_and_threshold_are_supported():
    values = tuple(event(index) for index in range(100))
    result = run(values, policy(min_events=100))
    assert result.received_count == result.unique_event_count == result.groups[0].event_count == 100
    assert run(tuple(reversed(values)), policy(min_events=100)) == result


def test_maximum_group_count_is_supported():
    values = tuple(event(index, agent=str(index // 2)) for index in range(100))
    result = run(values)
    assert len(result.groups) == 50
    assert sum(group.event_count for group in result.groups) == 100


def test_accounting_partitions_distinct_events_and_replays():
    values = (event(1), event(2), event(3, agent='singleton'), event(4, severity=0),
              event(5).model_copy(update={'agent': None}), event(1))
    result = run(values)
    assert result.received_count == result.unique_event_count + result.replay_count
    assert result.unique_event_count == result.matched_event_count + result.nonmatched_event_count
    assert result.matched_event_count == (result.missing_group_key_count + result.below_threshold_event_count
                                         + sum(group.event_count for group in result.groups))
    assert (result.replay_count, result.nonmatched_event_count, result.missing_group_key_count,
            result.below_threshold_event_count) == (1, 1, 1, 1)


def test_no_accumulation_between_calls_and_idempotent_replay():
    assert run((event(1),)).groups == run((event(2),)).groups == ()
    result = run((event(1), event(2)))
    assert run((event(1), event(2))) == result


def test_close_events_across_boundary_do_not_form_rolling_group():
    result = run((event(1, offset=59), event(2, offset=60)))
    assert result.groups == () and result.below_threshold_event_count == 2


def test_policy_json_roundtrip_and_condition_order_preserve_results():
    from tests.detection.test_detection_rules import condition
    selected = policy(detection_rule=rule(conditions=(condition(), condition('agent.id', 'eq', '001'))))
    restored = CorrelationPolicy.model_validate_json(selected.model_dump_json())
    reordered = policy(detection_rule=rule(conditions=(condition('agent.id', 'eq', '001'), condition())))
    assert selected == restored == reordered
    assert run((event(1), event(2)), selected) == run((event(1), event(2)), reordered)


def test_timezone_offsets_canonicalize_to_same_window_and_result():
    values = (event(1), event(2))
    zone = timezone(timedelta(hours=5, minutes=30))
    offset_values = tuple(item.model_copy(update={'event_time': item.event_time.astimezone(zone)}) for item in values)
    assert run(values) == run(offset_values)


@pytest.mark.parametrize('timestamp', [datetime(2026, 11, 9), 'bad',
                                       datetime.max.replace(tzinfo=timezone.utc)])
def test_invalid_or_unrepresentable_windows_reject_safely(timestamp):
    values = (event(1).model_copy(update={'event_time': timestamp}), event(2))
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        run(values)


@pytest.mark.parametrize('selected', [None, {}, object()])
def test_invalid_policy_objects(selected):
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        correlate_events((), selected, tenant_id=TENANT)


def test_conflicting_nonmatches_also_reject_instead_of_hiding_bad_input():
    first = event(1, severity=0)
    changed = first.model_copy(update={'source_reference': 'conflict'})
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        run((first, changed))


def test_cyclic_oversized_and_unexpected_model_values_reject_safely():
    cycle = {}; cycle['recursive'] = cycle
    for value in (cycle, 'x' * 5000, '\ud800', 2 ** 100):
        with pytest.raises(ValueError, match='^invalid_correlation_input$'):
            run((event(1).model_copy(update={'agent': value}),))


def test_result_id_tracks_member_content_and_group_id_tracks_policy_or_key():
    first = run((event(1), event(2))).groups[0]
    changed = event(2).model_copy(update={'severity': 61})
    second = run((event(1), changed)).groups[0]
    assert second.group_id == first.group_id and second.result_id != first.result_id
    for selected in (policy(name='Renamed'), policy(window_seconds=120), policy(group_by=('agent.name',))):
        assert run((event(1), event(2)), selected).groups[0].group_id != first.group_id


def test_malformed_inputs_do_not_mutate_original_objects_on_failure():
    values = (event(1), event(1).model_copy(update={'severity': True})); selected = policy()
    before = copy.deepcopy((values, selected))
    with pytest.raises(ValueError, match='^invalid_correlation_input$'):
        run(values, selected)
    assert (values, selected) == before
