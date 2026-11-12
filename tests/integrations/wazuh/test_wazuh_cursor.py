import json
from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from app.integrations.wazuh.cursor import WazuhCursor, validate_sort_values


TENANT = UUID('11111111-1111-4111-8111-111111111111')
INTEGRATION = UUID('22222222-2222-4222-8222-222222222222')
SNAPSHOT = UUID('33333333-3333-4333-8333-333333333333')


def cursor(**changes):
    values = dict(
        tenant_id=TENANT, integration_id=INTEGRATION,
        query_fingerprint='a' * 64, generation=0,
        window_start_ms=1000, window_end_ms=2000,
        snapshot_id=SNAPSHOT, sort_values=(1500, 'index-a', 'alert-a'),
    )
    values.update(changes)
    return WazuhCursor(**values)


def decode(value, **changes):
    context = dict(tenant_id=TENANT, integration_id=INTEGRATION,
                   query_fingerprint='a' * 64, generation=0,
                   window_start_ms=1000, window_end_ms=2000,
                   snapshot_id=SNAPSHOT)
    context.update(changes)
    return WazuhCursor.deserialize(value, **context)


def test_cursor_serialization_is_canonical_and_round_trips():
    value = cursor()
    assert decode(value.serialize()) == value
    assert value.serialize() == value.serialize()
    assert json.loads(value.serialize())['version'] == 1
    assert 'password' not in value.serialize()


@pytest.mark.parametrize('field,value', [
    ('tenant_id', uuid4()), ('integration_id', uuid4()),
    ('query_fingerprint', 'b' * 64), ('generation', 1),
    ('window_start_ms', 999), ('window_end_ms', 2001),
    ('snapshot_id', uuid4()),
])
def test_cursor_rejects_wrong_checkpoint_context(field, value):
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        decode(cursor().serialize(), **{field: value})


@pytest.mark.parametrize('value', [
    None, b'{}', '', '[]', 'null', '{', 'x' * 8193,
    '{"version":1,"version":1}',
])
def test_invalid_serialized_cursor(value):
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        decode(value)


@pytest.mark.parametrize('field,value', [
    ('version', 2), ('version', True), ('generation', True),
    ('generation', -1), ('generation', 2**63),
    ('tenant_id', 'invalid'), ('integration_id', None),
    ('snapshot_id', None), ('query_fingerprint', 'A' * 64),
    ('query_fingerprint', 'not-a-hash'), ('window_start_ms', -1),
    ('window_end_ms', 1000), ('window_end_ms', 253402300800000),
    ('sort_values', [2000, 'index-a', 'alert-a']),
    ('sort_values', [999, 'index-a', 'alert-a']),
])
def test_rejects_invalid_cursor_fields(field, value):
    data = json.loads(cursor().serialize())
    data[field] = value
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        decode(json.dumps(data))


def test_unknown_and_missing_fields_rejected():
    data = json.loads(cursor().serialize())
    data['password'] = 'must-not-be-accepted'
    with pytest.raises(ValueError, match='invalid_wazuh_cursor') as error:
        decode(json.dumps(data))
    assert 'must-not-be-accepted' not in str(error.value)
    del data['password']
    del data['sort_values']
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        decode(json.dumps(data))


@pytest.mark.parametrize('value', [
    None, [], [1, 'index'], [1, 'index', 'id', 4],
    [True, 'index', 'id'], [1.0, 'index', 'id'],
    [-1, 'index', 'id'], [253402300800000, 'index', 'id'],
    [1, '', 'id'], [1, 'index', ''], [1, None, 'id'],
    [1, 'index', True], [1, 'index\n', 'id'],
    [1, 'index', 'x' * 513], [1, 'index', '\ud800'],
])
def test_invalid_sort_values(value):
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        validate_sort_values(value)


def test_sort_validation_returns_immutable_tuple():
    original = [1500, 'index-a', 'alert-a']
    result = validate_sort_values(original)
    original[2] = 'changed'
    assert result == (1500, 'index-a', 'alert-a')


@pytest.mark.parametrize('next_values', [
    (1500, 'index-a', 'alert-b'),
    (1500, 'index-b', 'alert-a'),
    (1501, 'index-a', 'alert-a'),
])
def test_strict_sort_progression_with_equal_timestamps(next_values):
    assert cursor().advance(next_values).sort_values == next_values
    assert cursor().sort_values == (1500, 'index-a', 'alert-a')


@pytest.mark.parametrize('next_values', [
    (1500, 'index-a', 'alert-a'), (1499, 'index-z', 'alert-z'),
    (1500, 'index-a', 'alert-0'), (1500, 'index-0', 'alert-z'),
    (2000, 'index-a', 'alert-z'),
])
def test_repeated_decreasing_or_out_of_window_position_rejected(next_values):
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        cursor().advance(next_values)


def test_direct_construction_validates_and_normalizes():
    assert isinstance(cursor(sort_values=[1500, 'index-a', 'alert-a']).sort_values, tuple)
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        replace(cursor(), tenant_id=str(TENANT))
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        cursor(generation=True)


def test_duplicate_json_fields_rejected_even_with_valid_payload():
    value = cursor().serialize()
    with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
        decode(value[:-1] + ',"version":1}')
