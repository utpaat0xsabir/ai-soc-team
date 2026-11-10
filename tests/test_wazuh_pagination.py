import copy
import json
from dataclasses import replace
from uuid import uuid4

import certifi
import httpx
import pytest

from app.wazuh import WazuhIndexerClient, WazuhIndexerError


INDEX = 'wazuh-alerts-test'
TENANT, INTEGRATION = uuid4(), uuid4()
SHARDS = {'total': 1, 'successful': 1, 'skipped': 0, 'failed': 0}


def hit(identifier='a', timestamp=1500):
    return {'_index': INDEX, '_id': 'doc-' + identifier,
            '_source': {'id': identifier, 'timestamp': f'1970-01-01T00:00:01.{timestamp - 1000:03d}Z'},
            'sort': [timestamp, INDEX, identifier], 'fields': {'extra': ['preserve']}}


def response(hits):
    return {'timed_out': False, '_shards': dict(SHARDS), 'hits': {'hits': hits}}


class Indexer:
    def __init__(self, pages=None):
        self.pages = list(pages or [response([])])
        self.requests = []
        self.create = {'pit_id': 'private-pit', '_shards': dict(SHARDS)}
        self.delete_status = 200

    def __call__(self, request):
        self.requests.append(request)
        if request.method == 'DELETE':
            token = json.loads(request.content)['pit_id'][0]
            return httpx.Response(self.delete_status, json={'pits': [{'pit_id': token, 'successful': True}]})
        if request.url.path.endswith('/_search/point_in_time'):
            return httpx.Response(200, json=self.create)
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        if isinstance(page, httpx.Response):
            return page
        return httpx.Response(200, json=page)


@pytest.fixture
def client_factory():
    clients = []

    def make(indexer):
        client = WazuhIndexerClient(base_url='https://indexer.test', username='test',
                                    password='secret', ca_certificate=certifi.where())
        client._client.close()
        client._client = httpx.Client(transport=httpx.MockTransport(indexer))
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


def snapshot(client, **changes):
    args = dict(tenant_id=TENANT, integration_id=INTEGRATION,
                index_names=(INDEX,), window_start_ms=1000, window_end_ms=2000,
                source_filter={'term': {'organization.id': 'test-org'}})
    args.update(changes)
    return client.alert_snapshot(**args)


def test_first_next_and_empty_pages_preserve_documents(client_factory):
    docs = [hit('a'), hit('b'), hit('c')]
    original = copy.deepcopy(docs)
    server = Indexer([response(docs), response([docs[2]]), response([])])
    with snapshot(client_factory(server)) as scan:
        first = scan.page(size=2)
        assert [x['raw_document'] for x in first['items']] == docs[:2]
        assert first['next_cursor'].sort_values == tuple(docs[1]['sort'])
        assert not first['exhausted']
        second = scan.page(size=2, cursor=first['next_cursor'])
        assert second['items'][0]['raw_document'] == docs[2]
        assert not second['exhausted']  # A short page is not proof of exhaustion.
        empty = scan.page(size=2, cursor=second['next_cursor'])
        assert empty['exhausted'] and empty['next_cursor'] == second['next_cursor']
    assert docs == original
    create = server.requests[0]
    assert create.url.params['allow_partial_pit_creation'] == 'false'
    assert create.url.params['ignore_unavailable'] == 'false'
    queries = [json.loads(r.content) for r in server.requests if r.url.path == '/_search']
    assert queries[0]['size'] == 3
    assert queries[0]['sort'] == [{'timestamp': 'asc'}, {'_index': 'asc'}, {'id': 'asc'}]
    assert 'search_after' not in queries[0] and 'from' not in queries[0]
    assert queries[1]['search_after'] == docs[1]['sort']
    assert queries[0]['query']['bool']['filter'][0] == {'term': {'organization.id': 'test-org'}}
    assert server.requests[-1].method == 'DELETE'
    assert 'private-pit' not in repr(first)
    assert 'private-pit' not in repr(scan)


@pytest.mark.parametrize('docs', [
    [hit('a'), hit('a')], [hit('b'), hit('a')],
    [hit('a'), hit('b'), hit('b')],
])
def test_sort_collision_including_lookahead_rejected(client_factory, docs):
    server = Indexer([response(docs)])
    with snapshot(client_factory(server)) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page(size=2)


@pytest.mark.parametrize('field,value', [
    ('sort', None), ('sort', [True, INDEX, 'a']), ('sort', [1500, INDEX]),
    ('sort', [1500, INDEX, 'a', 1]), ('sort', [1500.5, INDEX, 'a']),
    ('sort', [2000, INDEX, 'a']), ('sort', [999, INDEX, 'a']),
    ('sort', [1500, 'other-index', 'a']), ('_index', 'other-index'),
    ('_id', None), ('_source', None),
])
def test_malformed_hit_rejected(client_factory, field, value):
    doc = hit(); doc[field] = value
    with snapshot(client_factory(Indexer([response([doc])]))) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page()


@pytest.mark.parametrize('field,value', [
    ('id', ['a']), ('id', None), ('id', 'different'),
    ('timestamp', ['1970-01-01T00:00:01.500Z']),
    ('timestamp', None), ('timestamp', '1970-01-01T00:00:01.600Z'),
])
def test_missing_multivalued_or_inconsistent_source_keys(client_factory, field, value):
    doc = hit(); doc['_source'][field] = value
    with snapshot(client_factory(Indexer([response([doc])]))) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page()


@pytest.mark.parametrize('data', [
    [], {}, {'timed_out': True, '_shards': SHARDS, 'hits': {'hits': []}},
    {'timed_out': 0, '_shards': SHARDS, 'hits': {'hits': []}},
    {'timed_out': False, '_shards': {'total': 2, 'successful': 1, 'skipped': 0, 'failed': 1}, 'hits': {'hits': []}},
    {'timed_out': False, '_shards': {'total': 2, 'successful': 1, 'skipped': 0, 'failed': 0}, 'hits': {'hits': []}},
    {'timed_out': False, '_shards': SHARDS, 'hits': {'hits': None}},
])
def test_invalid_or_incomplete_responses(client_factory, data):
    with snapshot(client_factory(Indexer([data]))) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page()


@pytest.mark.parametrize('size', [0, -1, 101, True, 1.5, '2'])
def test_invalid_page_size_before_search(client_factory, size):
    server = Indexer()
    with snapshot(client_factory(server)) as scan:
        with pytest.raises(ValueError, match='invalid_wazuh_page_size'):
            scan.page(size=size)
        assert len(server.requests) == 1


def test_oversized_page_rejected(client_factory):
    with snapshot(client_factory(Indexer([response([hit('a'), hit('b'), hit('c')])]))) as scan:
        with pytest.raises(WazuhIndexerError):
            scan.page(size=1)


@pytest.mark.parametrize('field,value', [
    ('tenant_id', uuid4()), ('integration_id', uuid4()), ('snapshot_id', uuid4()),
    ('query_fingerprint', 'f' * 64), ('generation', 1),
    ('window_start_ms', 999), ('window_end_ms', 2001),
])
def test_cursor_context_rejected_before_request(client_factory, field, value):
    server = Indexer([response([hit()])])
    with snapshot(client_factory(server)) as scan:
        good = scan.page()['next_cursor']
        count = len(server.requests)
        with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
            scan.page(cursor=replace(good, **{field: value}))
        assert len(server.requests) == count


def test_replayed_page_after_cursor_rejected(client_factory):
    server = Indexer([response([hit()]), response([hit()])])
    with snapshot(client_factory(server)) as scan:
        cursor = scan.page()['next_cursor']
        with pytest.raises(WazuhIndexerError):
            scan.page(cursor=cursor)


@pytest.mark.parametrize('page,code', [
    (httpx.Response(404, json={'secret': 'private-pit'}), 'wazuh_snapshot_expired'),
    (httpx.Response(403, json={'secret': 'password'}), 'wazuh_indexer_request_failed'),
    (httpx.Response(500), 'wazuh_indexer_request_failed'),
    (httpx.Response(200, content='not json private-pit'), 'wazuh_indexer_invalid_response'),
    (httpx.ReadTimeout('password private-pit'), 'wazuh_indexer_connection_failed'),
])
def test_safe_http_and_json_errors_and_cleanup(client_factory, page, code):
    server = Indexer([page])
    with pytest.raises(WazuhIndexerError, match=code) as error:
        with snapshot(client_factory(server)) as scan:
            scan.page()
    assert 'private-pit' not in str(error.value)
    assert 'password' not in str(error.value)
    assert error.value.__suppress_context__
    assert server.requests[-1].method == 'DELETE'


def test_cleanup_failure_does_not_mask_processing_failure(client_factory):
    server = Indexer(); server.delete_status = 500
    with pytest.raises(RuntimeError, match='original'):
        with snapshot(client_factory(server)):
            raise RuntimeError('original')


def test_cleanup_failure_after_success_is_reported(client_factory):
    server = Indexer(); server.delete_status = 500
    with pytest.raises(WazuhIndexerError):
        with snapshot(client_factory(server)):
            pass


def test_closed_snapshot_cannot_search(client_factory):
    server = Indexer()
    with snapshot(client_factory(server)) as scan:
        pass
    with pytest.raises(ValueError, match='wazuh_snapshot_closed'):
        scan.page()


@pytest.mark.parametrize('changes', [
    {'index_names': ('*',)}, {'index_names': ('../secrets',)}, {'index_names': ()},
    {'tenant_id': 'invalid'}, {'integration_id': None},
    {'window_start_ms': True}, {'window_end_ms': 1000},
    {'source_filter': None}, {'source_filter': []}, {'source_filter': {}},
])
def test_invalid_snapshot_before_network(client_factory, changes):
    server = Indexer()
    with pytest.raises(ValueError):
        with snapshot(client_factory(server), **changes):
            pass
    assert not server.requests


def test_partial_creation_released_before_error(client_factory):
    server = Indexer(); server.create['_shards']['failed'] = 1
    with pytest.raises(WazuhIndexerError):
        with snapshot(client_factory(server)):
            pass
    assert server.requests[-1].method == 'DELETE'


def test_snapshot_filter_is_frozen(client_factory):
    server = Indexer([response([])])
    scope = {'term': {'organization.id': 'original'}}
    with snapshot(client_factory(server), source_filter=scope) as scan:
        scope['term']['organization.id'] = 'changed'
        scan.page()
    search = next(r for r in server.requests if r.url.path == '/_search')
    assert json.loads(search.content)['query']['bool']['filter'][0]['term']['organization.id'] == 'original'


def test_query_does_not_silently_exclude_missing_timestamps(client_factory):
    server = Indexer([response([])])
    with snapshot(client_factory(server)) as scan:
        scan.page()
    search = next(r for r in server.requests if r.url.path == '/_search')
    condition = json.loads(search.content)['query']['bool']['filter'][1]['bool']
    assert condition['minimum_should_match'] == 1
    assert {'bool': {'must_not': [{'exists': {'field': 'timestamp'}}]}} in condition['should']


def test_response_byte_limit(client_factory):
    server = Indexer([httpx.Response(200, content=b' ' * (8 * 1024 * 1024 + 1))])
    with snapshot(client_factory(server)) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page()


def test_maximum_page_uses_only_one_extra_hit(client_factory):
    docs = [hit(f'{n:03d}') for n in range(101)]
    server = Indexer([response(docs)])
    with snapshot(client_factory(server)) as scan:
        page = scan.page(size=100)
        assert len(page['items']) == 100
        assert page['next_cursor'].sort_values[-1] == '099'
    search = next(r for r in server.requests if r.url.path == '/_search')
    assert json.loads(search.content)['size'] == 101


@pytest.mark.parametrize('generation', [True, -1, 1.5, 2**63])
def test_invalid_generation_before_request(client_factory, generation):
    server = Indexer()
    with snapshot(client_factory(server)) as scan:
        with pytest.raises(ValueError, match='invalid_wazuh_cursor'):
            scan.page(generation=generation)
        assert len(server.requests) == 1


def test_rotated_pit_token_used_and_released(client_factory):
    first = response([hit()]); first['pit_id'] = 'rotated-private-pit'
    server = Indexer([first, response([])])
    with snapshot(client_factory(server)) as scan:
        page = scan.page()
        scan.page(cursor=page['next_cursor'])
    searches = [r for r in server.requests if r.url.path == '/_search']
    assert json.loads(searches[1].content)['pit']['id'] == 'rotated-private-pit'
    assert json.loads(server.requests[-1].content)['pit_id'] == ['rotated-private-pit']


@pytest.mark.parametrize('create', [
    {}, {'pit_id': ''}, {'pit_id': 3}, {'pit_id': 'invalid\nsecret'},
    {'pit_id': 'private-pit'}, {'pit_id': 'private-pit', '_shards': []},
])
def test_invalid_snapshot_creation(client_factory, create):
    server = Indexer(); server.create = create
    with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
        with snapshot(client_factory(server)):
            pytest.fail('invalid PIT must not be yielded')


def test_cleanup_rejection_is_not_reported_as_success(client_factory):
    server = Indexer()
    original = server.__call__

    def handler(request):
        if request.method == 'DELETE':
            return httpx.Response(200, json={'pits': [{'pit_id': 'private-pit', 'successful': False}]})
        return original(request)

    with pytest.raises(WazuhIndexerError, match='wazuh_snapshot_cleanup_failed'):
        with snapshot(client_factory(handler)):
            pass


@pytest.mark.parametrize('body', [
    json.dumps(response([])).encode()[:-1] + b',"timed_out":false}',
    json.dumps(response([])).encode()[:-1] + b',"extra":NaN}',
    json.dumps(response([])).encode()[:-1] + b',"extra":Infinity}',
])
def test_ambiguous_or_nonstandard_json_rejected(client_factory, body):
    server = Indexer([httpx.Response(200, content=body)])
    with snapshot(client_factory(server)) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page()


def test_equal_timestamps_and_ids_across_indices_paginate_safely(client_factory):
    first, second = hit(), hit()
    second['_index'] = 'wazuh-alerts-test-z'
    second['sort'][1] = second['_index']
    server = Indexer([response([first, second]), response([second])])
    with snapshot(client_factory(server), index_names=(INDEX, second['_index'])) as scan:
        page = scan.page(size=1)
        next_page = scan.page(size=1, cursor=page['next_cursor'])
        assert page['items'][0]['raw_document'] == first
        assert next_page['items'][0]['raw_document'] == second


def test_client_specific_lower_page_limit(client_factory):
    server = Indexer()
    client = client_factory(server)
    client.max_page_size = 1
    with snapshot(client) as scan:
        with pytest.raises(ValueError, match='invalid_wazuh_page_size'):
            scan.page(size=2)
        assert len(server.requests) == 1


def test_changed_snapshot_shard_coverage_rejected(client_factory):
    data = response([])
    data['_shards'].update(total=2, successful=2)
    with snapshot(client_factory(Indexer([data]))) as scan:
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_response'):
            scan.page()
