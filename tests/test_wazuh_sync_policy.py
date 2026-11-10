from uuid import uuid4

import certifi
import httpx
import pytest

from app.config import settings
from app.wazuh import WazuhIndexerClient, WazuhIndexerError
from app.wazuh_sync import SyncScope, WazuhSyncError, load_scope


def policy(**changes):
    value = dict(tenant_id=str(uuid4()), bootstrap_start_ms=1000,
                 source_field='organization.id', source_value='org-a')
    value.update(changes)
    return value


@pytest.mark.parametrize('changes', [
    {'bootstrap_start_ms': True}, {'bootstrap_start_ms': -1},
    {'tenant_id': 'invalid'}, {'source_field': None}, {'source_value': ''},
    {'source_field': '_id'}, {'source_field': 'organization.*'},
    {'dedicated_source': True}, {'overlap_ms': 300000},
    {'window_ms': 0}, {'password': 'should-not-be-a-policy-field'},
])
def test_invalid_operator_policy(changes):
    with pytest.raises(ValueError):
        SyncScope.model_validate(policy(**changes))


@pytest.mark.parametrize('case', ['dedicated', 'same_value', 'different_field'])
def test_ambiguous_shared_source_is_denied(monkeypatch, case):
    a, b, tenant = uuid4(), uuid4(), uuid4()
    first = policy(tenant_id=str(tenant))
    other = policy()
    if case == 'dedicated':
        other.update(dedicated_source=True, source_field=None, source_value=None)
    elif case == 'different_field':
        other['source_field'] = 'another.id'
    monkeypatch.setattr(settings, 'wazuh_sync_scopes', {str(a): first, str(b): other})
    with pytest.raises(WazuhSyncError, match='wazuh_sync_scope_unavailable'):
        load_scope(a, tenant)


def test_disjoint_shared_source_values_allowed(monkeypatch):
    a, b, tenant = uuid4(), uuid4(), uuid4()
    monkeypatch.setattr(settings, 'wazuh_sync_scopes', {
        str(a): policy(tenant_id=str(tenant)), str(b): policy(source_value='org-b')})
    assert load_scope(a, tenant).source_filter() == {'term': {'organization.id': 'org-a'}}


def test_dedicated_source_requires_explicit_assertion(monkeypatch):
    identity, tenant = uuid4(), uuid4()
    monkeypatch.setattr(settings, 'wazuh_sync_scopes', {str(identity): policy(
        tenant_id=str(tenant), dedicated_source=True, source_field=None, source_value=None)})
    assert load_scope(identity, tenant).source_filter() == {'match_all': {}}


@pytest.mark.parametrize('case', ['missing_uuid', 'wrong_type', 'doc_values', 'missing_index', 'empty'])
def test_invalid_index_metadata(case):
    indices = {'wazuh-alerts-test': {'settings': {'index': {'uuid': 'index-uuid'}}}}
    mappings = {'wazuh-alerts-test': {'mappings': {
        field: {'mapping': {field: {'type': kind}}}
        for field, kind in [('timestamp', 'date'), ('id', 'keyword')]}}}
    if case == 'missing_uuid': indices['wazuh-alerts-test']['settings']['index'].clear()
    elif case == 'wrong_type': mappings['wazuh-alerts-test']['mappings']['id']['mapping']['id']['type'] = 'text'
    elif case == 'doc_values': mappings['wazuh-alerts-test']['mappings']['id']['mapping']['id']['doc_values'] = False
    elif case == 'missing_index': mappings.clear()
    else: indices.clear()
    def handler(request):
        return httpx.Response(200, json=indices if '/_settings/' in request.url.path else mappings)
    with WazuhIndexerClient(base_url='https://indexer.test', username='test', password='test',
                            ca_certificate=certifi.where()) as client:
        client._client.close(); client._client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(WazuhIndexerError, match='wazuh_indexer_invalid_metadata'):
            client.inspect_alert_indices()


def test_shared_scope_field_must_be_an_exact_keyword_mapping():
    def handler(request):
        if '/_settings/' in request.url.path:
            return httpx.Response(200, json={'wazuh-alerts-test': {'settings': {'index': {'uuid': 'uuid'}}}})
        return httpx.Response(200, json={'wazuh-alerts-test': {'mappings': {
            field: {'mapping': {field: {'type': kind}}}
            for field, kind in [('timestamp', 'date'), ('id', 'keyword'), ('organization.id', 'text')]}}})
    with WazuhIndexerClient(base_url='https://indexer.test', username='test', password='test',
                            ca_certificate=certifi.where()) as client:
        client._client.close(); client._client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(WazuhIndexerError):
            client.inspect_alert_indices(scope_field='organization.id')
