"""TG-04A only: closed synthetic dataset, never a network-backed Wazuh adapter.

Only tool_gateway.execute dispatches the private adapter. Trusted callers bind a
tenant/principal/integration to a dedicated fake source. Hashes bind pagination;
they do not authenticate source ownership. Live mapping/egress are unimplemented.
"""

import hashlib
import hmac
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, PrivateAttr, model_validator

from app.gateway.contracts import _Contract, ToolRequest


CAPABILITY_ID = 'wazuh.alerts.search'
SYNTHETIC_INDEX = 'wazuh-alerts-synthetic-v1'
Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Size = Annotated[int, Field(ge=1, le=2)]
Offset = Annotated[int, Field(ge=0, le=4)]


def _hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


class WazuhSourceBinding(_Contract):
    tenant_id: UUID
    principal_id: UUID
    integration_id: UUID
    source_index: Literal['wazuh-alerts-synthetic-v1']
    source_scope: Literal['DEDICATED_SYNTHETIC']
    source_snapshot: Literal['synthetic-v1'] = 'synthetic-v1'
    capability_id: Literal['wazuh.alerts.search'] = 'wazuh.alerts.search'
    capability_version: Literal['1.0'] = '1.0'
    operation: Literal['query'] = 'query'


def _binding(value):
    if type(value) is not WazuhSourceBinding or value.model_extra:
        raise ValueError('invalid_synthetic_source')
    return WazuhSourceBinding.model_validate(dict(value.__dict__))


def search_parameters(binding: WazuhSourceBinding, *, size: int, offset: int) -> tuple:
    """Pure parameter builder; no grant, source proof or execution authority."""
    binding = _binding(binding)
    if type(size) is not int or not 1 <= size <= 2 or type(offset) is not int or not 0 <= offset <= 4:
        raise ValueError('invalid_synthetic_page')
    context = _hash({'binding': binding.model_dump(mode='json'), 'size': size, 'offset': offset})
    return (('offset', str(offset)), ('query_context', context), ('size', str(size)))


def _parse_search(request, binding):
    binding = _binding(binding)
    if (type(request) is not ToolRequest or request.capability_id != CAPABILITY_ID
            or request.capability_version != '1.0' or request.operation != 'query'
            or request.tenant_id != binding.tenant_id or request.principal_id != binding.principal_id
            or request.target != str(binding.integration_id)):
        raise ValueError('invalid_synthetic_search')
    parameters = dict(request.parameters)
    if (set(parameters) != {'size', 'offset', 'query_context'}
            or parameters['size'] not in ('1', '2') or parameters['offset'] not in ('0', '1', '2', '3', '4')):
        raise ValueError('invalid_synthetic_search')
    size, offset = int(parameters['size']), int(parameters['offset'])
    if request.parameters != search_parameters(binding, size=size, offset=offset):
        raise ValueError('invalid_synthetic_context')
    return size, offset


class SyntheticAlert(_Contract):
    document_id: Annotated[str, Field(pattern=r'^synthetic-alert-00[1-4]$')]
    source_reference: Annotated[str, Field(pattern=r'^wazuh-alerts-synthetic-v1/synthetic-alert-00[1-4]$')]
    timestamp: Literal['2026-11-11T00:00:00Z'] = '2026-11-11T00:00:00Z'
    rule_id: Literal['synthetic-rule'] = 'synthetic-rule'
    rule_level: Literal[1] = 1
    label: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'


class _Page(_Contract):
    items: Annotated[tuple[SyntheticAlert, ...], Field(max_length=2)]
    total: Literal[4] = 4
    size: Size
    offset: Offset
    next_offset: Offset | None
    next_context: Digest | None
    label: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'


def _page(binding, size, offset):
    search_parameters(binding, size=size, offset=offset)
    items = tuple(SyntheticAlert(document_id=f'synthetic-alert-{i + 1:03}',
        source_reference=f'{binding.source_index}/synthetic-alert-{i + 1:03}')
        for i in range(offset, min(offset + size, 4)))
    following = offset + len(items) if offset + len(items) < 4 else None
    context = None if following is None else dict(search_parameters(binding, size=size, offset=following))['query_context']
    return _Page(items=items, size=size, offset=offset, next_offset=following, next_context=context)


class FakeWazuhClient(_Contract):
    """The sole injectable client type; has no URL, credentials or HTTP client."""
    binding: WazuhSourceBinding
    _calls: int = PrivateAttr(default=0)

    @property
    def calls(self):
        return self._calls

    def search_alerts(self, *, size: int, offset: int) -> dict:
        self._calls += 1
        return _page(_binding(self.binding), size, offset).model_dump()


class WazuhSearchResult(ToolRequest):
    source: Literal['wazuh.alerts.search'] = 'wazuh.alerts.search'
    label: Literal['SYNTHETIC / TEST ONLY'] = 'SYNTHETIC / TEST ONLY'
    integration_id: UUID
    source_index: Literal['wazuh-alerts-synthetic-v1']
    alerts: Annotated[tuple[SyntheticAlert, ...], Field(max_length=2)]
    total: Literal[4] = 4
    size: Size
    offset: Offset
    query_context: Digest
    next_offset: Offset | None
    next_context: Digest | None
    request_sha256: Digest
    result_sha256: Digest

    @model_validator(mode='after')
    def verify_binding_and_hashes(self):
        request = ToolRequest.model_validate({key: getattr(self, key) for key in ToolRequest.model_fields})
        binding = WazuhSourceBinding(tenant_id=self.tenant_id, principal_id=self.principal_id,
            integration_id=self.integration_id, source_index=self.source_index, source_scope='DEDICATED_SYNTHETIC')
        size, offset = _parse_search(request, binding)
        expected = _page(binding, size, offset)
        if (self.size != size or self.offset != offset or self.alerts != expected.items
                or self.next_offset != expected.next_offset or self.next_context != expected.next_context
                or self.query_context != dict(request.parameters)['query_context']):
            raise ValueError('invalid_synthetic_provenance')
        data = self.model_dump(mode='json'); claimed = data.pop('result_sha256')
        if (not hmac.compare_digest(_hash(request.model_dump(mode='json')), self.request_sha256)
                or not hmac.compare_digest(_hash(data), claimed)):
            raise ValueError('invalid_synthetic_digest')
        return self


def _bounded_response(value):
    nodes = 0
    def copy(item, depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 4 or nodes > 128:
            raise ValueError('invalid_synthetic_response')
        if type(item) is dict:
            if len(item) > 16 or any(type(key) is not str or len(key) > 32 for key in item):
                raise ValueError('invalid_synthetic_response')
            return {key: copy(val, depth + 1) for key, val in item.items()}
        if type(item) is tuple:
            if len(item) > 2:
                raise ValueError('invalid_synthetic_response')
            return tuple(copy(val, depth + 1) for val in item)
        if type(item) is str and len(item) <= 160:
            return item
        if item is None or type(item) is int and 0 <= item <= 10000:
            return item
        raise ValueError('invalid_synthetic_response')
    if type(value) is not dict or set(value) != set(_Page.model_fields):
        raise ValueError('invalid_synthetic_response')
    data = copy(value)
    if len(json.dumps(data, ensure_ascii=True).encode('ascii')) > 4096:
        raise ValueError('oversized_synthetic_response')
    if type(data['items']) is not tuple or any(type(item) is not dict
            or set(item) != set(SyntheticAlert.model_fields) for item in data['items']):
        raise ValueError('invalid_synthetic_response')
    return _Page.model_validate(data)


def _search_alerts(client, binding, request):
    """Private adapter: gateway owns authorization, limits and sink writes."""
    if type(client) is not FakeWazuhClient or _binding(client.binding) != binding:
        raise ValueError('unapproved_synthetic_client')
    size, offset = _parse_search(request, binding)
    page = _bounded_response(client.search_alerts(size=size, offset=offset))
    if page != _page(binding, size, offset) or _binding(client.binding) != binding:
        raise ValueError('inconsistent_synthetic_response')
    data = {**request.model_dump(mode='json'), 'source': CAPABILITY_ID,
        'label': 'SYNTHETIC / TEST ONLY', 'integration_id': str(binding.integration_id),
        'source_index': binding.source_index, 'alerts': [item.model_dump(mode='json') for item in page.items],
        'total': page.total, 'size': size, 'offset': offset,
        'query_context': dict(request.parameters)['query_context'],
        'next_offset': page.next_offset, 'next_context': page.next_context,
        'request_sha256': _hash(request.model_dump(mode='json'))}
    data['result_sha256'] = _hash(data)
    return WazuhSearchResult.model_validate_json(json.dumps(data))
