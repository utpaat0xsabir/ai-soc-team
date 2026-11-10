import hashlib
import json

import pytest

from app.wazuh import alert_query_fingerprint
from app.wazuh_sync import _verify_manifest, WazuhSyncError


def test_fingerprint_preserves_legacy_query_contract():
    scope = {'term': {'organization.id': 'org'}}
    context = {'index_manifest': {'wazuh-alerts-a': 'uuid'}, 'policy': 'policy', 'connection': 'connection'}
    legacy = {'indices': ('wazuh-alerts-a',), 'scope': scope,
              'sort': ['timestamp', '_index', 'id'], 'version': 1, 'context': context}
    expected = hashlib.sha256(json.dumps(legacy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert alert_query_fingerprint(('wazuh-alerts-a',), scope, context) == expected


def test_fingerprint_is_order_independent_but_scope_sensitive():
    assert alert_query_fingerprint(('b', 'a'), {'match_all': {}}) == alert_query_fingerprint(('a', 'b'), {'match_all': {}})
    assert alert_query_fingerprint(('a',), {'term': {'org': 'a'}}) != alert_query_fingerprint(('a',), {'term': {'org': 'b'}})


def test_manifest_additions_preserve_existing_identity():
    assert _verify_manifest({'old': 'uuid'}, {'old': 'uuid', 'new': 'new-uuid'}) is None


@pytest.mark.parametrize('current,code', [({}, 'retention_gap'), ({'old': 'changed'}, 'source_changed')])
def test_manifest_loss_or_recreation_is_never_silent(current, code):
    with pytest.raises(WazuhSyncError, match=code):
        _verify_manifest({'old': 'uuid'}, current)
