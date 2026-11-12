"""Offline review artifacts: never provision or establish operational trust."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.integrations.wazuh import manifest as manifest


ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / 'deploy' / 'gateway-dev'


def load(name):
    return json.loads((DIRECTORY / name).read_text())


def test_compose_draft_cannot_start_services():
    draft = load('compose.review.json')
    assert draft['services'] == {}
    assert draft['x-review']['executable'] is False
    assert draft['name'] == 'ai-soc-gateway-dev'
    services = draft['x-proposed-services']
    assert set(services) == {'postgres', 'indexer', 'runner'}
    for service in services.values():
        assert service['image'] is None  # No invented versions/digests.
        assert service['ports'] == []
        assert service['restart'] == 'no'
        assert service['privileged'] is False
        assert service['cap_drop'] == ['ALL']
        assert service['security_opt'] == ['no-new-privileges:true']
    assert services['postgres']['environment'] == {'POSTGRES_DB': 'ai_soc_gateway_dev'}
    assert services['runner']['read_only'] is True
    assert services['runner']['x-live-registration'] is False
    assert services['runner']['x-schedulers'] is False
    assert all(network['internal'] for network in draft['x-proposed-networks'].values())
    assert set(services['runner']['networks']) == {'database', 'search'}
    assert services['postgres']['networks'] == ['database']
    assert services['indexer']['networks'] == ['search']
    assert set(draft['x-proposed-volumes']) == {'gateway_dev_postgres', 'gateway_dev_indexer'}
    for service in services.values():
        assert all(volume.split(':')[0] in draft['x-proposed-volumes']
                   for volume in service['volumes'])


def test_security_draft_is_unenforced_and_defaults_to_deny():
    policy = load('security-policy.review.json')
    assert policy['status'] == 'DRAFT_NOT_ENFORCED'
    assert policy['executable'] is False
    assert policy['egress']['default'] == 'DENY'
    assert policy['egress']['ipv4_and_ipv6'] is True
    assert policy['egress']['proxy'] == policy['egress']['redirects'] == 'DENY'
    assert policy['source']['indices'] == ['wazuh-alerts-gateway-dev-v1']
    assert policy['source']['index_uuids'] is None
    assert policy['source']['aliases'] is False
    assert policy['source']['wildcards'] is False
    assert policy['tls']['verify'] is True
    assert policy['tls']['ca_sha256'] is None
    assert set(policy['environment_names']) == {
        'AI_SOC_GATEWAY_DEV_DATABASE_URL', 'AI_SOC_GATEWAY_DEV_WAZUH_PASSWORD',
        'AI_SOC_GATEWAY_DEV_API_KEY'}
    limits = manifest.ResourceCeilings.model_validate(policy['ceilings'])
    assert limits.max_fetched_hits == 2 and limits.max_retries == 0
    assert policy['query']['size'] == 1 and policy['query']['max_pages'] == 1
    assert policy['query']['require_timestamp'] is True


@pytest.mark.parametrize('contract', ['DevelopmentManifest', 'VerificationAuthority', 'IndependentVerification'])
def test_receipt_fields_track_existing_contract_without_becoming_authority(contract):
    templates = load('evidence-templates.review.json')
    assert templates['executable'] is False
    assert templates['status'] == 'TEMPLATE_NOT_EVIDENCE'
    fields = templates['pre2_contract_fields'][contract]
    assert set(fields) == set(getattr(manifest, contract).model_fields)
    assert all(value is None for value in fields.values())
    with pytest.raises(ValidationError):
        getattr(manifest, contract).model_validate(fields)


def test_all_required_receipts_are_unverified_and_have_review_criteria():
    templates = load('evidence-templates.review.json')
    assert set(templates['receipts']) == {
        'ownership', 'active_state', 'source', 'privileges', 'credential_isolation',
        'tls', 'egress', 'budgets', 'issuer_verifier'}
    common = templates['common_fields']
    assert common['status'] == 'UNVERIFIED'
    assert common['observed_at'] is None and common['valid_until'] is None
    assert common['issuer_id'] is None and common['verifier_id'] is None
    for receipt in templates['receipts'].values():
        assert receipt['required_fields'] and receipt['review_criteria']
    assert templates['validity']['verification_max_seconds'] == 300
    assert templates['validity']['manifest_max_seconds'] == 3600
