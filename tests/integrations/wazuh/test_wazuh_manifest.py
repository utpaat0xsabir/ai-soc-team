"""PRE2 uses synthetic receipts from an explicitly separate trusted boundary."""

from datetime import datetime, timedelta, timezone
import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.integrations.wazuh import manifest as policy
from app.gateway.disclosure_policy import Destination
from app.gateway.contracts import ToolRequest, TrustedContext


NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)


def setup():
    destination = Destination(provider_id='synthetic-indexer', provider_version='1.0',
        account_id='development', destination_id='approved-development', audience='TENANT_LOCAL')
    bounds = policy.QueryBounds(window_start=NOW - timedelta(minutes=15),
        window_end=NOW - timedelta(minutes=10), size=1, max_pages=1, require_timestamp=True)
    limits = policy.ResourceCeilings(max_input_bytes=16384, max_pages=1, max_fetched_hits=2,
        max_result_bytes=2048, max_wire_bytes=65536, request_timeout_ms=2000,
        overall_deadline_ms=10000, max_requests=3, max_retries=0)
    manifest = policy.DevelopmentManifest(manifest_id=UUID(int=10), tenant_id=UUID(int=1),
        principal_id=UUID(int=2), integration_id=UUID(int=3), active=True,
        indices=(policy.SourceIndex(name='wazuh-alerts-synthetic-2026.11.11',
            index_uuid='synthetic-index-uuid', kind='CONCRETE'),),
        organization=policy.OrganizationScope(mode='SHARED', field='organization.id',
            value='synthetic-org', mapping_type='keyword', server_enforced=True),
        destination=destination, credential_reference='env:SYNTHETIC_DEV_PASSWORD',
        ca_reference='ca-ref:synthetic-root', ca_sha256='a' * 64,
        issuer_id='synthetic-issuer', provenance_reference='receipt:synthetic-manifest',
        issued_at=NOW - timedelta(minutes=10), expires_at=NOW + timedelta(minutes=30),
        approved_query=bounds, ceilings=limits)
    authority = policy.VerificationAuthority(issuer_id='synthetic-issuer', verifier_id='independent-verifier',
        destination=destination, credential_reference=manifest.credential_reference, ca_sha256=manifest.ca_sha256)
    verification = policy.IndependentVerification(issuer_id=manifest.issuer_id,
        verifier_id=authority.verifier_id, manifest_sha256=policy.manifest_digest(manifest),
        evidence_reference='receipt:independent-review', verified_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=3), issuer_validated=True, integrity_validated=True,
        source_authority_validated=True, destination_validated=True,
        credential_reference_validated=True, ca_provenance_validated=True)
    request = ToolRequest(request_id=UUID(int=4), tenant_id=manifest.tenant_id,
        principal_id=manifest.principal_id, capability_id='wazuh.alerts.search', capability_version='1.0',
        operation='query', target=str(manifest.integration_id), parameters=policy.query_parameters(manifest))
    return dict(context=TrustedContext(tenant_id=manifest.tenant_id, principal_id=manifest.principal_id),
        manifest=manifest, request=request, authority=authority, verification=verification, at=NOW)


def refresh_receipt(args):
    args['verification'] = args['verification'].model_copy(update={
        'manifest_sha256': policy.manifest_digest(args['manifest'])})


def test_valid_manifest_compiles_strict_non_executable_query():
    args = setup(); before = repr(args); result = policy.assess_manifest(**args)
    assert result.status == 'PASS' and result.executable is False
    assert result.operational_clearance == 'UNVERIFIED' and result.missing_evidence == ()
    plan = result.plan
    assert plan.executable is False and plan.fetch_size == 2 and plan.manifest.ceilings.max_retries == 0
    assert plan.manifest.indices == args['manifest'].indices
    assert '*' not in plan.pit_open_path and plan.search_path == '/_search'
    filters = json.loads(plan.source_filter_json)['bool']['filter']
    assert {'term': {'organization.id': 'synthetic-org'}} in filters
    assert {'exists': {'field': 'timestamp'}} in filters
    assert any('range' in item and 'gte' in item['range']['timestamp'] and 'lt' in item['range']['timestamp'] for item in filters)
    assert result == policy.assess_manifest(**args) and repr(args) == before


@pytest.mark.parametrize('kind', ['missing', 'issuer', 'self_verified', 'integrity', 'source_authority',
    'wrong_hash', 'wrong_issuer', 'wrong_verifier', 'stale', 'future', 'expired', 'missing_root'])
def test_independent_evidence_is_mandatory(kind):
    args = setup(); verification = args['verification']
    if kind == 'missing': args['verification'] = None
    elif kind == 'issuer': verification = verification.model_copy(update={'issuer_validated': None})
    elif kind == 'self_verified': verification = verification.model_copy(update={'verifier_id': verification.issuer_id})
    elif kind == 'integrity': verification = verification.model_copy(update={'integrity_validated': False})
    elif kind == 'source_authority': verification = verification.model_copy(update={'source_authority_validated': None})
    elif kind == 'wrong_hash': verification = verification.model_copy(update={'manifest_sha256': '0' * 64})
    elif kind == 'wrong_issuer': verification = verification.model_copy(update={'issuer_id': 'other'})
    elif kind == 'wrong_verifier': verification = verification.model_copy(update={'verifier_id': 'other'})
    elif kind == 'stale': verification = verification.model_copy(update={'verified_at': NOW - timedelta(minutes=6)})
    elif kind == 'future': verification = verification.model_copy(update={'verified_at': NOW + timedelta(seconds=1)})
    elif kind == 'expired': verification = verification.model_copy(update={'valid_until': NOW})
    elif kind == 'missing_root': args['authority'] = None
    if kind not in ('missing', 'missing_root'): args['verification'] = verification
    result = policy.assess_manifest(**args)
    assert result.status == 'BLOCKED' and result.plan is None and result.missing_evidence


@pytest.mark.parametrize('kind', ['expired', 'stale', 'future', 'tenant', 'principal', 'integration',
    'inactive', 'wildcard', 'alias', 'conflicting_uuid', 'missing_organization', 'agent_ownership',
    'not_enforced', 'no_timestamp', 'unbounded_window', 'parameters', 'cross_tenant_pagination',
    'credential_value', 'ca_reference', 'ca_identity', 'destination', 'wire_budget', 'result_budget',
    'page_expansion', 'hit_expansion', 'timeout', 'deadline', 'retries', 'raw_dsl', 'schema_version',
    'capability_version', 'self_assertion'])
def test_invalid_scope_and_budgets_never_compile(kind):
    args = setup(); manifest = args['manifest']; request = args['request']
    if kind == 'expired': manifest = manifest.model_copy(update={'expires_at': NOW})
    elif kind == 'stale': manifest = manifest.model_copy(update={'issued_at': NOW - timedelta(hours=2)})
    elif kind == 'future': manifest = manifest.model_copy(update={'issued_at': NOW + timedelta(seconds=1)})
    elif kind in ('tenant', 'principal', 'integration'):
        if kind == 'integration': request = request.model_copy(update={'target': str(UUID(int=99))})
        else: request = request.model_copy(update={kind + '_id': UUID(int=99)})
    elif kind == 'inactive': manifest = manifest.model_copy(update={'active': False})
    elif kind == 'wildcard': manifest = manifest.model_copy(update={'indices': (manifest.indices[0].model_copy(update={'name': 'wazuh-alerts-*'}),)})
    elif kind == 'alias': manifest = manifest.model_copy(update={'indices': (manifest.indices[0].model_copy(update={'kind': 'ALIAS'}),)})
    elif kind == 'conflicting_uuid': manifest = manifest.model_copy(update={'indices': manifest.indices + (manifest.indices[0].model_copy(update={'index_uuid': 'different'}),)})
    elif kind in ('missing_organization', 'agent_ownership', 'not_enforced'):
        changes = {'missing_organization': {'value': None}, 'agent_ownership': {'field': 'agent.id'}, 'not_enforced': {'server_enforced': False}}[kind]
        manifest = manifest.model_copy(update={'organization': manifest.organization.model_copy(update=changes)})
    elif kind in ('no_timestamp', 'unbounded_window', 'page_expansion'):
        changes = {'no_timestamp': {'require_timestamp': False}, 'unbounded_window': {'window_start': NOW - timedelta(days=365)}, 'page_expansion': {'max_pages': 2}}[kind]
        manifest = manifest.model_copy(update={'approved_query': manifest.approved_query.model_copy(update=changes)})
    elif kind == 'parameters': request = request.model_copy(update={'parameters': (('size', '2'),)})
    elif kind == 'cross_tenant_pagination':
        foreign = manifest.model_copy(update={'tenant_id': UUID(int=99)})
        request = request.model_copy(update={'parameters': policy.query_parameters(foreign)})
    elif kind == 'credential_value': manifest = manifest.model_copy(update={'credential_reference': 'SECRET-CANARY'})
    elif kind == 'ca_reference': manifest = manifest.model_copy(update={'ca_reference': ''})
    elif kind == 'ca_identity': manifest = manifest.model_copy(update={'ca_sha256': 'b' * 64})
    elif kind == 'destination': manifest = manifest.model_copy(update={'destination': manifest.destination.model_copy(update={'destination_id': 'unauthorized'})})
    elif kind in ('wire_budget', 'result_budget', 'hit_expansion', 'timeout', 'deadline', 'retries'):
        changes = {'wire_budget': {'max_wire_bytes': 65537}, 'result_budget': {'max_result_bytes': 2049},
            'hit_expansion': {'max_fetched_hits': 1}, 'timeout': {'request_timeout_ms': 5001},
            'deadline': {'overall_deadline_ms': 1}, 'retries': {'max_retries': 1}}[kind]
        manifest = manifest.model_copy(update={'ceilings': manifest.ceilings.model_copy(update=changes)})
    elif kind == 'raw_dsl': request.__dict__['query'] = {'match_all': {}}
    elif kind == 'schema_version': manifest = manifest.model_copy(update={'schema_version': '2.0'})
    elif kind == 'capability_version': request = request.model_copy(update={'capability_version': '2.0'})
    elif kind == 'self_assertion': manifest.__dict__['source_authority_validated'] = True
    args.update(manifest=manifest, request=request)
    result = policy.assess_manifest(**args)
    assert result.status == 'BLOCKED' and result.plan is None and result.executable is False
    assert 'SECRET-CANARY' not in result.model_dump_json()


@pytest.mark.parametrize('check', ['ca_provenance_validated', 'credential_reference_validated', 'destination_validated'])
def test_unknown_supporting_evidence_is_not_a_pass(check):
    args = setup(); args['verification'] = args['verification'].model_copy(update={check: None})
    result = policy.assess_manifest(**args)
    assert result.status == 'UNVERIFIED' and result.plan is None and result.missing_evidence


@pytest.mark.parametrize('kind', ['alias', 'organization', 'wrong_destination', 'wrong_ca', 'wrong_credential'])
def test_verified_digest_does_not_override_scope_constraints(kind):
    args = setup(); manifest = args['manifest']
    if kind == 'alias': manifest = manifest.model_copy(update={'indices': (manifest.indices[0].model_copy(update={'kind': 'ALIAS'}),)})
    if kind == 'organization': manifest = manifest.model_copy(update={'organization': manifest.organization.model_copy(update={'server_enforced': False})})
    if kind == 'wrong_destination': manifest = manifest.model_copy(update={'destination': manifest.destination.model_copy(update={'destination_id': 'other'})})
    if kind == 'wrong_ca': manifest = manifest.model_copy(update={'ca_sha256': 'b' * 64})
    if kind == 'wrong_credential': manifest = manifest.model_copy(update={'credential_reference': 'env:OTHER_REFERENCE'})
    args['manifest'] = manifest; refresh_receipt(args)
    result = policy.assess_manifest(**args)
    assert result.status == 'BLOCKED' and result.plan is None


def test_contracts_round_trip_are_immutable_and_plan_tampering_fails():
    args = setup(); result = policy.assess_manifest(**args)
    for value in (*args.values(), result, result.plan):
        if isinstance(value, datetime): continue
        with pytest.raises(ValidationError): value.schema_version = '2.0'
        assert type(value).model_validate_json(value.model_dump_json()) == value
    assert result.model_dump_json() == policy.assess_manifest(**args).model_dump_json()
    with pytest.raises(ValidationError):
        policy.QueryPlan.model_validate({**result.plan.model_dump(), 'source_filter_json': '{"match_all":{}}'})


def test_equivalent_timezone_and_parameter_order_are_canonical():
    args = setup(); original = policy.assess_manifest(**args)
    args['at'] = NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))
    args['request'] = args['request'].model_copy(update={'parameters': tuple(reversed(args['request'].parameters))})
    assert policy.assess_manifest(**args) == original


def test_no_files_network_database_secrets_processes_or_dispatch(monkeypatch):
    import builtins
    import io
    import os
    import socket
    import subprocess
    from pathlib import Path
    from app.gateway import tool_gateway
    from app.integrations.wazuh import gateway as wazuh_gateway
    args = setup()
    def forbidden(*args, **kwargs): pytest.fail('forbidden I/O or dispatch')
    for obj, name in ((builtins, 'open'), (io, 'open'), (Path, 'open'),
        (socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
        (subprocess, 'Popen'), (os, 'system'), (os, 'getenv'),
        (tool_gateway, 'execute'), (wazuh_gateway.FakeWazuhClient, 'search_alerts')):
        monkeypatch.setattr(obj, name, forbidden)
    original_import = builtins.__import__
    def guard(name, *a, **kw):
        if name.split('.')[0] in ('sqlalchemy', 'psycopg', 'httpx', 'requests'):
            pytest.fail('forbidden dependency')
        return original_import(name, *a, **kw)
    monkeypatch.setattr(builtins, '__import__', guard)
    assert policy.assess_manifest(**args).status == 'PASS'
    assert policy.assess_manifest(**{**args, 'verification': None}).status == 'BLOCKED'


def test_dedicated_source_compiles_without_a_fabricated_organization():
    args = setup(); manifest = args['manifest']
    manifest = manifest.model_copy(update={'organization': policy.OrganizationScope(
        mode='DEDICATED', field=None, value=None, mapping_type=None, server_enforced=False)})
    args['manifest'] = manifest; refresh_receipt(args)
    args['request'] = args['request'].model_copy(update={'parameters': policy.query_parameters(manifest)})
    result = policy.assess_manifest(**args)
    assert result.status == 'PASS'
    assert not any('term' in item for item in json.loads(result.plan.source_filter_json)['bool']['filter'])


def test_compiler_sorts_concrete_indices_without_changing_scope():
    args = setup(); manifest = args['manifest']
    sources = (policy.SourceIndex(name='wazuh-alerts-z', index_uuid='uuid-z', kind='CONCRETE'),
               policy.SourceIndex(name='wazuh-alerts-a', index_uuid='uuid-a', kind='CONCRETE'))
    args['manifest'] = manifest.model_copy(update={'indices': sources})
    refresh_receipt(args)
    args['request'] = args['request'].model_copy(update={'parameters': policy.query_parameters(args['manifest'])})
    result = policy.assess_manifest(**args)
    assert result.status == 'PASS' and result.plan.pit_open_path == '/wazuh-alerts-a,wazuh-alerts-z/_search/point_in_time'


@pytest.mark.parametrize('kind', ['context_dict', 'receipt_dict', 'manifest_dict',
    'extra_signature', 'bad_time', 'support_rejected', 'source_substitution'])
def test_untrusted_inputs_and_evidence_never_gain_authority(kind):
    args = setup()
    if kind == 'context_dict': args['context'] = args['context'].model_dump()
    if kind == 'receipt_dict': args['verification'] = args['verification'].model_dump()
    if kind == 'manifest_dict': args['manifest'] = args['manifest'].model_dump()
    if kind == 'extra_signature': args['manifest'].__dict__['signature'] = 'SECRET-CANARY'
    if kind == 'bad_time': args['at'] = NOW.replace(tzinfo=None)
    if kind == 'support_rejected': args['verification'] = args['verification'].model_copy(update={'ca_provenance_validated': False})
    if kind == 'source_substitution': args['manifest'] = args['manifest'].model_copy(update={
        'indices': (args['manifest'].indices[0].model_copy(update={'index_uuid': 'recreated-index'}),)})
    result = policy.assess_manifest(**args)
    assert result.status == 'BLOCKED' and result.plan is None
    assert 'SECRET-CANARY' not in result.model_dump_json()


def test_pass_cannot_be_relabelled_or_associated_with_a_different_time():
    result = policy.assess_manifest(**setup())
    for patch in ({'evaluated_at': NOW.replace(tzinfo=None)},
                  {'evaluated_at': NOW + timedelta(seconds=1)}, {'executable': True}):
        with pytest.raises(ValidationError):
            policy.Clearance.model_validate({**result.model_dump(), **patch})


def test_even_a_rehashed_plan_cannot_widen_the_filter():
    result = policy.assess_manifest(**setup()); data = result.plan.model_dump(mode='json')
    data['source_filter_json'] = '{"match_all":{}}'
    data.pop('plan_sha256'); data['plan_sha256'] = policy._hash(data)
    with pytest.raises(ValidationError): policy.QueryPlan.model_validate_json(json.dumps(data))


def test_compiled_plan_does_not_enable_existing_gateway_dispatch():
    from app.gateway import tool_gateway
    from app.integrations.wazuh import gateway as wazuh_gateway
    args = setup(); result = policy.assess_manifest(**args); request = result.plan.request
    binding = wazuh_gateway.WazuhSourceBinding(tenant_id=request.tenant_id, principal_id=request.principal_id,
        integration_id=UUID(request.target), source_index=wazuh_gateway.SYNTHETIC_INDEX, source_scope='DEDICATED_SYNTHETIC')
    client = wazuh_gateway.FakeWazuhClient(binding=binding)
    grant = tool_gateway.ToolGrant(grant_id=UUID(int=99), **{key: getattr(request, key)
        for key in tool_gateway._Operation.model_fields}, risk='R1', read_only=True, disclosure_consent=False)
    with pytest.raises(tool_gateway.GatewayError):
        tool_gateway.execute(args['context'], request, registry=(tool_gateway.WAZUH_ALERT_SEARCH,),
            policy=(grant,), disclosure=result, wazuh_bindings=(binding,), wazuh_client=client,
            audit_sink=[], evidence_sink=[])
    assert client.calls == 0


@pytest.mark.parametrize('kind', ['inactive', 'lookahead_budget', 'deadline_budget',
    'wire_budget', 'long_window', 'future_window'])
def test_independent_verification_cannot_relax_query_or_resource_constraints(kind):
    args = setup(); manifest = args['manifest']
    if kind == 'inactive': manifest = manifest.model_copy(update={'active': False})
    if kind == 'lookahead_budget': manifest = manifest.model_copy(update={
        'approved_query': manifest.approved_query.model_copy(update={'size': 2})})
    if kind == 'deadline_budget': manifest = manifest.model_copy(update={
        'ceilings': manifest.ceilings.model_copy(update={'overall_deadline_ms': 5000})})
    if kind == 'wire_budget': manifest = manifest.model_copy(update={
        'ceilings': manifest.ceilings.model_copy(update={'max_wire_bytes': 1024})})
    if kind == 'long_window': manifest = manifest.model_copy(update={
        'approved_query': manifest.approved_query.model_copy(update={'window_start': NOW - timedelta(hours=1)})})
    if kind == 'future_window': manifest = manifest.model_copy(update={
        'approved_query': manifest.approved_query.model_copy(update={'window_start': NOW, 'window_end': NOW + timedelta(minutes=1)})})
    args['manifest'] = manifest; refresh_receipt(args)
    args['request'] = args['request'].model_copy(update={'parameters': policy.query_parameters(manifest)})
    result = policy.assess_manifest(**args)
    assert result.status == 'BLOCKED' and result.plan is None


@pytest.mark.parametrize('field', ['tenant_id', 'principal_id'])
def test_trusted_context_must_match_manifest_not_only_request(field):
    args = setup(); args['context'] = args['context'].model_copy(update={field: UUID(int=99)})
    assert policy.assess_manifest(**args).reasons == ('IDENTITY_MISMATCH',)
