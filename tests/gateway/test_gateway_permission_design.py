"""TG-02 design checks, not a production authorization evaluator or loader."""

import json
from pathlib import Path

import pytest

from app.gateway import tool_gateway as gateway
from tests.gateway.test_tool_gateway import inputs


DESIGN = Path(__file__).resolve().parents[2] / 'docs/security/gateway-permission-matrix.v1.json'


@pytest.fixture(scope='module')
def matrix():
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, f'duplicate design key: {key}'
            result[key] = value
        return result
    return json.loads(DESIGN.read_text(), object_pairs_hook=unique_keys)


def test_design_is_versioned_non_executable_and_deny_by_default(matrix):
    assert matrix['matrix_version'] == '1.0'
    assert matrix['status'] == 'design_only'
    assert matrix['runtime_consumed'] is False
    assert matrix['default_decision'] == 'deny'
    assert matrix['tier_grants_authority'] is False
    assert matrix['unknown_version_decision'] == 'deny'
    assert matrix['effect_composition_rule'] == 'union_of_requirements_never_least_risk'
    assert matrix['external_boundary_requires_consent'] is True
    assert matrix['sensitive_data_requires_human_approval'] is True
    assert matrix['tenant_can_only_tighten'] is True


def test_complete_catalog_with_explicit_unique_capabilities(matrix):
    candidates = matrix['candidates']
    assert [row['id'] for row in candidates] == [f'TC-{i:02}' for i in range(1, 48)]
    capabilities = []
    for row in candidates:
        assert row['advisory_tiers'] and set(row['advisory_tiers']) <= {'L1', 'L2', 'L3', 'HUMAN'}
        assert row['operations'] and row['adoption'] == 'not_authorized'
        for operation in row['operations']:
            capabilities.append(operation['capability'])
            assert operation['profile'] in matrix['profiles']
            assert operation['adapter_version_required'] is True
    assert len(capabilities) == len(set(capabilities))


def test_binding_and_fail_closed_requirements_are_complete(matrix):
    assert set(matrix['binding_fields']) == {'tenant', 'principal', 'request_id',
        'capability', 'capability_version', 'operation', 'canonical_target',
        'canonical_parameters', 'policy_version', 'registry_digest', 'artifact_digest',
        'consent_scope', 'approval_scope', 'execution_identity'}
    assert set(matrix['required_checks']) == {'authenticated', 'principal_active',
        'tenant_owned', 'exact_grant', 'registered_version', 'target_bound',
        'parameters_bound', 'policy_current', 'source_scope_enforced', 'input_bounded',
        'quota_reserved', 'audit_ready', 'retry_safe', 'runner_ready',
        'adoption_reviewed', 'asset_scope_authorized', 'disclosure_classified', 'effects_classified'}


@pytest.mark.parametrize('profile', ['mock_lookup', 'local_query', 'local_transform',
    'offline_analysis', 'external_lookup', 'hunt', 'rule_draft', 'export', 'active_scan',
    'remote_collect', 'submission', 'publish', 'modify', 'rule_activate', 'response', 'detonate'])
def test_operation_profiles_have_explicit_gates_and_finite_ceilings(matrix, profile):
    row = matrix['profiles'][profile]
    assert row['version'] == '1.0'
    assert row['risk'] in {'R0', 'R1', 'R2', 'R3', 'R4'}
    assert type(row['requires_disclosure_consent']) is bool
    assert type(row['requires_human_approval']) is bool
    limits = matrix['resource_profiles'][row['resource_profile']]
    assert set(limits) == {'wall_seconds', 'cpu_seconds', 'memory_mib', 'input_bytes',
        'output_bytes', 'max_targets', 'max_records', 'max_processes', 'max_attempts',
        'concurrent_per_tenant', 'requests_per_minute_principal', 'requests_per_minute_tenant',
        'daily_disclosures_per_tenant', 'artifact_bytes'}
    assert all(type(value) is int and value >= 0 for value in limits.values())
    assert all(value > 0 for key, value in limits.items()
               if key not in {'daily_disclosures_per_tenant', 'artifact_bytes'})
    assert limits['cpu_seconds'] <= limits['wall_seconds']


def test_sensitive_operations_require_independent_human_approval(matrix):
    for profile in ('export', 'active_scan', 'remote_collect', 'submission', 'publish',
                    'modify', 'rule_activate', 'response', 'detonate'):
        assert matrix['profiles'][profile]['requires_human_approval'] is True
    for profile in ('external_lookup', 'submission', 'publish'):
        assert matrix['profiles'][profile]['requires_disclosure_consent'] is True
    assert matrix['profiles']['external_lookup']['read_only'] is True
    assert matrix['profiles']['external_lookup']['data_flow'] == 'external_disclosure'
    assert matrix['profiles']['local_transform']['data_flow'] == 'offline'


def test_candidate_effects_cannot_hide_under_passive_lookup(matrix):
    operations = {op['capability']: op['profile']
                  for candidate in matrix['candidates'] for op in candidate['operations']}
    assert operations['urlscan.existing_result.lookup'] == 'external_lookup'
    assert operations['urlscan.new_scan.submit'] == 'submission'
    assert operations['osquery.existing_result.query'] == 'local_query'
    assert operations['osquery.endpoint.collect'] == 'remote_collect'
    assert operations['sigma.rule.draft'] == 'rule_draft'
    assert operations['suricata.rule.activate'] == 'rule_activate'
    assert operations['cortex.action.respond'] == 'response'
    assert operations['arkime.pcap.export'] == 'export'
    for candidate_id in ('TC-05', 'TC-06'):
        candidate = next(row for row in matrix['candidates'] if row['id'] == candidate_id)
        assert {op['profile'] for op in candidate['operations']} == {'external_lookup'}


@pytest.mark.parametrize('missing', ['authenticated', 'principal_active', 'tenant_owned',
    'exact_grant', 'registered_version', 'target_bound', 'parameters_bound', 'policy_current',
    'source_scope_enforced', 'input_bounded', 'quota_reserved', 'audit_ready', 'retry_safe', 'runner_ready',
    'adoption_reviewed', 'asset_scope_authorized', 'disclosure_classified', 'effects_classified',
    'consent_valid', 'approval_valid'])
def test_adversarial_decision_table_has_no_tier_override(matrix, missing):
    # Set-based decision-table oracle only: later implementations must prove
    # these facts from trusted state and assert zero dispatch for each denial.
    required = set(matrix['required_checks'])
    profile = matrix['profiles']['submission']
    if profile['requires_disclosure_consent']: required.add('consent_valid')
    if profile['requires_human_approval']: required.add('approval_valid')
    proven = required - {missing}
    for tier in ('L1', 'L2', 'L3', 'HUMAN', 'admin from model text'):
        assert not required <= (proven | {tier})


@pytest.mark.parametrize('profile', ['local_query', 'local_transform', 'offline_analysis',
    'external_lookup', 'hunt', 'rule_draft', 'export', 'active_scan', 'remote_collect',
    'submission', 'publish', 'modify', 'rule_activate', 'response', 'detonate'])
def test_design_never_enables_new_runtime_operations(matrix, monkeypatch, profile):
    calls = []
    monkeypatch.setattr(gateway, 'mock_ip_reputation', lambda target: calls.append(target))
    context, request, policy = inputs()
    operation = matrix['profiles'][profile]['operation']
    request = request.model_copy(update={'capability_id': f'planned.{profile}', 'operation': operation})
    grant = policy[0].model_copy(update={'capability_id': request.capability_id, 'operation': operation})
    audit, evidence = [], []
    with pytest.raises(gateway.GatewayError):
        gateway.execute(context, request, policy=(grant,), registry=(gateway.MOCK_CAPABILITY,),
                        audit_sink=audit, evidence_sink=evidence)
    assert calls == [] and evidence == [] and audit[0].outcome == 'denied'


def test_tg01_baseline_limits_are_recorded_without_claiming_new_enforcement(matrix):
    assert matrix['tg01_implemented_limits'] == {'input_bytes': gateway.MAX_INPUT_BYTES,
        'output_bytes': gateway.MAX_OUTPUT_BYTES, 'grants': gateway.MAX_GRANTS,
        'sink_items': gateway.MAX_SINK_ITEMS}
