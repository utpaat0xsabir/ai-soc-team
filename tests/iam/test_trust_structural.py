"""Offline structural fixtures: no identity, signature or authority is verified."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.iam.trust import contracts as trust
from app.iam.trust.canonical import canonical_bytes, parse_canonical
from app.iam.trust.denials import StructuralError
from app.iam.trust.validation import validate_structure

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def binding(**changes):
    data = dict(trust_domain_id=UUID(int=1), deployment_id=UUID(int=2), tenant_id=UUID(int=3),
                deployment_type='SELF_HOSTED_ENTERPRISE', customer_authority_id=UUID(int=4),
                provider_identity_id=None)
    return trust.TrustBinding(**dict(data, **changes))


def reference(value=10, tenant=3):
    return dict(tenant_id=UUID(int=tenant), reference_id=UUID(int=value))


def custodian(value):
    return dict(custodian_id=f'customer-{value}', kind='CUSTOMER',
                anchor=trust.TrustAnchorReference(anchor_id=f'anchor-{value}',
                    public_material_digest=str(value) * 64), delegation_ref=None)


def root_data():
    return dict(schema_version='trust02.1', binding=binding(), root_policy_id='customer-root',
                root_policy_version=1, required_quorum=2,
                custodians=tuple(trust.RootCustodian(**custodian(i)) for i in (1, 2, 3)))


def scope():
    return dict(tenant_id=UUID(int=3), scope_id=UUID(int=20), actions=('evidence.metadata.read',),
                resource_types=('evidence',), classifications=('RESTRICTED',),
                team_scope=dict(tenant_id=UUID(int=3), mode='ALL_TENANT_TEAMS', team_refs=(), authorization_ref=reference(21)))


def envelope_data():
    return dict(schema_version='trust02.1', binding=binding(), payload_id=UUID(int=30),
                issuer_ref=reference(11), subject_ref=reference(12), source_ref=reference(13),
                operation='issue-authority', authority_scope=scope(), authority_revision=1,
                provenance_ref=reference(14), root_policy_id='customer-root', root_policy_version=1,
                issued_at=NOW, expires_at=NOW + timedelta(minutes=1))


def recovery_data():
    return dict(schema_version='trust02.1', binding=binding(), operation_id=UUID(int=40),
                operation='recover', root_policy_id='customer-root', root_policy_version=1,
                proposed_state_digest='a' * 64, checkpoint_ref=reference(41),
                recovery_journal_ref=reference(42), issued_at=NOW,
                expires_at=NOW + timedelta(minutes=1))


def check(kind, data, **changes):
    args = dict(expected_binding=binding(), issuer_ids=(UUID(int=11),))
    return validate_structure(kind, data, **dict(args, **changes))


def denied(kind, data, reason, **changes):
    for _ in range(2):
        with pytest.raises(StructuralError) as error:
            check(kind, data, **changes)
        assert error.value.code == reason
        assert str(error.value) == reason
        assert 'secret-canary' not in str(error.value)


@pytest.mark.parametrize('kind,factory', [(trust.RootTrustPolicy, root_data),
    (trust.ProvenanceEnvelope, envelope_data), (trust.RecoveryProposal, recovery_data)])
def test_immutable_structural_only_roundtrip(kind, factory):
    result = check(kind, factory())
    assert result.status == 'STRUCTURAL_ONLY'
    assert result.record.executable is False
    assert not hasattr(result, 'trusted') and not hasattr(result, 'authorized')
    with pytest.raises((ValidationError, AttributeError)):
        result.record.schema_version = 'changed'
    with pytest.raises(AttributeError):
        result.status = 'ALLOW'
    payload = canonical_bytes(result.record)
    assert parse_canonical(kind, payload) == result.record
    assert canonical_bytes(parse_canonical(kind, payload)) == payload


@pytest.mark.parametrize('kind,factory,field', [(trust.RootTrustPolicy, root_data, 'root_policy_id'),
    (trust.ProvenanceEnvelope, envelope_data, 'issuer_ref'),
    (trust.RecoveryProposal, recovery_data, 'checkpoint_ref')])
def test_missing_required_field(kind, factory, field):
    data = factory(); del data[field]
    denied(kind, data, 'MISSING_REQUIRED_FIELD')


@pytest.mark.parametrize('field,value,reason', [
    ('schema_version', '1.0', 'UNSUPPORTED_SCHEMA_VERSION'),
    ('root_policy_id', 'secret-canary /', 'INVALID_IDENTIFIER'),
    ('root_policy_version', 0, 'INVALID_ROOT_POLICY_VERSION'),
    ('root_policy_version', True, 'INVALID_ROOT_POLICY_VERSION'),
    ('root_policy_version', '1', 'INVALID_ROOT_POLICY_VERSION'),
    ('required_quorum', 1, 'INVALID_QUORUM_CONFIGURATION'),
    ('required_quorum', 3, 'INVALID_QUORUM_CONFIGURATION'),
    ('required_quorum', True, 'INVALID_QUORUM_CONFIGURATION'),
    ('required_quorum', 2.0, 'INVALID_QUORUM_CONFIGURATION')])
def test_invalid_root_values(field, value, reason):
    data = root_data(); data[field] = value
    denied(trust.RootTrustPolicy, data, reason)


@pytest.mark.parametrize('field,value,reason', [
    ('deployment_type', 'VENDOR_ROOT', 'INVALID_DEPLOYMENT_TYPE'),
    ('deployment_id', None, 'INVALID_IDENTIFIER'),
    ('tenant_id', UUID(int=0), 'INVALID_TENANT_BINDING'),
    ('tenant_id', 'not-a-tenant', 'INVALID_TENANT_BINDING'),
    ('trust_domain_id', None, 'INVALID_IDENTIFIER'),
    ('provider_identity_id', UUID(int=4), 'INVALID_DEPLOYMENT_IDENTITY')])
def test_invalid_binding(field, value, reason):
    data = root_data(); data['binding'] = dict(binding().model_dump(), **{field:value})
    denied(trust.RootTrustPolicy, data, reason)


@pytest.mark.parametrize('field,value,reason', [
    ('tenant_id', UUID(int=99), 'INVALID_TENANT_BINDING'),
    ('deployment_id', UUID(int=99), 'INVALID_DEPLOYMENT_BINDING'),
    ('trust_domain_id', UUID(int=99), 'INVALID_DEPLOYMENT_BINDING'),
    ('customer_authority_id', UUID(int=99), 'INVALID_DEPLOYMENT_BINDING')])
def test_context_binding_mismatch(field, value, reason):
    data = root_data(); data['binding'] = binding(**{field:value})
    denied(trust.RootTrustPolicy, data, reason)


@pytest.mark.parametrize('change', ['id', 'anchor_id', 'anchor_digest', 'count'])
def test_distinct_custodians_and_anchors(change):
    data = root_data(); cs = [c.model_dump() for c in data['custodians']]
    if change == 'count': cs.pop()
    elif change == 'id': cs[1]['custodian_id'] = cs[0]['custodian_id']
    elif change == 'anchor_id': cs[1]['anchor']['anchor_id'] = cs[0]['anchor']['anchor_id']
    else: cs[1]['anchor']['public_material_digest'] = cs[0]['anchor']['public_material_digest']
    data['custodians'] = tuple(cs)
    denied(trust.RootTrustPolicy, data,
           'INVALID_QUORUM_CONFIGURATION' if change == 'count' else 'DUPLICATE_CUSTODIAN')


def test_order_does_not_change_root_payload():
    data = root_data(); a = trust.RootTrustPolicy(**data)
    data['custodians'] = tuple(reversed(data['custodians']))
    assert canonical_bytes(a) == canonical_bytes(trust.RootTrustPolicy(**data))


@pytest.mark.parametrize('field,value,reason', [
    ('checkpoint_ref', None, 'INVALID_CHECKPOINT_REFERENCE'),
    ('checkpoint_ref', reference(41, 99), 'INVALID_TENANT_BINDING'),
    ('recovery_journal_ref', None, 'INVALID_RECOVERY_JOURNAL_REFERENCE'),
    ('recovery_journal_ref', 'secret-canary', 'INVALID_RECOVERY_JOURNAL_REFERENCE'),
    ('operation', 'execute', 'UNSUPPORTED_OPERATION')])
def test_recovery_references(field, value, reason):
    data = recovery_data(); data[field] = value
    denied(trust.RecoveryProposal, data, reason)


@pytest.mark.parametrize('field,value,reason', [
    ('issuer_ref', reference(99), 'INVALID_ISSUER_REFERENCE'),
    ('issuer_ref', reference(11, 99), 'INVALID_TENANT_BINDING'),
    ('issuer_ref', None, 'INVALID_ISSUER_REFERENCE'),
    ('subject_ref', reference(12, 99), 'INVALID_TENANT_BINDING'),
    ('operation', 'roles.assign', 'UNSUPPORTED_OPERATION'),
    ('authority_scope', None, 'INVALID_AUTHORITY_SCOPE'),
    ('authority_revision', True, 'INVALID_AUTHORITY_REVISION'),
    ('authority_revision', -1, 'INVALID_AUTHORITY_REVISION'),
    ('authority_revision', 1.0, 'INVALID_AUTHORITY_REVISION'),
    ('issued_at', datetime(2026, 11, 15), 'INVALID_TIMESTAMP'),
    ('issued_at', '2026-11-15T00:00:00Z', 'INVALID_TIMESTAMP'),
    ('issued_at', 1234, 'INVALID_TIMESTAMP'),
    ('expires_at', NOW, 'INVALID_TIMESTAMP'),
    ('trusted', True, 'MALFORMED_PROVENANCE_ENVELOPE')])
def test_invalid_envelope(field, value, reason):
    data = envelope_data(); data[field] = value
    denied(trust.ProvenanceEnvelope, data, reason)


@pytest.mark.parametrize('change', ['wildcard', 'duplicate', 'tenant', 'metadata', 'numeric_flag'])
def test_scope_uses_existing_iam_validation(change):
    data = envelope_data(); s = data['authority_scope']
    reason = 'INVALID_AUTHORITY_SCOPE'
    if change == 'wildcard': s['actions'] = ('*',)
    if change == 'duplicate': s['actions'] = ('evidence.metadata.read',) * 2
    if change == 'tenant': s['tenant_id'] = UUID(int=99); reason = 'INVALID_TENANT_BINDING'
    if change == 'metadata': s['provider_admin'] = True
    if change == 'numeric_flag': s['executable'] = 0
    denied(trust.ProvenanceEnvelope, data, reason)


@pytest.mark.parametrize('change', ['whitespace', 'duplicate', 'unicode_alias', 'numeric', 'bad_json', 'version', 'oversize'])
def test_invalid_canonical_payload(change):
    raw = canonical_bytes(trust.ProvenanceEnvelope(**envelope_data()))
    reason = 'NONCANONICAL_REPRESENTATION'
    if change == 'whitespace': raw += b'\n'
    if change == 'duplicate': raw = raw.replace(b'{', b'{"schema_version":"trust02.1",', 1)
    if change == 'unicode_alias': raw = raw.replace(b'"issuer_ref"', b'"\\u0069ssuer_ref"')
    if change == 'numeric': raw = raw.replace(b'"authority_revision":1', b'"authority_revision":1.0')
    if change == 'bad_json': raw = b'{'
    if change == 'version': raw = raw.replace(b'trust02.1', b'trust02.9')
    if change == 'oversize': raw = b' ' * 65537
    if change == 'version': reason = 'UNSUPPORTED_SCHEMA_VERSION'
    if change == 'numeric': reason = 'INVALID_AUTHORITY_REVISION'
    with pytest.raises(StructuralError) as error:
        parse_canonical(trust.ProvenanceEnvelope, raw)
    assert error.value.code == reason


def test_timestamp_profile_normalizes_aware_time_only():
    data = envelope_data()
    data['issued_at'] = NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))
    raw = canonical_bytes(trust.ProvenanceEnvelope(**data))
    assert b'2026-11-15T00:00:00.000000+00:00' in raw
    assert raw == canonical_bytes(trust.ProvenanceEnvelope(**envelope_data()))


def test_provider_recovery_requires_explicit_structural_delegation():
    data = root_data()
    data['binding'] = binding(deployment_type='MANAGED_SAAS', provider_identity_id=UUID(int=90))
    cs = [c.model_dump() for c in data['custodians']]
    cs[2]['kind'] = 'PROVIDER_RECOVERY'; data['custodians'] = tuple(cs)
    denied(trust.RootTrustPolicy, data, 'INVALID_PROVIDER_DELEGATION', expected_binding=data['binding'])
    cs[2]['delegation_ref'] = reference(70)
    checked = check(trust.RootTrustPolicy, data, expected_binding=data['binding'])
    assert checked.status == 'STRUCTURAL_ONLY'
    assert not hasattr(checked, 'authorized')


def test_customer_only_self_hosted_root_has_no_vendor_dependency():
    assert check(trust.RootTrustPolicy, root_data()).record.binding.provider_identity_id is None


def test_model_copy_cannot_bypass_validation():
    model = trust.ProvenanceEnvelope(**envelope_data()).model_copy(update={'authority_revision': True})
    denied(trust.ProvenanceEnvelope, model, 'INVALID_AUTHORITY_REVISION')
    with pytest.raises(StructuralError): canonical_bytes(model)


def test_package_has_no_operational_importers_or_io():
    package = Path('services/api/app/iam/trust')
    for path in Path('services/api/app').rglob('*.py'):
        if package not in path.parents:
            assert 'app.iam.trust' not in path.read_text()
    script = '''
import socket, subprocess
from unittest.mock import patch
with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(subprocess, 'Popen', side_effect=AssertionError('process')):
    import app.iam.trust
    from app.iam.trust import contracts, canonical, validation, denials
    import sys
    assert not any(n in sys.modules for n in ('app.db','app.iam.auth','app.iam.admission','app.iam.authority_provider','app.iam.postgres_authority','cryptography','nacl'))
'''
    import os
    environment = dict(os.environ, PYTHONPATH='services/api', PYTHONDONTWRITEBYTECODE='1')
    completed = subprocess.run([sys.executable, '-c', script], env=environment, capture_output=True)
    assert completed.returncode == 0, 'isolated import guard failed'


@pytest.mark.parametrize('change', ['extra', 'nested_extra', 'private_key', 'zero_flag'])
def test_copied_metadata_and_private_material_are_not_silently_dropped(change):
    data = root_data()
    if change == 'extra':
        data = trust.RootTrustPolicy(**data).model_copy(update={'trusted': True})
    elif change == 'nested_extra':
        data['binding'] = binding().model_copy(update={'provider_admin': True})
    elif change == 'private_key':
        cs = [c.model_dump() for c in data['custodians']]
        cs[0]['anchor']['private_key'] = 'secret-canary'; data['custodians'] = tuple(cs)
    else: data['executable'] = 0
    denied(trust.RootTrustPolicy, data, 'MALFORMED_PROVENANCE_ENVELOPE')


@pytest.mark.parametrize('change', ['missing_provider', 'equal_provider', 'zero_provider',
                                     'provider_on_self_hosted', 'all_providers', 'wrong_delegation_tenant'])
def test_provider_cannot_become_customer_root_by_default(change):
    data = root_data()
    b = binding().model_dump()
    if change == 'provider_on_self_hosted': b['provider_identity_id'] = UUID(int=90)
    else:
        b['deployment_type'] = 'MANAGED_SAAS'
        b['provider_identity_id'] = {'missing_provider':None, 'equal_provider':UUID(int=4),
                                    'zero_provider':UUID(int=0)}.get(change, UUID(int=90))
    data['binding'] = b
    reason = 'INVALID_DEPLOYMENT_IDENTITY'
    if change in ('all_providers', 'wrong_delegation_tenant'):
        cs = [c.model_dump() for c in data['custodians']]
        for c in cs if change == 'all_providers' else cs[:1]:
            c.update(kind='PROVIDER_RECOVERY', delegation_ref=reference(70, 99 if change == 'wrong_delegation_tenant' else 3))
        data['custodians'] = tuple(cs)
        reason = 'INVALID_PROVIDER_DELEGATION' if change == 'all_providers' else 'INVALID_TENANT_BINDING'
    # Valid external expected context is separate from the candidate data.
    denied(trust.RootTrustPolicy, data, reason)


@pytest.mark.parametrize('issuers', [(), (UUID(int=90),), (UUID(int=11),) * 2, ['not-a-uuid'], (True,)])
def test_structural_issuer_registry_is_explicit_and_strict(issuers):
    denied(trust.ProvenanceEnvelope, envelope_data(), 'INVALID_ISSUER_REFERENCE', issuer_ids=issuers)


def test_multifault_order_does_not_depend_on_dictionary_order():
    data = envelope_data(); data.update(operation='secret-canary', authority_revision=True)
    for ordered in (data, dict(reversed(tuple(data.items())))):
        denied(trust.ProvenanceEnvelope, ordered, 'INVALID_AUTHORITY_REVISION')


@pytest.mark.parametrize('kind,factory', [(trust.RootTrustPolicy, root_data),
                                         (trust.ProvenanceEnvelope, envelope_data)])
def test_nested_and_direct_mutation_rejected(kind, factory):
    result = check(kind, factory())
    with pytest.raises(ValidationError): result.record.binding.tenant_id = UUID(int=99)
    if kind is trust.RootTrustPolicy:
        with pytest.raises(ValidationError): result.record.custodians[0].anchor.anchor_id = 'changed'
    else:
        with pytest.raises(ValidationError): result.record.authority_scope.actions = ('roles.assign',)
    with pytest.raises(TypeError): type(result)(result.record, status='ALLOW')


@pytest.mark.parametrize('transform', [
    lambda raw:raw.replace(b'"authority_revision":1', b'"authority_revision":1e0'),
    lambda raw:raw.replace(b'"issued_at":"2026-11-15T00:00:00.000000+00:00"', b'"issued_at":123'),
    lambda raw:raw.replace(b'"issued_at":"2026-11-15T00:00:00.000000+00:00"', b'"issued_at":"2026-11-15T00:00:00"'),
    lambda raw:raw.replace(b'"authority_revision":1', b'"authority_revision":NaN'),
    lambda raw:b'[' * 100 + b'0' + b']' * 100,
])
def test_numeric_and_time_aliases_never_canonicalize_into_validity(transform):
    raw = canonical_bytes(trust.ProvenanceEnvelope(**envelope_data()))
    with pytest.raises(StructuralError): parse_canonical(trust.ProvenanceEnvelope, transform(raw))


def test_bootstrap_reference_option_is_explicit_not_a_default():
    data = recovery_data(); data.update(operation='bootstrap', checkpoint_ref=None, recovery_journal_ref=None)
    assert check(trust.RecoveryProposal, data).status == 'STRUCTURAL_ONLY'
    del data['checkpoint_ref']
    denied(trust.RecoveryProposal, data, 'MISSING_REQUIRED_FIELD')


@pytest.mark.parametrize('change', ['key_order', 'uuid_alias', 'time_alias', 'null_omission'])
def test_semantic_aliases_are_rejected_as_noncanonical(change):
    import json
    raw = canonical_bytes(trust.ProvenanceEnvelope(**envelope_data()))
    parsed = json.loads(raw)
    if change == 'key_order':
        raw = json.dumps(dict(reversed(tuple(parsed.items()))), separators=(',', ':')).encode()
    if change == 'uuid_alias':
        raw = raw.replace(b'"payload_id":"00000000-0000-0000-0000-00000000001e"',
                          b'"payload_id":"00000000-0000-0000-0000-00000000001E"')
    if change == 'time_alias': raw = raw.replace(b'.000000+00:00', b'Z')
    if change == 'null_omission': raw = raw.replace(b'"provider_identity_id":null,', b'')
    with pytest.raises(StructuralError): parse_canonical(trust.ProvenanceEnvelope, raw)


def test_structural_operations_do_not_access_files_network_processes_or_crypto(monkeypatch):
    import builtins
    import socket
    from unittest.mock import patch
    def forbidden(*args, **kwargs): raise AssertionError('unexpected I/O')
    with patch.object(builtins, 'open', forbidden), patch.object(socket, 'socket', forbidden), patch.object(subprocess, 'Popen', forbidden):
        result = check(trust.ProvenanceEnvelope, envelope_data())
        payload = canonical_bytes(result.record)
        assert parse_canonical(trust.ProvenanceEnvelope, payload) == result.record
    import ast
    for path in Path('services/api/app/iam/trust').glob('*.py'):
        tree = ast.parse(path.read_text())
        imports = [n.module or '' for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        assert not any(name.split('.')[0] in {'cryptography', 'nacl', 'socket', 'sqlalchemy', 'os', 'subprocess'} for name in imports)


def test_nil_delegation_is_not_an_explicit_customer_reference():
    data = root_data()
    data['binding'] = binding(deployment_type='MANAGED_SAAS', provider_identity_id=UUID(int=90))
    cs = [c.model_dump() for c in data['custodians']]
    cs[2].update(kind='PROVIDER_RECOVERY', delegation_ref=reference(0))
    data['custodians'] = tuple(cs)
    denied(trust.RootTrustPolicy, data, 'INVALID_PROVIDER_DELEGATION', expected_binding=data['binding'])


def test_same_identifiers_do_not_bridge_deployment_models():
    data = root_data()
    data['binding'] = binding(deployment_type='MANAGED_SAAS', provider_identity_id=UUID(int=90))
    denied(trust.RootTrustPolicy, data, 'INVALID_DEPLOYMENT_BINDING')
    assert check(trust.RootTrustPolicy, data, expected_binding=data['binding']).status == 'STRUCTURAL_ONLY'


def test_saas_operator_identity_is_not_implicitly_an_issuer():
    data = envelope_data()
    data['binding'] = binding(deployment_type='MANAGED_SAAS', provider_identity_id=UUID(int=90))
    data['issuer_ref'] = reference(90)
    denied(trust.ProvenanceEnvelope, data, 'INVALID_ISSUER_REFERENCE', expected_binding=data['binding'])
