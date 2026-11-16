from uuid import UUID

import pytest

from app.iam.auth import AuthenticatedPrincipal
from app.iam import development as dev


TENANT = UUID(int=1)
PRINCIPAL = UUID(int=2)
RESOURCE = UUID(int=3)


class AuditSession:
    pass


def grant(*, tenant=TENANT, principal=PRINCIPAL, action='evidence.read',
          resource_type='evidence', resource=RESOURCE, environment='development'):
    return dev.DevelopmentGrant(tenant, principal, action, resource_type, resource, environment)


def provider(*grants, environment='development', enabled=True):
    return dev.DevelopmentAuthorizationProvider(environment, tuple(grants), enabled)


def authorize(monkeypatch, *, grants=None, principal=None, tenant=TENANT,
              action='evidence.read', resource_type='evidence', resource=RESOURCE,
              environment='development', audit_session=AuditSession(), **kwargs):
    events = []

    def write(session, **fields):
        events.append((session, fields))
        return object()

    monkeypatch.setattr(dev, 'record_audit_event', write)
    result = dev.authorize_development(
        provider(*(grants if grants is not None else (grant(),))),
        AuthenticatedPrincipal(TENANT, PRINCIPAL) if principal is None else principal,
        tenant_id=tenant, action=action, resource_type=resource_type,
        resource_id=resource, environment=environment, audit_session=audit_session,
        **kwargs,
    )
    return result, events


def test_exact_development_grant_allows_and_records_sanitized_audit(monkeypatch):
    result, events = authorize(monkeypatch)
    assert result.outcome == 'ALLOW'
    assert result.reason == 'EXPLICIT_DEVELOPMENT_GRANT'
    assert result.executable is False
    assert result.policy_id == 'development-explicit-readonly-v1'
    assert len(events) == 1
    _, event = events[0]
    assert event['tenant_id'] == TENANT
    assert event['actor_id'] == PRINCIPAL
    assert event['action'] == 'iam.authorization.decision'
    assert event['details']['outcome'] == 'ALLOW'
    assert event['details']['action'] == 'evidence.read'
    assert 'api_key' not in repr(event['details'])


@pytest.mark.parametrize(('change', 'reason'), [
    ({'grants': ()}, 'NO_EXPLICIT_GRANT'),
    ({'action': 'unknown.read'}, 'UNKNOWN_ACTION'),
    ({'action': 'response.execute'}, 'UNKNOWN_ACTION'),
    ({'action': 'roles.assign'}, 'UNKNOWN_ACTION'),
    ({'resource_type': 'audit'}, 'INVALID_RESOURCE'),
    ({'resource': UUID(int=4)}, 'NO_EXPLICIT_GRANT'),
    ({'tenant': UUID(int=99)}, 'TENANT_MISMATCH'),
    ({'principal': AuthenticatedPrincipal(TENANT, UUID(int=99))}, 'NO_EXPLICIT_GRANT'),
    ({'environment': 'production'}, 'UNSUPPORTED_ENVIRONMENT'),
    ({'environment': None}, 'UNSUPPORTED_ENVIRONMENT'),
    ({'requires_root_authority': True}, 'ROOT_AUTHORITY_UNAVAILABLE'),
    ({'model_generated': True}, 'MODEL_REQUEST_DENIED'),
])
def test_mismatched_or_unsupported_requests_deny(monkeypatch, change, reason):
    result, events = authorize(monkeypatch, **change)
    assert result.outcome == 'DENY'
    assert result.reason == reason
    assert len(events) == 1
    assert events[0][1]['details']['outcome'] == 'DENY'


def test_only_verified_read_routes_are_allowlisted(monkeypatch):
    cases = (
        ('tenant.read', 'tenant', TENANT),
        ('audit.read', 'audit', None),
    )
    for action, resource_type, resource_id in cases:
        exact = grant(action=action, resource_type=resource_type, resource=resource_id)
        result, _ = authorize(monkeypatch, grants=(exact,), action=action,
                              resource_type=resource_type, resource=resource_id)
        assert result.outcome == 'ALLOW'
    result, _ = authorize(monkeypatch, action='wazuh.alerts.read', resource_type='alert')
    assert result.outcome == 'DENY'
    assert result.reason == 'UNKNOWN_ACTION'


@pytest.mark.parametrize('provider_value,reason', [
    (provider(grant(), enabled=False), 'PROVIDER_DISABLED'),
    (provider(grant(), environment='production'), 'UNSUPPORTED_ENVIRONMENT'),
    (provider(grant(), environment='test'), 'ENVIRONMENT_MISMATCH'),
])
def test_provider_is_explicitly_opt_in_and_never_falls_back(monkeypatch, provider_value, reason):
    events = []
    monkeypatch.setattr(dev, 'record_audit_event', lambda session, **fields: events.append(fields) or object())
    result = dev.authorize_development(
        provider_value, AuthenticatedPrincipal(TENANT, PRINCIPAL), tenant_id=TENANT,
        action='evidence.read', resource_type='evidence', resource_id=RESOURCE,
        environment='development', audit_session=AuditSession())
    assert result.outcome == 'DENY'
    assert result.reason == reason


def test_missing_or_malformed_principal_denies_without_fake_tenant_audit(monkeypatch):
    result, events = authorize(monkeypatch, principal=object())
    assert result.outcome == 'DENY'
    assert result.reason == 'INVALID_PRINCIPAL'
    assert result.context.tenant_id is None
    assert events == []


def test_no_audit_session_cannot_return_allow(monkeypatch):
    result, events = authorize(monkeypatch, audit_session=None)
    assert result.outcome == 'DENY'
    assert result.reason == 'AUDIT_UNAVAILABLE'
    assert events == []


def test_audit_write_failure_cannot_turn_a_deny_into_allow(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('private driver detail')

    monkeypatch.setattr(dev, 'record_audit_event', fail)
    result = dev.authorize_development(
        provider(), AuthenticatedPrincipal(TENANT, PRINCIPAL), tenant_id=TENANT,
        action='evidence.read', resource_type='evidence', resource_id=UUID(int=4),
        environment='development', audit_session=AuditSession())
    assert result.outcome == 'DENY'
    assert result.reason == 'AUDIT_WRITE_FAILED'
    assert 'private driver detail' not in repr(result)


def test_audit_write_failure_denies_a_matching_grant(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('private driver detail')

    monkeypatch.setattr(dev, 'record_audit_event', fail)
    result = dev.authorize_development(
        provider(grant()), AuthenticatedPrincipal(TENANT, PRINCIPAL), tenant_id=TENANT,
        action='evidence.read', resource_type='evidence', resource_id=RESOURCE,
        environment='development', audit_session=AuditSession())
    assert result.outcome == 'DENY'
    assert result.reason == 'AUDIT_WRITE_FAILED'


def test_audit_failure_cannot_override_missing_root_authority(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('private driver detail')

    monkeypatch.setattr(dev, 'record_audit_event', fail)
    result = dev.authorize_development(
        provider(grant()), AuthenticatedPrincipal(TENANT, PRINCIPAL), tenant_id=TENANT,
        action='evidence.read', resource_type='evidence', resource_id=RESOURCE,
        environment='development', audit_session=AuditSession(), requires_root_authority=True)
    assert result.outcome == 'DENY'
    assert result.reason == 'AUDIT_WRITE_FAILED'


def test_malformed_grants_and_duplicate_grants_fail_closed(monkeypatch):
    malformed = dev.DevelopmentGrant(TENANT, PRINCIPAL, ['evidence.read'], 'evidence', RESOURCE, 'development')
    for grants in ((malformed,), (grant(), grant())):
        events = []
        monkeypatch.setattr(dev, 'record_audit_event', lambda session, **fields: events.append(fields) or object())
        result = dev.authorize_development(
            provider(*grants), AuthenticatedPrincipal(TENANT, PRINCIPAL), tenant_id=TENANT,
            action='evidence.read', resource_type='evidence', resource_id=RESOURCE,
            environment='development', audit_session=AuditSession())
        assert result.outcome == 'DENY'
        assert result.reason == 'INVALID_PROVIDER_CONFIGURATION'


def test_authenticated_tenant_is_used_for_mismatch_audit(monkeypatch):
    result, events = authorize(monkeypatch, tenant=UUID(int=99))
    assert result.reason == 'TENANT_MISMATCH'
    fields = events[0][1]
    assert fields['tenant_id'] == TENANT
    assert fields['details']['requested_tenant_id'] == str(UUID(int=99))
