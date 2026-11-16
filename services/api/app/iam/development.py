"""Explicit, non-operational development grants for read-only workflows.

This module is not selected by application routes and cannot supply root authority.
An ALLOW is a non-executable decision; callers must keep any protected work and its
audit event in the same transaction.
"""
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy.orm import Session

from app.audit.integrity import record_audit_event
from app.iam.auth import AuthenticatedPrincipal


_ACTIONS = {
    'tenant.read': ('tenant', 'TENANT'),
    'evidence.read': ('evidence', 'RESOURCE'),
    'audit.read': ('audit', 'COLLECTION'),
}
_POLICY_ID = 'development-explicit-readonly-v1'

Outcome = Literal['ALLOW', 'DENY']
Reason = Literal[
    'EXPLICIT_DEVELOPMENT_GRANT', 'INVALID_PRINCIPAL', 'INVALID_TENANT',
    'TENANT_MISMATCH', 'UNKNOWN_ACTION', 'INVALID_RESOURCE', 'UNSUPPORTED_ENVIRONMENT',
    'ENVIRONMENT_MISMATCH', 'PROVIDER_DISABLED', 'ROOT_AUTHORITY_UNAVAILABLE',
    'MODEL_REQUEST_DENIED', 'NO_EXPLICIT_GRANT', 'INVALID_PROVIDER_CONFIGURATION',
    'AUDIT_UNAVAILABLE', 'AUDIT_WRITE_FAILED',
]


def _valid_id(value):
    return type(value) is UUID and value.int != 0


@dataclass(frozen=True)
class DevelopmentGrant:
    """An exact principal/tenant/action/resource/environment grant; no wildcards."""

    tenant_id: UUID
    principal_id: UUID
    action: str
    resource_type: str
    resource_id: UUID | None
    environment: str


@dataclass(frozen=True)
class DevelopmentAuthorizationProvider:
    """Explicitly injected TEST/development grant set; never auto-selected."""

    environment: str
    grants: tuple[DevelopmentGrant, ...]
    enabled: bool = False


@dataclass(frozen=True)
class DecisionContext:
    tenant_id: UUID | None
    principal_id: UUID | None
    requested_tenant_id: UUID | None
    action: str | None
    resource_type: str | None
    resource_id: UUID | None
    environment: str | None


@dataclass(frozen=True)
class AuthorizationDecision:
    outcome: Outcome
    reason: Reason
    policy_id: str
    context: DecisionContext
    executable: Literal[False] = False


def _decision(outcome, reason, context):
    return AuthorizationDecision(outcome, reason, _POLICY_ID, context)


def _valid_grant(grant):
    if type(grant) is not DevelopmentGrant:
        return False
    if (not _valid_id(grant.tenant_id) or not _valid_id(grant.principal_id)
            or type(grant.action) is not str or grant.action not in _ACTIONS
            or type(grant.resource_type) is not str
            or type(grant.environment) is not str
            or grant.environment not in ('development', 'test')):
        return False
    resource_type, resource_rule = _ACTIONS[grant.action]
    if grant.resource_type != resource_type:
        return False
    if resource_rule == 'TENANT':
        return _valid_id(grant.resource_id) and grant.resource_id == grant.tenant_id
    if resource_rule == 'RESOURCE':
        return _valid_id(grant.resource_id)
    return grant.resource_id is None


def authorize_development(
    provider: DevelopmentAuthorizationProvider,
    principal: AuthenticatedPrincipal | None,
    *,
    tenant_id: UUID,
    action: str,
    resource_type: str,
    resource_id: UUID | None,
    environment: str | None,
    audit_session: Session | None,
    requires_root_authority: bool = False,
    model_generated: bool = False,
) -> AuthorizationDecision:
    """Evaluate one exact dev grant and append its decision to the caller's audit txn.

    Authentication must already have been performed by ``get_current_principal``.
    This function never commits. If the caller's transaction contains protected work,
    the caller must commit that work and this audit event atomically. On
    ``AUDIT_WRITE_FAILED``, the caller must roll back before reusing the session.
    """
    principal_ok = (type(principal) is AuthenticatedPrincipal
                    and _valid_id(principal.tenant_id) and _valid_id(principal.api_key_id))
    authenticated_tenant = principal.tenant_id if principal_ok else None
    principal_id = principal.api_key_id if principal_ok else None
    requested_tenant = tenant_id if _valid_id(tenant_id) else None
    known_action = action if type(action) is str and action in _ACTIONS else None
    expected_resource = _ACTIONS[known_action][0] if known_action else None
    audit_resource_type = expected_resource if resource_type == expected_resource else None
    audit_resource_id = resource_id if _valid_id(resource_id) else None
    audit_environment = (environment if type(environment) is str
                         and environment in ('development', 'test', 'production') else None)
    context = DecisionContext(authenticated_tenant, principal_id, requested_tenant,
                              known_action, audit_resource_type, audit_resource_id, audit_environment)

    if not principal_ok:
        decision = _decision('DENY', 'INVALID_PRINCIPAL', context)
    elif not requested_tenant:
        decision = _decision('DENY', 'INVALID_TENANT', context)
    elif requested_tenant != authenticated_tenant:
        decision = _decision('DENY', 'TENANT_MISMATCH', context)
    elif known_action is None:
        decision = _decision('DENY', 'UNKNOWN_ACTION', context)
    elif type(resource_type) is not str or resource_type != expected_resource:
        decision = _decision('DENY', 'INVALID_RESOURCE', context)
    elif not (
        (expected_resource == 'tenant' and _valid_id(resource_id) and resource_id == authenticated_tenant)
        or (expected_resource == 'evidence' and _valid_id(resource_id))
        or (expected_resource == 'audit' and resource_id is None)
    ):
        decision = _decision('DENY', 'INVALID_RESOURCE', context)
    elif type(environment) is not str or environment not in ('development', 'test'):
        decision = _decision('DENY', 'UNSUPPORTED_ENVIRONMENT', context)
    elif type(provider) is not DevelopmentAuthorizationProvider:
        decision = _decision('DENY', 'INVALID_PROVIDER_CONFIGURATION', context)
    elif type(provider.enabled) is not bool:
        decision = _decision('DENY', 'INVALID_PROVIDER_CONFIGURATION', context)
    elif provider.enabled is not True:
        decision = _decision('DENY', 'PROVIDER_DISABLED', context)
    elif type(provider.environment) is not str or provider.environment not in ('development', 'test'):
        decision = _decision('DENY', 'UNSUPPORTED_ENVIRONMENT', context)
    elif environment != provider.environment:
        decision = _decision('DENY', 'ENVIRONMENT_MISMATCH', context)
    elif type(requires_root_authority) is not bool:
        decision = _decision('DENY', 'INVALID_PROVIDER_CONFIGURATION', context)
    elif requires_root_authority:
        decision = _decision('DENY', 'ROOT_AUTHORITY_UNAVAILABLE', context)
    elif type(model_generated) is not bool:
        decision = _decision('DENY', 'INVALID_PROVIDER_CONFIGURATION', context)
    elif model_generated:
        decision = _decision('DENY', 'MODEL_REQUEST_DENIED', context)
    elif (type(provider.grants) is not tuple
          or any(not _valid_grant(grant) for grant in provider.grants)
          or len(set(provider.grants)) != len(provider.grants)):
        decision = _decision('DENY', 'INVALID_PROVIDER_CONFIGURATION', context)
    else:
        matched = any(
            (grant.tenant_id, grant.principal_id, grant.action, grant.resource_type,
             grant.resource_id, grant.environment)
            == (authenticated_tenant, principal_id, known_action, expected_resource,
                resource_id, environment)
            for grant in provider.grants
        )
        decision = _decision(
            'ALLOW' if matched else 'DENY',
            'EXPLICIT_DEVELOPMENT_GRANT' if matched else 'NO_EXPLICIT_GRANT', context)

    # No tenant is invented before successful authentication. No ALLOW is returned
    # unless the existing hash-chain writer accepts the decision in the caller txn.
    if authenticated_tenant is None or principal_id is None:
        return decision
    if audit_session is None:
        return _decision('DENY', 'AUDIT_UNAVAILABLE', context)
    try:
        event = record_audit_event(
            audit_session,
            tenant_id=authenticated_tenant,
            actor_type='api_key',
            actor_id=principal_id,
            action='iam.authorization.decision',
            resource_type='iam_authorization',
            resource_id=audit_resource_id,
            details={
                'outcome': decision.outcome,
                'reason': decision.reason,
                'policy_id': decision.policy_id,
                'requested_tenant_id': None if requested_tenant is None else str(requested_tenant),
                'action': known_action,
                'resource_type': audit_resource_type,
                'environment': audit_environment,
            },
        )
        if event is None:
            raise RuntimeError('audit_write_failed')
    except Exception:
        return _decision('DENY', 'AUDIT_WRITE_FAILED', context)
    return decision
