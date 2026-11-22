"""Offline query and consistency contracts. This module owns no database session."""

from collections.abc import Mapping
from datetime import datetime
from enum import Enum
import hashlib
import hmac
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field
from sqlalchemy import Select, select

from app.analysts.classification_authority import (
    DecisionState, EvidenceBinding, IssuedClassificationRecord, IssuerScope, PolicyActivation,
    _checked, _ID, _Label, _utc, issuance_digest,
)
from app.analysts.contracts import Digest
from app.database.classification_registry_schema import AUDIT, DECISIONS, POLICIES, REVOCATIONS, SCOPES
from app.gateway.contracts import TrustedContext, _Contract


_Sequence = Annotated[int, Field(ge=1, le=2**63 - 1)]
_Operation = Literal["issue", "revoke"]
IssueAction = "evidence.classification.issue"
DecisionResource = "evidence_classification_decision"


def _identifier(value: UUID) -> UUID:
    if type(value) is not UUID or not value.int:
        raise ValueError("invalid_identifier")
    return value


def _scoped(table, tenant_id: UUID) -> Select:
    return select(table).where(table.c.tenant_id == _identifier(tenant_id))


def decision_lookup(tenant_id: UUID, decision_id: UUID) -> Select:
    return _scoped(DECISIONS, tenant_id).where(DECISIONS.c.decision_id == _identifier(decision_id)).limit(2)


def decision_history(tenant_id: UUID, evidence_id: UUID, *, limit: int = 32) -> Select:
    if type(limit) is not int or not 1 <= limit <= 32:
        raise ValueError("invalid_history_limit")
    return (_scoped(DECISIONS, tenant_id).where(DECISIONS.c.evidence_id == _identifier(evidence_id))
            .order_by(DECISIONS.c.issued_at.desc(), DECISIONS.c.decision_id).limit(limit))


def _policy_history(tenant_id: UUID, policy_id: str) -> Select:
    if type(policy_id) is not str or not 1 <= len(policy_id) <= 64:
        raise ValueError("invalid_policy_id")
    return _scoped(POLICIES, tenant_id).where(POLICIES.c.policy_id == policy_id)


def latest_policy(tenant_id: UUID, policy_id: str) -> Select:
    return _policy_history(tenant_id, policy_id).order_by(POLICIES.c.generation.desc()).limit(1)


def historical_policy_lookup(tenant_id: UUID, policy_id: str, generation: int) -> Select:
    if type(generation) is not int or not 1 <= generation <= 2**63 - 1:
        raise ValueError("invalid_policy_generation")
    return _policy_history(tenant_id, policy_id).where(POLICIES.c.generation == generation).limit(2)


def issuer_scope_lookup(tenant_id: UUID, scope_id: UUID) -> Select:
    return _scoped(SCOPES, tenant_id).where(SCOPES.c.scope_id == _identifier(scope_id)).limit(2)


def suspension_lookup(tenant_id: UUID, scope_id: UUID) -> Select:
    # Preserve the row when unsuspended, so no row cannot be interpreted as active.
    return issuer_scope_lookup(tenant_id, scope_id).with_only_columns(
        SCOPES.c.tenant_id, SCOPES.c.scope_id, SCOPES.c.suspended_at, SCOPES.c.suspension_audit_sequence,
    )


def revocation_lookup(tenant_id: UUID, decision_id: UUID) -> Select:
    return _scoped(REVOCATIONS, tenant_id).where(REVOCATIONS.c.decision_id == _identifier(decision_id)).limit(2)


def idempotency_lookup(context: TrustedContext, operation: _Operation, request_id: UUID) -> Select:
    context = _checked(context, TrustedContext)
    if type(operation) is not str or operation not in ("issue", "revoke"):
        raise ValueError("invalid_operation")
    if operation == "issue":
        table, actor = DECISIONS, DECISIONS.c.requester_principal_id
    else:
        table, actor = REVOCATIONS, REVOCATIONS.c.revoker_principal_id
    return (_scoped(table, context.tenant_id)
            .where(actor == _identifier(context.principal_id), table.c.request_id == _identifier(request_id))
            .limit(2))


def audit_link_lookup(tenant_id: UUID, sequence: int) -> Select:
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise ValueError("invalid_audit_sequence")
    return _scoped(AUDIT, tenant_id).where(AUDIT.c.sequence_number == sequence).limit(2)


class RegistryError(ValueError):
    """Stable offline consistency errors."""


class ReconstructedIssuance(_Contract):
    """Consistent stored bytes and linkage fields, with no authority provenance."""

    record: IssuedClassificationRecord
    issuance_sha256: Digest
    request_sha256: Digest
    audit_sequence: _Sequence


_ISSUANCE_FIELDS = frozenset(IssuedClassificationRecord.model_fields)
_LINK_FIELDS = frozenset(ReconstructedIssuance.model_fields) - {"record", "schema_version"}


def _consistent(value: ReconstructedIssuance) -> ReconstructedIssuance:
    value = _checked(value, ReconstructedIssuance)
    if value.record.classification != "OBSERVED":
        raise RegistryError("INVALID_ISSUANCE_ROW")
    if not hmac.compare_digest(value.issuance_sha256, issuance_digest(value.record)):
        raise RegistryError("ISSUANCE_DIGEST_MISMATCH")
    return value


def reconstruct_issuance(
    row: Mapping[str, object],
    *,
    evidence: EvidenceBinding,
    scope: IssuerScope,
    historical_policy: PolicyActivation,
) -> ReconstructedIssuance:
    """Revalidate a single exact row and its separately supplied relational bindings."""
    try:
        if (not isinstance(row, Mapping) or len(row) != len(_ISSUANCE_FIELDS | _LINK_FIELDS)
                or frozenset(row.keys()) != _ISSUANCE_FIELDS | _LINK_FIELDS):
            raise ValueError()
        evidence = _checked(evidence, EvidenceBinding)
        scope = _checked(scope, IssuerScope)
        policy = _checked(historical_policy, PolicyActivation)
        record = IssuedClassificationRecord.model_validate({key: row[key] for key in _ISSUANCE_FIELDS})
        stored = ReconstructedIssuance(record=record, **{key: row[key] for key in _LINK_FIELDS})
    except (ValueError, TypeError, KeyError):
        raise RegistryError("INVALID_ISSUANCE_ROW") from None
    if (any(record.tenant_id != value.tenant_id for value in (evidence, scope, policy))
            or (record.evidence_id, record.content_sha256) != (evidence.evidence_id, evidence.content_sha256)
            or (record.issuer_scope_id, record.issuer_principal_id, record.authority_id)
            != (scope.scope_id, scope.principal_id, scope.authority_id)
            or (record.policy_id, record.policy_generation, record.policy_sha256)
            != (policy.policy_id, policy.generation, policy.policy_sha256)):
        raise RegistryError("RELATIONAL_BINDING_MISMATCH")
    return _consistent(stored)


class IssuanceAuditEvent(_Contract):
    """Projected fields from an explicitly supplied audit event."""

    tenant_id: _ID
    sequence_number: _Sequence
    action: _Label
    resource_type: _Label
    resource_id: _ID
    actor_type: Literal["service"]
    actor_id: _ID
    issuance_sha256: Digest


def validate_audit_link(
    issuance: ReconstructedIssuance,
    event: IssuanceAuditEvent | None,
    *,
    expected_tenant: UUID,
    expected_action: str,
    expected_resource_type: str,
    expected_resource_id: UUID,
) -> bool:
    """Check internal linkage only. This does not verify the audit chain or issuer."""
    try:
        issuance = _consistent(issuance)
        event = _checked(event, IssuanceAuditEvent)
        _identifier(expected_tenant)
        _identifier(expected_resource_id)
    except ValueError:
        return False
    record = issuance.record
    return (
        event.tenant_id == expected_tenant == record.tenant_id
        and event.sequence_number == issuance.audit_sequence
        and event.action == expected_action == IssueAction
        and event.resource_type == expected_resource_type == DecisionResource
        and event.resource_id == expected_resource_id == record.decision_id
        and event.actor_id == record.issuer_principal_id
        and hmac.compare_digest(event.issuance_sha256, issuance.issuance_sha256)
    )


class IssueRequest(_Contract):
    request_id: _ID
    evidence_id: _ID
    expected_content_sha256: Digest


class RevokeRequest(_Contract):
    request_id: _ID
    decision_id: _ID
    reason_code: Annotated[str, Field(max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")]


def _request_operation(request: IssueRequest | RevokeRequest) -> _Operation:
    if type(request) is IssueRequest:
        return "issue"
    if type(request) is RevokeRequest:
        return "revoke"
    raise ValueError("invalid_request")


class RequestBinding(_Contract):
    tenant_id: _ID
    principal_id: _ID
    operation: _Operation
    request_id: _ID
    request_sha256: Digest


def bind_request(context: TrustedContext, request: IssueRequest | RevokeRequest) -> RequestBinding:
    """Bind canonical request content to independently authenticated context."""
    try:
        context = _checked(context, TrustedContext)
        operation = _request_operation(request)
        request = _checked(request, type(request))
        payload = {
            "domain": "ai-soc-team.classification-request", "operation": operation,
            "context": context.model_dump(mode="json"), "request": request.model_dump(mode="json"),
        }
        return RequestBinding(
            tenant_id=context.tenant_id, principal_id=context.principal_id,
            operation=operation, request_id=request.request_id,
            request_sha256=hashlib.sha256(json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")).hexdigest(),
        )
    except ValueError:
        raise RegistryError("INVALID_REQUEST") from None


class RetryResult(Enum):
    NEW = "NEW"
    EXACT_RETRY = "EXACT_RETRY"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


def check_retry(request: RequestBinding, found: tuple[RequestBinding, ...] | None) -> RetryResult:
    """An empty tuple means a completed lookup. None or multiple rows denies."""
    try:
        request = _checked(request, RequestBinding)
        if type(found) is not tuple or len(found) > 1:
            return RetryResult.UNKNOWN
        if not found:
            return RetryResult.NEW
        previous = _checked(found[0], RequestBinding)
    except ValueError:
        return RetryResult.UNKNOWN
    key = ("tenant_id", "principal_id", "operation", "request_id")
    if any(getattr(request, field) != getattr(previous, field) for field in key):
        return RetryResult.UNKNOWN
    if not hmac.compare_digest(request.request_sha256, previous.request_sha256):
        return RetryResult.CONFLICT
    return RetryResult.EXACT_RETRY


class IssuanceLifecycle(Enum):
    UNKNOWN = "UNKNOWN"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    INACTIVE = "INACTIVE"
    DUPLICATE = "DUPLICATE"
    HIGHER_GENERATION = "HIGHER_GENERATION"


def issuance_lifecycle(
    prior: ReconstructedIssuance,
    *,
    evidence: EvidenceBinding,
    scope: IssuerScope,
    current_policy: PolicyActivation,
    state: DecisionState,
    at: datetime,
) -> IssuanceLifecycle:
    """Check renewal constraints only. It supplies neither validity nor issuance authority."""
    try:
        prior = _consistent(prior)
        evidence = _checked(evidence, EvidenceBinding)
        scope = _checked(scope, IssuerScope)
        policy = _checked(current_policy, PolicyActivation)
        state = _checked(state, DecisionState)
        at = _utc(at)
    except (ValueError, OverflowError):
        return IssuanceLifecycle.UNKNOWN
    record = prior.record
    if (any(item.tenant_id != record.tenant_id for item in (evidence, scope, policy, state))
            or (evidence.evidence_id, evidence.content_sha256) != (record.evidence_id, record.content_sha256)
            or (scope.scope_id, scope.principal_id, scope.authority_id)
            != (record.issuer_scope_id, record.issuer_principal_id, record.authority_id)
            or (state.decision_id, state.issuance_sha256) != (record.decision_id, prior.issuance_sha256)
            or policy.policy_id != record.policy_id or policy.generation < record.policy_generation
            or (policy.generation == record.policy_generation and policy.policy_sha256 != record.policy_sha256)
            or at < record.issued_at):
        return IssuanceLifecycle.UNKNOWN
    if policy.active and scope.active and policy.generation > record.policy_generation:
        # Only the generation requirement is met. The old record remains inactive.
        return IssuanceLifecycle.HIGHER_GENERATION
    if state.revoked:
        return IssuanceLifecycle.REVOKED
    if at >= record.expires_at:
        return IssuanceLifecycle.EXPIRED
    if not policy.active or not scope.active or policy.generation != record.policy_generation:
        return IssuanceLifecycle.INACTIVE
    return IssuanceLifecycle.DUPLICATE


class SourceVerificationRequirement(EvidenceBinding):
    """Required binding for a future protected attestation.

    A separately authenticated verification authority must establish the collector
    or integration identity, verification timestamp, current validity/revocation,
    and tenant audit link.
    No such trust source can be supplied to the offline registry.
    """

    source_id: _ID
    verification_id: _ID

    @property
    def status(self) -> Literal["SOURCE_VERIFICATION_UNAVAILABLE"]:
        return "SOURCE_VERIFICATION_UNAVAILABLE"
