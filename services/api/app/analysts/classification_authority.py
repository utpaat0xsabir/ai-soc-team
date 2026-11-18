"""Offline validity checks over independently trusted state.

Construction of a typed value authenticates nothing. Only trusted application
composition may supply issuer, evidence, policy, source and decision state.
Results confer no permission to invoke inference.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from typing import Annotated, Literal, TypeVar
from uuid import UUID

from pydantic import AfterValidator, Field, model_validator

from app.analysts.contracts import Classification, Digest
from app.gateway.contracts import _Contract


def _nonzero(value: UUID) -> UUID:
    if not value.int:
        raise ValueError("invalid_identifier")
    return value


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.utcoffset() != timedelta(0):
        raise ValueError("invalid_utc_time")
    return value.astimezone(timezone.utc)


_ID = Annotated[UUID, AfterValidator(_nonzero)]
_UTC = Annotated[datetime, AfterValidator(_utc)]
_Label = Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
_Login = Annotated[str, Field(max_length=63, pattern=r"^[a-z_][a-z0-9_]*$")]
_Generation = Annotated[int, Field(ge=1, le=2**63 - 1)]
_MAX_RECORD_BYTES = 4096


class EvidenceBinding(_Contract):
    """Binding supplied by the caller after tenant-scoped integrity verification."""

    tenant_id: _ID
    evidence_id: _ID
    content_sha256: Digest


class IssuedClassificationRecord(EvidenceBinding):
    record_domain: Literal["ai-soc-team.evidence-classification"]
    schema_version: Literal["1.0"] = Field()
    decision_id: _ID
    classification: Classification
    authority_id: _Label
    evaluator_policy_version: Literal["1"]
    issuer_scope_id: _ID
    issuer_principal_id: _ID
    requester_principal_id: _ID
    policy_id: _Label
    policy_generation: _Generation
    policy_sha256: Digest
    source_verification_id: _ID
    issued_at: _UTC
    expires_at: _UTC
    request_id: _ID

    @model_validator(mode="after")
    def check_interval(self):
        if self.expires_at <= self.issued_at:
            raise ValueError("invalid_issuance_interval")
        return self


class AuthenticatedIssuer(_Contract):
    """Identity established independently of the issued record."""

    tenant_id: _ID
    scope_id: _ID
    principal_id: _ID
    database_login: _Login


class IssuerScope(AuthenticatedIssuer):
    authority_id: _Label
    source_id: _ID
    active: bool


class PolicyActivation(_Contract):
    tenant_id: _ID
    policy_id: _Label
    generation: _Generation
    policy_sha256: Digest
    active: bool


class SourceVerificationReference(EvidenceBinding):
    """Reference to independently verified source state, not an attestation issuer."""

    source_id: _ID
    verification_id: _ID
    active: bool


class DecisionState(_Contract):
    """Trusted registry state for the exact issuance, including permanent revocation."""

    tenant_id: _ID
    decision_id: _ID
    issuance_sha256: Digest
    revoked: bool


class ValidityResult(Enum):
    VALID = "VALID"
    MISSING_STATE = "MISSING_STATE"
    INVALID_STATE = "INVALID_STATE"
    INVALID_RECORD = "INVALID_RECORD"
    INVALID_TIME = "INVALID_TIME"
    UNSUPPORTED_CLASSIFICATION = "UNSUPPORTED_CLASSIFICATION"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    ISSUER_DENIED = "ISSUER_DENIED"
    POLICY_INACTIVE = "POLICY_INACTIVE"
    POLICY_DIGEST_MISMATCH = "POLICY_DIGEST_MISMATCH"
    SOURCE_UNVERIFIED = "SOURCE_UNVERIFIED"
    ISSUANCE_MISMATCH = "ISSUANCE_MISMATCH"
    REVOKED = "REVOKED"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"


_T = TypeVar("_T", bound=_Contract)


def _checked(value: object, contract: type[_T]) -> _T:
    if type(value) is not contract:
        raise ValueError("invalid_contract")
    return contract.model_validate(value)


def canonical_issuance_bytes(record: IssuedClassificationRecord) -> bytes:
    """V1 UTC uses six decimal places and +00:00. Audit linkage is external."""
    try:
        record = _checked(record, IssuedClassificationRecord)
    except ValueError:
        raise ValueError("invalid_issuance_record") from None
    fields = record.model_dump(mode="json")
    for name in ("issued_at", "expires_at"):
        fields[name] = getattr(record, name).isoformat(timespec="microseconds")
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("utf-8")
    if len(payload) > _MAX_RECORD_BYTES:
        raise ValueError("invalid_issuance_record")
    return payload


def issuance_digest(record: IssuedClassificationRecord) -> str:
    """Digest of issuance metadata, distinct from E2's content digest. Neither authenticates an issuer."""
    return hashlib.sha256(canonical_issuance_bytes(record)).hexdigest()


def is_policy_successor(previous: PolicyActivation, candidate: PolicyActivation) -> bool:
    """Use the latest trusted generation, including disabled generations, as the floor.

    Renewal after expiry or revocation requires separate approval and a higher
    generation. B1 does not persist or activate policy.
    """
    try:
        previous = _checked(previous, PolicyActivation)
        candidate = _checked(candidate, PolicyActivation)
    except ValueError:
        return False
    return (candidate.tenant_id == previous.tenant_id and candidate.policy_id == previous.policy_id
            and candidate.generation > previous.generation)


def evaluate_validity(
    record: IssuedClassificationRecord,
    *,
    evidence: EvidenceBinding,
    issuer: AuthenticatedIssuer,
    scope: IssuerScope,
    policy: PolicyActivation,
    source: SourceVerificationReference,
    state: DecisionState,
    at: datetime,
) -> ValidityResult:
    """Evaluate exact issuance against current state from a trusted, coherent read."""
    if any(value is None for value in (evidence, issuer, scope, policy, source, state, at)):
        return ValidityResult.MISSING_STATE
    try:
        record = _checked(record, IssuedClassificationRecord)
    except ValueError:
        return ValidityResult.INVALID_RECORD
    try:
        evidence = _checked(evidence, EvidenceBinding)
        issuer = _checked(issuer, AuthenticatedIssuer)
        scope = _checked(scope, IssuerScope)
        policy = _checked(policy, PolicyActivation)
        source = _checked(source, SourceVerificationReference)
        state = _checked(state, DecisionState)
    except ValueError:
        return ValidityResult.INVALID_STATE
    try:
        at = _utc(at)
    except (ValueError, OverflowError):
        return ValidityResult.INVALID_TIME

    if record.classification != "OBSERVED":
        return ValidityResult.UNSUPPORTED_CLASSIFICATION
    if (any(value.tenant_id != record.tenant_id for value in (evidence, issuer, scope, policy, source, state))
            or record.evidence_id != evidence.evidence_id or record.decision_id != state.decision_id):
        return ValidityResult.SCOPE_MISMATCH
    if not hmac.compare_digest(record.content_sha256, evidence.content_sha256):
        return ValidityResult.DIGEST_MISMATCH
    if state.revoked:
        return ValidityResult.REVOKED
    if (not scope.active or issuer.scope_id != scope.scope_id or record.issuer_scope_id != scope.scope_id
            or issuer.principal_id != scope.principal_id or record.issuer_principal_id != scope.principal_id
            or issuer.database_login != scope.database_login or record.authority_id != scope.authority_id):
        return ValidityResult.ISSUER_DENIED
    if (not policy.active or record.policy_id != policy.policy_id
            or record.policy_generation != policy.generation):
        return ValidityResult.POLICY_INACTIVE
    if not hmac.compare_digest(record.policy_sha256, policy.policy_sha256):
        return ValidityResult.POLICY_DIGEST_MISMATCH
    if (not source.active or source.verification_id != record.source_verification_id
            or source.source_id != scope.source_id or source.evidence_id != record.evidence_id
            or not hmac.compare_digest(source.content_sha256, record.content_sha256)):
        return ValidityResult.SOURCE_UNVERIFIED
    if not hmac.compare_digest(state.issuance_sha256, issuance_digest(record)):
        return ValidityResult.ISSUANCE_MISMATCH
    if at < record.issued_at:
        return ValidityResult.NOT_YET_VALID
    if at >= record.expires_at:
        return ValidityResult.EXPIRED
    return ValidityResult.VALID
