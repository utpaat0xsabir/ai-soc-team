"""Offline consistency checks for dedicated Wazuh installations.

Trusted adapters must establish identity, provenance and freshness independently.
None of these contracts establishes source truth, evidence trust, or admission.
"""

from datetime import datetime
from enum import Enum
import hashlib
import hmac
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, TypeAdapter, field_validator, model_validator

from app.analysts.classification_authority import (
    EvidenceBinding, _checked, _Generation, _ID, _Label, _Login, _utc, _UTC,
)
from app.analysts.contracts import Digest
from app.gateway.contracts import TrustedContext, _Contract


_DocumentID = Annotated[str, Field(max_length=512, pattern=r"^[A-Za-z0-9_.:-]+$")]
_IndexUUID = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{21}[AQgw]$")]
_Revision = Annotated[int, Field(ge=0, le=2**63 - 1)]
_DIGEST = TypeAdapter(Digest)
_MAX_RECORD_BYTES = 4096


class ProtectedEventLocator(_Contract):
    installation_id: _ID
    index_uuid: _IndexUUID
    document_id: _DocumentID
    event_revision: _Revision | None = None

    @field_validator("document_id")
    @classmethod
    def reject_dot_segments(cls, value):
        if value in (".", ".."):
            raise ValueError("invalid_document_id")
        return value


class _SourceBinding(_Contract):
    tenant_id: _ID
    source_scope_id: _ID
    integration_id: _ID


class SourceConfiguration(_SourceBinding):
    installation_id: _ID
    generation: _Generation
    config_sha256: Digest
    collector_principal_id: _ID
    collector_scope_id: _ID
    collector_database_login: _Login
    normalization: _Label
    normalization_version: _Label
    credential_epoch_id: _ID
    mode: Literal["DEDICATED"]
    active: bool


class AuthenticatedCollector(_SourceBinding):
    """Supplied by a protected adapter after workload and database authentication."""

    principal_id: _ID
    collector_scope_id: _ID
    database_login: _Login
    generation: _Generation
    credential_epoch_id: _ID


class AuthenticatedAttestor(_SourceBinding):
    """Independently authenticated state; construction does not authenticate."""

    principal_id: _ID
    attestor_scope_id: _ID
    database_login: _Login
    verification_method: _Label
    verification_version: _Label


class CollectionRequest(EvidenceBinding, _SourceBinding):
    request_id: _ID
    generation: _Generation
    config_sha256: Digest
    locator: ProtectedEventLocator


class VerificationRequest(EvidenceBinding, _SourceBinding):
    request_id: _ID
    receipt_id: _ID


class SourceCollectionReceipt(CollectionRequest):
    record_domain: Literal["ai-soc-team.source-collection-receipt"]
    schema_version: Literal["1.0"] = Field()
    receipt_id: _ID
    collector_principal_id: _ID
    collector_scope_id: _ID
    origin_sha256: Digest
    collected_at: _UTC
    request_sha256: Digest


class SourceVerificationAttestation(VerificationRequest):
    record_domain: Literal["ai-soc-team.source-verification-attestation"]
    schema_version: Literal["1.0"] = Field()
    attestation_id: _ID
    receipt_sha256: Digest
    collector_principal_id: _ID
    origin_sha256: Digest
    attestor_principal_id: _ID
    attestor_scope_id: _ID
    verification_method: _Label
    verification_version: _Label
    generation: _Generation
    config_sha256: Digest
    verified_at: _UTC
    expires_at: _UTC
    requester_principal_id: _ID

    @model_validator(mode="after")
    def check_interval(self):
        if self.expires_at <= self.verified_at:
            raise ValueError("invalid_attestation_interval")
        return self


def _canonical(fields: dict) -> bytes:
    encoded = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("utf-8")
    if len(encoded) > _MAX_RECORD_BYTES:
        raise ValueError("invalid_source_record")
    return encoded


def canonical_origin_bytes(locator: ProtectedEventLocator) -> bytes:
    """Index UUID is a canonical unpadded base64url identifier.

    Revisions are compared on replay, never used to create a new origin.
    """
    locator = _checked(locator, ProtectedEventLocator)
    return _canonical({
        "domain": "ai-soc-team.source-origin", "version": "1.0",
        **locator.model_dump(mode="json", include={"installation_id", "index_uuid", "document_id"}),
    })


def origin_digest(locator: ProtectedEventLocator) -> str:
    return hashlib.sha256(canonical_origin_bytes(locator)).hexdigest()


def _record_bytes(record, contract, *time_fields) -> bytes:
    try:
        record = _checked(record, contract)
    except ValueError:
        raise ValueError("invalid_source_record") from None
    fields = record.model_dump(mode="json")
    for name in time_fields:
        fields[name] = getattr(record, name).isoformat(timespec="microseconds")
    return _canonical(fields)


def canonical_receipt_bytes(record: SourceCollectionReceipt) -> bytes:
    return _record_bytes(record, SourceCollectionReceipt, "collected_at")


def receipt_digest(record: SourceCollectionReceipt) -> str:
    return hashlib.sha256(canonical_receipt_bytes(record)).hexdigest()


def canonical_attestation_bytes(record: SourceVerificationAttestation) -> bytes:
    return _record_bytes(record, SourceVerificationAttestation, "verified_at", "expires_at")


def attestation_digest(record: SourceVerificationAttestation) -> str:
    return hashlib.sha256(canonical_attestation_bytes(record)).hexdigest()


def request_digest(context: TrustedContext, request: CollectionRequest | VerificationRequest) -> str:
    try:
        context = _checked(context, TrustedContext)
        if type(request) is CollectionRequest:
            operation = "collect"
            request = _checked(request, CollectionRequest)
        else:
            operation = "verify"
            request = _checked(request, VerificationRequest)
        if not context.principal_id.int or context.tenant_id != request.tenant_id:
            raise ValueError()
    except ValueError:
        raise ValueError("invalid_source_request") from None
    return hashlib.sha256(_canonical({
        "domain": "ai-soc-team.source-request", "version": "1.0", "operation": operation,
        "context": context.model_dump(mode="json"), "request": request.model_dump(mode="json"),
    })).hexdigest()


def _check_receipt(receipt: SourceCollectionReceipt) -> SourceCollectionReceipt:
    receipt = _checked(receipt, SourceCollectionReceipt)
    request = CollectionRequest.model_validate(receipt.model_dump(include=set(CollectionRequest.model_fields)))
    context = TrustedContext(tenant_id=receipt.tenant_id, principal_id=receipt.collector_principal_id)
    if (not hmac.compare_digest(receipt.origin_sha256, origin_digest(receipt.locator))
            or not hmac.compare_digest(receipt.request_sha256, request_digest(context, request))):
        raise ValueError("invalid_receipt_binding")
    return receipt


class ReplayResult(Enum):
    NEW = "NEW"
    EXACT_RETRY = "EXACT_RETRY"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


def classify_replay(
    candidate: SourceCollectionReceipt,
    prior: tuple[SourceCollectionReceipt, ...] | None,
    *,
    latest_generation: int,
) -> ReplayResult:
    """Prior rows are from a complete protected lookup of this origin key.

    An empty tuple is a completed miss. Distinct index UUIDs are distinct
    origins and must use separate lookups. No reindex continuity is inferred.
    """
    try:
        candidate = _check_receipt(candidate)
        if (type(latest_generation) is not int or candidate.generation != latest_generation
                or type(prior) is not tuple or len(prior) > 1):
            return ReplayResult.UNKNOWN
        if not prior:
            return ReplayResult.NEW
        previous = _check_receipt(prior[0])
    except ValueError:
        return ReplayResult.UNKNOWN
    if previous.origin_sha256 != candidate.origin_sha256:
        return ReplayResult.UNKNOWN
    if (previous.collector_scope_id != candidate.collector_scope_id
            or not hmac.compare_digest(previous.request_sha256, candidate.request_sha256)):
        return ReplayResult.CONFLICT
    return ReplayResult.EXACT_RETRY


class IndependentRetrievalResult(_SourceBinding):
    """Future independently retrieved state. A caller-created MATCH proves nothing."""

    installation_id: _ID
    receipt_id: _ID
    attestor_principal_id: _ID
    attestor_scope_id: _ID
    requested_locator: ProtectedEventLocator
    returned_locator: ProtectedEventLocator | None
    generation: _Generation
    config_sha256: Digest
    normalization: _Label
    normalization_version: _Label
    reproduced_sha256: Digest | None
    outcome: Literal["MATCH", "MISMATCH", "NOT_FOUND", "SOURCE_UNAVAILABLE",
                     "UNAUTHORIZED", "AMBIGUOUS", "ERROR"]


class ScopeState(_SourceBinding):
    suspended: bool


class AttestationState(_SourceBinding):
    attestation_id: _ID
    attestation_sha256: Digest
    revoked: bool


class EvaluationResult(_Contract):
    valid: bool
    reason: Literal["CONSISTENT", "MISSING_STATE", "INVALID_STATE", "SCOPE_MISMATCH",
                    "EVIDENCE_MISMATCH", "INVALID_RECEIPT", "INVALID_ATTESTATION",
                    "CONFIGURATION_INACTIVE", "COLLECTOR_MISMATCH", "ATTESTOR_MISMATCH",
                    "IDENTITY_COLLISION", "RETRIEVAL_NOT_MATCHED", "SCOPE_SUSPENDED",
                    "ATTESTATION_REVOKED", "NOT_YET_VALID", "EXPIRED"]
    evaluator_version: Literal["1"] = "1"
    tenant_id: _ID | None = None
    evidence_id: _ID | None = None
    attestation_id: _ID | None = None


def _source(value: _SourceBinding) -> tuple[UUID, UUID, UUID]:
    return value.tenant_id, value.source_scope_id, value.integration_id


def _evidence(value: EvidenceBinding) -> tuple[UUID, UUID, str]:
    return value.tenant_id, value.evidence_id, value.content_sha256


def evaluate_source_verification(
    *,
    evidence: EvidenceBinding,
    receipt: SourceCollectionReceipt,
    receipt_sha256: Digest,
    attestation: SourceVerificationAttestation,
    collector: AuthenticatedCollector,
    attestor: AuthenticatedAttestor,
    configuration: SourceConfiguration,
    latest_generation: int,
    retrieval: IndependentRetrievalResult,
    scope_state: ScopeState,
    attestation_state: AttestationState,
    at: datetime,
) -> EvaluationResult:
    """Evaluate coherent offline state only; the output is not an authority capability."""
    if any(value is None for value in (
        evidence, receipt, receipt_sha256, attestation, collector, attestor, configuration,
        latest_generation, retrieval, scope_state, attestation_state, at,
    )):
        return EvaluationResult(valid=False, reason="MISSING_STATE")
    try:
        receipt = _check_receipt(receipt)
        if not hmac.compare_digest(_DIGEST.validate_python(receipt_sha256, strict=True),
                                   receipt_digest(receipt)):
            raise ValueError()
    except ValueError:
        return EvaluationResult(valid=False, reason="INVALID_RECEIPT")
    try:
        attestation = _checked(attestation, SourceVerificationAttestation)
    except ValueError:
        return EvaluationResult(valid=False, reason="INVALID_ATTESTATION")
    try:
        evidence = _checked(evidence, EvidenceBinding)
        collector = _checked(collector, AuthenticatedCollector)
        attestor = _checked(attestor, AuthenticatedAttestor)
        configuration = _checked(configuration, SourceConfiguration)
        retrieval = _checked(retrieval, IndependentRetrievalResult)
        scope_state = _checked(scope_state, ScopeState)
        attestation_state = _checked(attestation_state, AttestationState)
        at = _utc(at)
        if type(latest_generation) is not int or not 1 <= latest_generation <= 2**63 - 1:
            raise ValueError()
    except (ValueError, OverflowError):
        return EvaluationResult(valid=False, reason="INVALID_STATE")

    def result(reason):
        return EvaluationResult(valid=reason == "CONSISTENT", reason=reason,
                                tenant_id=evidence.tenant_id, evidence_id=evidence.evidence_id,
                                attestation_id=attestation.attestation_id)

    if any(_source(item) != _source(configuration) for item in (
        receipt, attestation, collector, attestor, retrieval, scope_state, attestation_state,
    )) or evidence.tenant_id != configuration.tenant_id:
        return result("SCOPE_MISMATCH")
    if _evidence(receipt) != _evidence(evidence) or _evidence(attestation) != _evidence(evidence):
        return result("EVIDENCE_MISMATCH")
    if (attestation.receipt_id != receipt.receipt_id
            or attestation.origin_sha256 != receipt.origin_sha256
            or attestation.receipt_sha256 != receipt_sha256
            or attestation.collector_principal_id != receipt.collector_principal_id
            or attestation.verified_at < receipt.collected_at
            or attestation_state.attestation_id != attestation.attestation_id
            or not hmac.compare_digest(attestation_state.attestation_sha256, attestation_digest(attestation))):
        return result("INVALID_ATTESTATION")
    if scope_state.suspended:
        return result("SCOPE_SUSPENDED")
    if attestation_state.revoked:
        return result("ATTESTATION_REVOKED")
    if (not configuration.active or configuration.generation != latest_generation
            or any((item.generation, item.config_sha256)
                   != (configuration.generation, configuration.config_sha256)
                   for item in (receipt, attestation, retrieval))):
        return result("CONFIGURATION_INACTIVE")
    if (collector.principal_id != configuration.collector_principal_id
            or collector.collector_scope_id != configuration.collector_scope_id
            or collector.database_login != configuration.collector_database_login
            or (receipt.collector_principal_id, receipt.collector_scope_id)
            != (collector.principal_id, collector.collector_scope_id)
            or collector.generation != configuration.generation
            or collector.credential_epoch_id != configuration.credential_epoch_id):
        return result("COLLECTOR_MISMATCH")
    if (attestation.attestor_principal_id, attestation.attestor_scope_id, attestation.verification_method,
            attestation.verification_version) != (attestor.principal_id, attestor.attestor_scope_id,
                                                  attestor.verification_method, attestor.verification_version):
        return result("ATTESTOR_MISMATCH")
    if (collector.principal_id == attestor.principal_id
            or collector.collector_scope_id == attestor.attestor_scope_id
            or collector.database_login == attestor.database_login):
        return result("IDENTITY_COLLISION")
    if (retrieval.outcome != "MATCH" or retrieval.installation_id != configuration.installation_id
            or retrieval.receipt_id != receipt.receipt_id
            or (retrieval.attestor_principal_id, retrieval.attestor_scope_id)
            != (attestor.principal_id, attestor.attestor_scope_id)
            or receipt.locator.installation_id != configuration.installation_id
            or retrieval.requested_locator != receipt.locator or retrieval.returned_locator != receipt.locator
            or (retrieval.normalization, retrieval.normalization_version)
            != (configuration.normalization, configuration.normalization_version)
            or retrieval.reproduced_sha256 != evidence.content_sha256):
        return result("RETRIEVAL_NOT_MATCHED")
    if at < attestation.verified_at:
        return result("NOT_YET_VALID")
    if at >= attestation.expires_at:
        return result("EXPIRED")
    return result("CONSISTENT")
