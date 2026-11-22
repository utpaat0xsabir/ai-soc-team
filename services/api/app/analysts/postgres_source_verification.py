"""Offline source registry queries and consistency checks.

Lookup outcomes must come from future protected adapters. SQL construction,
canonical digests and model instances confer no authentication or authority.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import hmac
from typing import Annotated, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import Field, field_validator
from sqlalchemy import Select, select

from app.analysts import source_verification as sv
from app.analysts.classification_authority import EvidenceBinding, _Generation, _ID, _Label, _UTC, _checked
from app.analysts.contracts import Digest
from app.database import source_registry_schema as schema
from app.gateway.contracts import TrustedContext, _Contract


class RegistryError(ValueError):
    """Bounded, non-sensitive offline consistency failure."""


_Sequence = Annotated[int, Field(ge=1, le=2**63 - 1)]
_Duration = Annotated[int, Field(ge=1, le=2**31 - 1)]


def _id(value: UUID) -> UUID:
    if type(value) is not UUID or not value.int:
        raise RegistryError("INVALID_IDENTIFIER")
    return value


def _by_id(table, tenant_id: UUID, field, identity: UUID) -> Select:
    # Generated SQL-only locator key is outside the canonical receipt projection.
    columns = [column for column in table.c if column.name != "locator_revision_key"]
    return select(*columns).where(table.c.tenant_id == _id(tenant_id), field == _id(identity))


def installation_lookup(tenant_id: UUID, installation_id: UUID) -> Select:
    return _by_id(schema.INSTALLATIONS, tenant_id, schema.INSTALLATIONS.c.installation_id, installation_id).limit(2)


def scope_lookup(tenant_id: UUID, scope_id: UUID) -> Select:
    return _by_id(schema.SCOPES, tenant_id, schema.SCOPES.c.source_scope_id, scope_id).limit(2)


def latest_configuration(tenant_id: UUID, scope_id: UUID) -> Select:
    table = schema.CONFIGURATIONS
    return _by_id(table, tenant_id, table.c.source_scope_id, scope_id).order_by(table.c.generation.desc()).limit(1)


def exact_configuration(tenant_id: UUID, scope_id: UUID, generation: int, config_sha256: str) -> Select:
    if type(generation) is not int or not 1 <= generation <= 2**63 - 1:
        raise RegistryError("INVALID_CONFIGURATION")
    try:
        digest = sv._DIGEST.validate_python(config_sha256, strict=True)
    except ValueError:
        raise RegistryError("INVALID_CONFIGURATION") from None
    table = schema.CONFIGURATIONS
    return _by_id(table, tenant_id, table.c.source_scope_id, scope_id).where(
        table.c.generation == generation, table.c.config_sha256 == digest,
    ).limit(2)


def receipt_lookup(tenant_id: UUID, receipt_id: UUID) -> Select:
    return _by_id(schema.RECEIPTS, tenant_id, schema.RECEIPTS.c.receipt_id, receipt_id).limit(2)


def _history(table, tenant_id, evidence_id, time_column, identity, limit):
    if type(limit) is not int or not 1 <= limit <= 32:
        raise RegistryError("INVALID_HISTORY_LIMIT")
    return _by_id(table, tenant_id, table.c.evidence_id, evidence_id).order_by(
        time_column.desc(), identity,
    ).limit(limit)


def receipt_history(tenant_id: UUID, evidence_id: UUID, *, limit: int = 32) -> Select:
    table = schema.RECEIPTS
    return _history(table, tenant_id, evidence_id, table.c.collected_at, table.c.receipt_id, limit)


def attestation_lookup(tenant_id: UUID, attestation_id: UUID) -> Select:
    return _by_id(schema.ATTESTATIONS, tenant_id, schema.ATTESTATIONS.c.attestation_id, attestation_id).limit(2)


def attestation_history(tenant_id: UUID, evidence_id: UUID, *, limit: int = 32) -> Select:
    table = schema.ATTESTATIONS
    return _history(table, tenant_id, evidence_id, table.c.verified_at, table.c.attestation_id, limit)


def revocation_lookup(tenant_id: UUID, attestation_id: UUID) -> Select:
    return _by_id(schema.REVOCATIONS, tenant_id, schema.REVOCATIONS.c.attestation_id, attestation_id).limit(2)


def audit_lookup(tenant_id: UUID, sequence: int) -> Select:
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise RegistryError("INVALID_AUDIT_SEQUENCE")
    columns = schema.AUDIT.c
    return select(*(columns[name] for name in _AUDIT_FIELDS)).where(
        columns.tenant_id == _id(tenant_id), columns.sequence_number == sequence,
    ).limit(2)


class LookupStatus(Enum):
    COMPLETE_MATCH = "COMPLETE_MATCH"
    COMPLETE_MISS = "COMPLETE_MISS"
    CONFLICT = "CONFLICT"
    AMBIGUOUS = "AMBIGUOUS"
    UNAVAILABLE = "UNAVAILABLE"
    UNAUTHORIZED = "UNAUTHORIZED"


_T = TypeVar("_T")


@dataclass(frozen=True)
class Lookup(Generic[_T]):
    """A protected lookup adapter must establish completeness before construction."""

    status: LookupStatus
    value: _T | None = None

    def __post_init__(self):
        if type(self.status) is not LookupStatus or ((self.status is LookupStatus.COMPLETE_MATCH)
                                                      != (self.value is not None)):
            raise RegistryError("INVALID_LOOKUP_STATE")


def _match(lookup):
    if type(lookup) is not Lookup or lookup.status is not LookupStatus.COMPLETE_MATCH:
        raise RegistryError("INCOMPLETE_STATE")
    return lookup.value


def _fields(row: Mapping[str, object], names) -> dict:
    if (not isinstance(row, Mapping) or len(row) != len(names)
            or frozenset(row.keys()) != frozenset(names)):
        raise RegistryError("INVALID_ROW")
    return dict(row)


class ConfigurationRow(sv.SourceConfiguration):
    collector_build: _Label
    approved_index_uuids: tuple[sv._IndexUUID, ...] = Field(min_length=1, max_length=64)
    approval_id: _ID
    activated_at: _UTC
    audit_sequence: _Sequence

    @field_validator("approved_index_uuids")
    @classmethod
    def check_index_set(cls, indices):
        if len(set(indices)) != len(indices):
            raise ValueError("duplicate_index_uuid")
        return indices


def reconstruct_configuration(row: Mapping[str, object], *, tenant_id: UUID,
                              source_scope_id: UUID, integration_id: UUID) -> ConfigurationRow:
    try:
        fields = _fields(row, schema.CONFIGURATIONS.c.keys())
        indices = fields["approved_index_uuids"]
        if type(indices) is not dict or not 1 <= len(indices) <= 64 or any(v is not True for v in indices.values()):
            raise ValueError()
        fields["approved_index_uuids"] = tuple(indices)
        configuration = ConfigurationRow.model_validate(fields)
        if sv._source(configuration) != (_id(tenant_id), _id(source_scope_id), _id(integration_id)):
            raise ValueError()
        return configuration
    except ValueError:
        raise RegistryError("INVALID_CONFIGURATION") from None


class ReceiptRow(_Contract):
    record: sv.SourceCollectionReceipt
    receipt_sha256: Digest
    audit_sequence: _Sequence


class AttestationRow(_Contract):
    record: sv.SourceVerificationAttestation
    attestation_sha256: Digest
    request_sha256: Digest
    retrieval_attempt_id: _ID
    retrieval_attempt_sha256: Digest
    audit_sequence: _Sequence


def reconstruct_locator(*, installation_id: UUID, index_uuid: str, document_id: str,
                        event_revision: int | None, locator_schema_version: str) -> sv.ProtectedEventLocator:
    try:
        return sv.ProtectedEventLocator(
            installation_id=installation_id, index_uuid=index_uuid, document_id=document_id,
            event_revision=event_revision, schema_version=locator_schema_version,
        )
    except ValueError:
        raise RegistryError("INVALID_LOCATOR") from None


def _check_configuration(record, configuration):
    if (sv._source(record) != sv._source(configuration)
            or (record.generation, record.config_sha256) != (configuration.generation, configuration.config_sha256)):
        raise RegistryError("CONFIGURATION_MISMATCH")


def _check_receipt(row, evidence, configuration):
    record = sv._check_receipt(row.record)
    _check_configuration(record, configuration)
    if (sv._evidence(record) != sv._evidence(evidence)
            or record.locator.installation_id != configuration.installation_id
            or record.locator.index_uuid not in configuration.approved_index_uuids
            or record.collected_at < configuration.activated_at
            or row.audit_sequence <= configuration.audit_sequence
            or (record.collector_principal_id, record.collector_scope_id)
            != (configuration.collector_principal_id, configuration.collector_scope_id)
            or not hmac.compare_digest(row.receipt_sha256, sv.receipt_digest(record))):
        raise RegistryError("RECEIPT_BINDING_MISMATCH")


def reconstruct_receipt(row: Mapping[str, object], *, evidence: EvidenceBinding,
                        configuration: ConfigurationRow) -> ReceiptRow:
    try:
        fields = _fields(row, tuple(key for key in schema.RECEIPTS.c.keys() if key != "locator_revision_key"))
        locator_fields = ("installation_id", "index_uuid", "document_id", "event_revision", "locator_schema_version")
        locator = reconstruct_locator(**{key: fields.pop(key) for key in locator_fields})
        digest, sequence = fields.pop("receipt_sha256"), fields.pop("audit_sequence")
        record = sv.SourceCollectionReceipt.model_validate(dict(fields, locator=locator))
        receipt = ReceiptRow(record=record, receipt_sha256=digest, audit_sequence=sequence)
        _check_receipt(receipt, _checked(evidence, EvidenceBinding), _checked(configuration, ConfigurationRow))
        return receipt
    except (ValueError, TypeError):
        raise RegistryError("INVALID_RECEIPT") from None


def _verification_request_digest(record):
    request = sv.VerificationRequest.model_validate(record.model_dump(include=set(sv.VerificationRequest.model_fields)))
    return sv.request_digest(
        TrustedContext(tenant_id=record.tenant_id, principal_id=record.requester_principal_id), request,
    )


def _check_attestation(attestation, receipt, configuration):
    record, received = attestation.record, receipt.record
    _check_configuration(record, configuration)
    if (sv._evidence(record) != sv._evidence(received)
            or (record.receipt_id, record.receipt_sha256, record.origin_sha256, record.collector_principal_id)
            != (received.receipt_id, receipt.receipt_sha256, received.origin_sha256, received.collector_principal_id)
            or not hmac.compare_digest(attestation.attestation_sha256, sv.attestation_digest(record))
            or not hmac.compare_digest(attestation.request_sha256, _verification_request_digest(record))):
        raise RegistryError("ATTESTATION_BINDING_MISMATCH")


def reconstruct_attestation(row: Mapping[str, object], *, receipt: ReceiptRow, evidence: EvidenceBinding,
                            configuration: ConfigurationRow) -> AttestationRow:
    try:
        fields = _fields(row, schema.ATTESTATIONS.c.keys())
        extras = {key: fields.pop(key) for key in AttestationRow.model_fields if key not in ("record", "schema_version")}
        attestation = AttestationRow(record=sv.SourceVerificationAttestation.model_validate(fields), **extras)
        receipt = _checked(receipt, ReceiptRow)
        configuration = _checked(configuration, ConfigurationRow)
        _check_receipt(receipt, _checked(evidence, EvidenceBinding), configuration)
        _check_attestation(attestation, receipt, configuration)
        return attestation
    except (ValueError, TypeError):
        raise RegistryError("INVALID_ATTESTATION") from None


class RevocationRow(_Contract):
    tenant_id: _ID
    attestation_id: _ID
    revoker_principal_id: _ID
    request_id: _ID
    request_sha256: Digest
    revoked_at: _UTC
    reason_code: Annotated[str, Field(max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")]
    audit_sequence: _Sequence


def reconstruct_revocation(row: Mapping[str, object], *, tenant_id: UUID, attestation_id: UUID) -> RevocationRow:
    try:
        record = RevocationRow.model_validate(_fields(row, schema.REVOCATIONS.c.keys()))
        if (record.tenant_id, record.attestation_id) != (_id(tenant_id), _id(attestation_id)):
            raise ValueError()
        return record
    except ValueError:
        raise RegistryError("INVALID_REVOCATION") from None


class SuspensionRow(sv.ScopeState):
    suspended_at: _UTC | None
    suspension_audit_sequence: _Sequence | None


def reconstruct_suspension(row: Mapping[str, object], *, tenant_id: UUID, source_scope_id: UUID,
                           integration_id: UUID) -> SuspensionRow:
    fields = _fields(row, ("tenant_id", "source_scope_id", "integration_id",
                           "suspended_at", "suspension_audit_sequence"))
    try:
        if (fields["suspended_at"] is None) != (fields["suspension_audit_sequence"] is None):
            raise ValueError()
        result = SuspensionRow(**fields, suspended=fields["suspended_at"] is not None)
        if sv._source(result) != (_id(tenant_id), _id(source_scope_id), _id(integration_id)):
            raise ValueError()
        return result
    except ValueError:
        raise RegistryError("INVALID_SUSPENSION") from None


def suspension_lookup(tenant_id: UUID, scope_id: UUID) -> Select:
    columns = schema.SCOPES.c
    return scope_lookup(tenant_id, scope_id).with_only_columns(
        columns.tenant_id, columns.source_scope_id, columns.integration_id,
        columns.suspended_at, columns.suspension_audit_sequence,
    )


class AuditLink(_Contract):
    tenant_id: _ID
    sequence_number: _Sequence
    action: Literal["source_authority.receipt", "source_authority.attest"]
    actor_type: Literal["service"]
    actor_id: _ID
    resource_type: Literal["source_collection_receipt", "source_verification_attestation"]
    resource_id: _ID
    record_sha256: Digest
    request_sha256: Digest
    retrieval_attempt_sha256: Digest | None


_AUDIT_FIELDS = ("tenant_id", "sequence_number", "action", "actor_type", "actor_id", "resource_type",
                 "resource_id", "details")


def reconstruct_audit_link(row: Mapping[str, object]) -> AuditLink:
    try:
        fields = _fields(row, _AUDIT_FIELDS)
        details = _fields(fields.pop("details"), ("record_sha256", "request_sha256", "retrieval_attempt_sha256"))
        return AuditLink.model_validate(fields | details)
    except ValueError:
        raise RegistryError("INVALID_AUDIT_LINK") from None


def validate_audit_link(row: ReceiptRow | AttestationRow, lookup: Lookup[AuditLink]) -> bool:
    """Validate one complete projected link. It does not verify the hash chain."""
    try:
        event = _checked(_match(lookup), AuditLink)
        if type(row) is ReceiptRow:
            row = _checked(row, ReceiptRow)
            record = sv._check_receipt(row.record)
            if not hmac.compare_digest(row.receipt_sha256, sv.receipt_digest(record)):
                return False
            expected = ("source_authority.receipt", "source_collection_receipt", record.receipt_id,
                        record.collector_principal_id, row.receipt_sha256, record.request_sha256, None)
        else:
            row = _checked(row, AttestationRow)
            record = row.record
            if (not hmac.compare_digest(row.attestation_sha256, sv.attestation_digest(record))
                    or not hmac.compare_digest(row.request_sha256, _verification_request_digest(record))):
                return False
            expected = ("source_authority.attest", "source_verification_attestation", record.attestation_id,
                        record.attestor_principal_id, row.attestation_sha256, row.request_sha256,
                        row.retrieval_attempt_sha256)
    except ValueError:
        return False
    return (
        (event.tenant_id, event.sequence_number) == (record.tenant_id, row.audit_sequence)
        and (event.action, event.resource_type, event.resource_id, event.actor_id, event.record_sha256,
             event.request_sha256, event.retrieval_attempt_sha256) == expected
    )


@dataclass(frozen=True)
class GlobalOriginObservation:
    """Future protected global lookup outcome; no query builder produces this."""

    origin_sha256: str
    result: Lookup[ReceiptRow]


class ReplayResult(Enum):
    NEW = "NEW"
    EXACT_RETRY = "EXACT_RETRY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


def classify_origin(candidate: sv.SourceCollectionReceipt, observation: GlobalOriginObservation,
                    *, configuration: ConfigurationRow, collector: sv.AuthenticatedCollector,
                    latest_generation: int) -> ReplayResult:
    """Assess the supplied global state; never reserve an origin or return a receipt."""
    try:
        candidate = sv._check_receipt(candidate)
        configuration = _checked(configuration, ConfigurationRow)
        collector = _checked(collector, sv.AuthenticatedCollector)
        _check_configuration(candidate, configuration)
        if (type(observation) is not GlobalOriginObservation or type(observation.result) is not Lookup
                or observation.origin_sha256 != candidate.origin_sha256
                or type(latest_generation) is not int or latest_generation != configuration.generation
                or not configuration.active or sv._source(collector) != sv._source(configuration)
                or collector.generation != latest_generation
                or (collector.principal_id, collector.collector_scope_id, collector.database_login,
                    collector.credential_epoch_id)
                != (configuration.collector_principal_id, configuration.collector_scope_id,
                    configuration.collector_database_login, configuration.credential_epoch_id)
                or (candidate.collector_principal_id, candidate.collector_scope_id)
                != (collector.principal_id, collector.collector_scope_id)
                or candidate.locator.installation_id != configuration.installation_id
                or candidate.locator.index_uuid not in configuration.approved_index_uuids):
            return ReplayResult.UNKNOWN
        if observation.result.status is LookupStatus.COMPLETE_MISS:
            return ReplayResult.NEW
        if observation.result.status is LookupStatus.CONFLICT:
            return ReplayResult.CONFLICT
        previous = _checked(_match(observation.result), ReceiptRow)
        stored = sv._check_receipt(previous.record)
        if (stored.origin_sha256 != candidate.origin_sha256
                or not hmac.compare_digest(previous.receipt_sha256, sv.receipt_digest(stored))):
            return ReplayResult.UNKNOWN
    except ValueError:
        return ReplayResult.UNKNOWN
    if (sv._evidence(candidate), sv._source(candidate), candidate.locator,
            candidate.collector_principal_id, candidate.collector_scope_id) != (
            sv._evidence(stored), sv._source(stored), stored.locator,
            stored.collector_principal_id, stored.collector_scope_id):
        return ReplayResult.CONFLICT
    if sv.classify_replay(candidate, (stored,), latest_generation=latest_generation) is sv.ReplayResult.EXACT_RETRY:
        return ReplayResult.EXACT_RETRY
    if candidate.request_id == stored.request_id:
        return ReplayResult.CONFLICT
    return ReplayResult.REVIEW_REQUIRED


class RetrievalAttempt(_Contract):
    """Inert transcript binding. A future authenticated collector cannot supply it."""

    attempt_id: _ID
    attestor: sv.AuthenticatedAttestor
    credential_epoch_id: _ID
    result: sv.IndependentRetrievalResult
    result_sha256: Digest
    started_at: _UTC
    completed_at: _UTC
    request_sha256: Digest


def retrieval_result_digest(result: sv.IndependentRetrievalResult) -> str:
    result = _checked(result, sv.IndependentRetrievalResult)
    return hashlib.sha256(sv._canonical({
        "domain": "ai-soc-team.source-retrieval-result", **result.model_dump(mode="json"),
    })).hexdigest()


def retrieval_attempt_digest(attempt: RetrievalAttempt) -> str:
    attempt = _checked(attempt, RetrievalAttempt)
    fields = attempt.model_dump(mode="json")
    for key in ("started_at", "completed_at"):
        fields[key] = getattr(attempt, key).isoformat(timespec="microseconds")
    return hashlib.sha256(sv._canonical({"domain": "ai-soc-team.source-retrieval-attempt", **fields})).hexdigest()


class LifetimePolicy(_Contract):
    tenant_id: _ID
    source_scope_id: _ID
    policy_id: _Label
    generation: _Generation
    config_sha256: Digest
    max_lifetime_seconds: _Duration
    max_retrieval_age_seconds: _Duration


@dataclass(frozen=True)
class RevocationObservation:
    """Complete absence is meaningful only for this exact tenant and attestation."""

    tenant_id: UUID
    attestation_id: UUID
    result: Lookup[RevocationRow]


@dataclass(frozen=True)
class CurrentState:
    receipt: Lookup[ReceiptRow]
    attestation: Lookup[AttestationRow]
    configuration: Lookup[ConfigurationRow]
    suspension: Lookup[SuspensionRow]
    revocation: RevocationObservation
    receipt_audit: Lookup[AuditLink]
    attestation_audit: Lookup[AuditLink]


@dataclass(frozen=True)
class CurrentResult:
    valid: bool
    reason: str


def evaluate_current(
    state: CurrentState, *, evidence: EvidenceBinding, collector: sv.AuthenticatedCollector,
    attestor: sv.AuthenticatedAttestor, attestor_epoch_id: UUID, attempt: RetrievalAttempt,
    policy: LifetimePolicy, latest_generation: int, at: datetime,
) -> CurrentResult:
    """Point-in-time offline consistency only. Provenance/freshness remain external."""
    if type(state) is not CurrentState:
        return CurrentResult(False, "INCOMPLETE_STATE")
    try:
        receipt = _checked(_match(state.receipt), ReceiptRow)
        attestation = _checked(_match(state.attestation), AttestationRow)
        config = _checked(_match(state.configuration), ConfigurationRow)
        suspension = _checked(_match(state.suspension), SuspensionRow)
        observation = state.revocation
        if (type(observation) is not RevocationObservation
                or (_id(observation.tenant_id), _id(observation.attestation_id))
                != (attestation.record.tenant_id, attestation.record.attestation_id)
                or type(observation.result) is not Lookup):
            raise RegistryError("INCOMPLETE_STATE")
        if observation.result.status not in (
            LookupStatus.COMPLETE_MATCH, LookupStatus.COMPLETE_MISS,
        ):
            raise RegistryError("INCOMPLETE_STATE")
        revoked = observation.result.status is LookupStatus.COMPLETE_MATCH
        if revoked:
            revocation = _checked(observation.result.value, RevocationRow)
            if (revocation.tenant_id, revocation.attestation_id) != (
                attestation.record.tenant_id, attestation.record.attestation_id,
            ):
                raise RegistryError("INCOMPLETE_STATE")
        if (suspension.suspended != (suspension.suspended_at is not None)
                or suspension.suspended != (suspension.suspension_audit_sequence is not None)):
            raise RegistryError("INCOMPLETE_STATE")
    except ValueError:
        return CurrentResult(False, "INCOMPLETE_STATE")

    if (receipt.audit_sequence >= attestation.audit_sequence
            or not validate_audit_link(receipt, state.receipt_audit)
            or not validate_audit_link(attestation, state.attestation_audit)):
        return CurrentResult(False, "AUDIT_LINK_MISMATCH")
    try:
        evidence = _checked(evidence, EvidenceBinding)
        if type(latest_generation) is not int or latest_generation != config.generation or not config.active:
            return CurrentResult(False, "CONFIGURATION_INACTIVE")
        _check_receipt(receipt, evidence, config)
        _check_attestation(attestation, receipt, config)
        policy = _checked(policy, LifetimePolicy)
        attempt = _checked(attempt, RetrievalAttempt)
        attestor = _checked(attestor, sv.AuthenticatedAttestor)
        at = sv._utc(at)
    except (ValueError, OverflowError):
        return CurrentResult(False, "INVALID_PERSISTENCE_STATE")

    record = attestation.record
    if ((policy.tenant_id, policy.source_scope_id, policy.generation, policy.config_sha256)
            != (config.tenant_id, config.source_scope_id, config.generation, config.config_sha256)
            or record.expires_at - record.verified_at > timedelta(seconds=policy.max_lifetime_seconds)):
        return CurrentResult(False, "LIFETIME_POLICY_DENIED")
    if (attempt.attempt_id != attestation.retrieval_attempt_id
            or attempt.attestor != attestor or attempt.credential_epoch_id != attestor_epoch_id
            or attempt.request_sha256 != attestation.request_sha256
            or not hmac.compare_digest(attempt.result_sha256, retrieval_result_digest(attempt.result))
            or not receipt.record.collected_at <= attempt.started_at <= attempt.completed_at <= record.verified_at
            or record.verified_at - attempt.completed_at > timedelta(seconds=policy.max_retrieval_age_seconds)
            or not hmac.compare_digest(attestation.retrieval_attempt_sha256, retrieval_attempt_digest(attempt))):
        return CurrentResult(False, "RETRIEVAL_PROVENANCE_MISMATCH")

    result = sv.evaluate_source_verification(
        evidence=evidence, receipt=receipt.record, receipt_sha256=receipt.receipt_sha256, attestation=record,
        collector=collector, attestor=attestor,
        configuration=sv.SourceConfiguration.model_validate(config.model_dump(include=set(sv.SourceConfiguration.model_fields))),
        latest_generation=latest_generation, retrieval=attempt.result,
        scope_state=sv.ScopeState(tenant_id=suspension.tenant_id, source_scope_id=suspension.source_scope_id,
                                  integration_id=suspension.integration_id, suspended=suspension.suspended),
        attestation_state=sv.AttestationState(
            tenant_id=record.tenant_id, source_scope_id=record.source_scope_id, integration_id=record.integration_id,
            attestation_id=record.attestation_id, attestation_sha256=attestation.attestation_sha256, revoked=revoked,
        ), at=at,
    )
    return CurrentResult(result.valid, result.reason)
