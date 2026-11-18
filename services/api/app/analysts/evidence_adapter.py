"""Tenant-scoped evidence retrieval and synthetic-only admission."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hmac
import json
from typing import Annotated, Literal, NoReturn, Protocol
from uuid import UUID

from pydantic import Field, ValidationError, field_validator

from app.analysts import contracts
from app.evidence.hashing import calculate_evidence_hash
from app.gateway.contracts import TrustedContext, _Contract


RejectionReason = Literal[
    "INVALID_CONTEXT", "INVALID_EVIDENCE_IDS", "EVIDENCE_NOT_FOUND",
    "EVIDENCE_SCOPE_MISMATCH", "INVALID_EVIDENCE", "HASH_MISMATCH",
    "UNSUPPORTED_SOURCE", "UNSUPPORTED_CLASSIFICATION", "UNVERIFIED_EVIDENCE",
    "UNSUPPORTED_TRUST_LEVEL", "EVIDENCE_BUNDLE_TOO_LARGE",
    "UNSAFE_EVIDENCE_SESSION", "EVIDENCE_LOOKUP_FAILED", "STORED_EVIDENCE_NOT_ADMITTED",
]


class EvidenceRejected(ValueError):
    def __init__(self, reason: RejectionReason) -> None:
        self.reason = reason
        super().__init__(reason)


def _checked_context(context: TrustedContext) -> TrustedContext:
    if type(context) is not TrustedContext:
        raise EvidenceRejected("INVALID_CONTEXT")
    try:
        context = TrustedContext.model_validate(context)
    except ValidationError:
        raise EvidenceRejected("INVALID_CONTEXT") from None
    if not context.tenant_id.int or not context.principal_id.int:
        raise EvidenceRejected("INVALID_CONTEXT")
    return context


def _checked_evidence_ids(evidence_ids: tuple[UUID, ...]) -> tuple[UUID, ...]:
    if (type(evidence_ids) is not tuple or not 1 <= len(evidence_ids) <= 32
            or any(type(value) is not UUID or not value.int for value in evidence_ids)
            or len(set(evidence_ids)) != len(evidence_ids)):
        raise EvidenceRejected("INVALID_EVIDENCE_IDS")
    return tuple(sorted(evidence_ids))


@dataclass(frozen=True)
class TrustedEvidenceAdapter:
    """Read preclassified test evidence. Stored observations require classifier authority."""

    records: Mapping[tuple[UUID, UUID], contracts.EvidenceReference]

    def load_bundle(
        self, context: TrustedContext, evidence_ids: tuple[UUID, ...],
    ) -> tuple[contracts.EvidenceReference, ...]:
        context = _checked_context(context)
        evidence_ids = _checked_evidence_ids(evidence_ids)

        bundle = []
        size = 0
        for evidence_id in evidence_ids:
            record = self.records.get((context.tenant_id, evidence_id))
            if record is None:
                raise EvidenceRejected("EVIDENCE_NOT_FOUND")
            if type(record) is not contracts.EvidenceReference:
                raise EvidenceRejected("INVALID_EVIDENCE")
            if (getattr(record, "tenant_id", None) != context.tenant_id
                    or getattr(record, "evidence_id", None) != evidence_id):
                raise EvidenceRejected("EVIDENCE_SCOPE_MISMATCH")
            if getattr(record, "classification", None) != "SYNTHETIC / TEST ONLY":
                raise EvidenceRejected("UNSUPPORTED_CLASSIFICATION")
            if getattr(record, "trust_level", None) == "unverified":
                raise EvidenceRejected("UNVERIFIED_EVIDENCE")
            try:
                contracts._bounded(record)
                reference = contracts.EvidenceReference.model_validate(record)
            except ValidationError as exc:
                for error in exc.errors(include_input=False, include_context=False):
                    if error["type"] == "analyst_evidence_hash_mismatch":
                        raise EvidenceRejected("HASH_MISMATCH") from None
                    if error["loc"] == ("source_type",) and error["type"] == "literal_error":
                        raise EvidenceRejected("UNSUPPORTED_SOURCE") from None
                    if error["loc"] == ("trust_level",) and error["type"] == "literal_error":
                        raise EvidenceRejected("UNSUPPORTED_TRUST_LEVEL") from None
                raise EvidenceRejected("INVALID_EVIDENCE") from None
            except ValueError:
                raise EvidenceRejected("INVALID_EVIDENCE") from None
            size += len(contracts.canonical_bytes(reference))
            if size > contracts.MAX_INPUT_BYTES:
                raise EvidenceRejected("EVIDENCE_BUNDLE_TOO_LARGE")
            bundle.append(reference)
        return tuple(bundle)


class VerifiedStoredEvidence(_Contract):
    """Integrity-checked stored data. The hash supplies no classification or authority."""

    schema_version: Literal["1.0"] = Field()
    evidence_id: UUID
    tenant_id: UUID
    evidence_type: Literal["observation", "interpretation", "conclusion"]
    source_type: Literal["wazuh", "normalized_event", "tool_result", "analyst"]
    source_reference: Annotated[str, Field(min_length=1, max_length=500, pattern=r"\S")]
    collector_name: Annotated[str, Field(min_length=1, max_length=150, pattern=r"\S")]
    collector_version: Annotated[str, Field(min_length=1, max_length=100, pattern=r"\S")]
    trust_level: Literal["unverified", "source_verified", "system_verified"]
    event_time: datetime | None
    collected_at: datetime
    payload_json: str
    content_sha256: contracts.Digest

    _collection_utc = field_validator("collected_at")(contracts._utc)

    @field_validator("evidence_id", "tenant_id")
    @classmethod
    def validate_id(cls, value: UUID) -> UUID:
        if not value.int:
            raise ValueError("invalid_stored_evidence_id")
        return value

    @field_validator("event_time")
    @classmethod
    def validate_event_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else contracts._utc(value)


def validate_stored_evidence(row: Mapping[str, object]) -> VerifiedStoredEvidence:
    values = dict(row)
    payload = values.pop("payload", None)
    if type(payload) is not dict:
        raise EvidenceRejected("INVALID_EVIDENCE")
    try:
        contracts._bounded(payload)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True, allow_nan=False)
        record = VerifiedStoredEvidence.model_validate(dict(values, payload_json=payload_json))
        digest = calculate_evidence_hash(
            evidence_type=record.evidence_type, source_type=record.source_type,
            source_reference=record.source_reference, collector_name=record.collector_name,
            collector_version=record.collector_version, trust_level=record.trust_level,
            event_time=record.event_time, payload=payload,
        )
    except ValidationError as exc:
        for error in exc.errors(include_input=False, include_context=False):
            if error["type"] == "literal_error":
                if error["loc"] == ("source_type",):
                    raise EvidenceRejected("UNSUPPORTED_SOURCE") from None
                if error["loc"] == ("trust_level",):
                    raise EvidenceRejected("UNSUPPORTED_TRUST_LEVEL") from None
        raise EvidenceRejected("INVALID_EVIDENCE") from None
    except (ValueError, TypeError):
        raise EvidenceRejected("INVALID_EVIDENCE") from None
    if not hmac.compare_digest(record.content_sha256, digest):
        raise EvidenceRejected("HASH_MISMATCH")
    return record


class StoredEvidenceRepository(Protocol):
    def load_stored_bundle(
        self, tenant_id: UUID, evidence_ids: tuple[UUID, ...],
    ) -> tuple[VerifiedStoredEvidence, ...]: ...


@dataclass(frozen=True)
class StoredEvidenceAdapter:
    repository: StoredEvidenceRepository

    def load_stored_bundle(
        self, context: TrustedContext, evidence_ids: tuple[UUID, ...],
    ) -> tuple[VerifiedStoredEvidence, ...]:
        context = _checked_context(context)
        return self.repository.load_stored_bundle(context.tenant_id, evidence_ids)

    def load_bundle(self, context: TrustedContext, evidence_ids: tuple[UUID, ...]) -> NoReturn:
        """L1 admission. Storage carries neither classification nor admission authority."""
        records = self.load_stored_bundle(context, evidence_ids)
        if any(record.trust_level == "unverified" for record in records):
            raise EvidenceRejected("UNVERIFIED_EVIDENCE")
        raise EvidenceRejected("STORED_EVIDENCE_NOT_ADMITTED")
