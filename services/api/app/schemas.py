
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    created_at: datetime


class EvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: Literal[
        "observation",
        "interpretation",
        "conclusion",
    ]

    source_type: str = Field(min_length=1, max_length=100)
    source_reference: str = Field(min_length=1, max_length=500)

    event_time: datetime | None = None

    payload: dict[str, Any]

    @field_validator("source_type", "source_reference")
    @classmethod
    def validate_nonempty_strings(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Field cannot contain only whitespace")

        return value

    @field_validator("event_time")
    @classmethod
    def validate_event_time(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(
                    "event_time must include a timezone"
                )

        return value


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_type: str
    source_type: str
    source_reference: str
    event_time: datetime | None
    collected_at: datetime
    collector_name: str
    collector_version: str
    trust_level: str
    schema_version: str
    payload: dict[str, Any]
    content_sha256: str
    created_at: datetime


class EvidenceListResponse(BaseModel):
    items: list[EvidenceResponse]
    total: int
    limit: int
    offset: int


class EvidenceIntegrityResponse(BaseModel):
    evidence_id: UUID
    integrity_valid: bool
    stored_sha256: str
    calculated_sha256: str
    verified_at: datetime


class EvidenceLineageCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    child_evidence_id: UUID

    relationship_type: Literal[
        "derived_from",
        "supports",
        "contradicts",
        "references",
    ]


class EvidenceLineageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    parent_evidence_id: UUID
    child_evidence_id: UUID
    relationship_type: str
    created_at: datetime


class EvidenceLineageListResponse(BaseModel):
    items: list[EvidenceLineageResponse]
    total: int


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_type: str
    actor_id: UUID | None
    action: str
    resource_type: str
    resource_id: UUID | None
    details: dict[str, Any]
    created_at: datetime


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    limit: int
    offset: int

class AuditIntegrityResponse(BaseModel):
    valid: bool
    total: int
    checked: int
    first_invalid_sequence: int | None
    failure_reason: str | None
    verified_at: datetime

class WazuhIntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    base_url: str
    is_active: bool
    created_at: datetime


class WazuhIntegrationListResponse(BaseModel):
    items: list[WazuhIntegrationResponse]
    total: int


class WazuhIngestionResponse(BaseModel):
    integration_id: UUID
    requested: int
    fetched: int
    imported: int
    duplicates: int
    total_available: int
    offset: int


class WazuhSyncResponse(BaseModel):
    integration_id: UUID
    status: Literal['completed', 'not_due']
    fetched: int
    imported: int
    duplicates: int
    pages: int


WazuhSyncSafeErrorCode = Literal[
    'indexer_unavailable', 'invalid_response', 'snapshot_expired',
    'source_changed', 'retention_gap', 'identity_conflict', 'processing_failed',
    'configuration_unavailable', 'authorization_revoked', 'scope_mismatch',
    'lease_lost', 'stale_generation',
]


class WazuhSyncStatusResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    integration_id: UUID
    integration_active: bool
    checkpoint_status: Literal['uninitialized', 'idle', 'syncing', 'error', 'gap']
    completed_window_end_ms: int | None = Field(default=None, ge=0)
    generation: int = Field(ge=0)
    imported_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    has_committed_cursor: bool
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    last_finished_at: datetime | None
    last_attempt_outcome: Literal['running', 'succeeded', 'failed', 'not_due', 'interrupted'] | None
    safe_error_code: WazuhSyncSafeErrorCode | None
    sync_lock_active: bool
