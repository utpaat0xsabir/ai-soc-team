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
