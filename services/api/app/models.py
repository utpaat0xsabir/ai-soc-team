import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_evidence_tenant_id_id",
        ),
        CheckConstraint(
            "evidence_type IN ('observation', 'interpretation', 'conclusion')",
            name="ck_evidence_type",
        ),
        CheckConstraint(
            "trust_level IN ('unverified', 'source_verified', 'system_verified')",
            name="ck_evidence_trust_level",
        ),
        Index(
            "ix_evidence_tenant_collected",
            "tenant_id",
            "collected_at",
        ),
        Index(
            "ix_evidence_tenant_type",
            "tenant_id",
            "evidence_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
    )

    evidence_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    source_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    source_reference: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    collector_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    collector_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    trust_level: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="unverified",
        server_default="unverified",
    )

    schema_version: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="1.0",
        server_default="1.0",
    )

    payload: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    content_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class EvidenceLineage(Base):
    __tablename__ = "evidence_lineage"

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "parent_evidence_id"],
            ["evidence_records.tenant_id", "evidence_records.id"],
            ondelete="RESTRICT",
            name="fk_lineage_parent_same_tenant",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "child_evidence_id"],
            ["evidence_records.tenant_id", "evidence_records.id"],
            ondelete="RESTRICT",
            name="fk_lineage_child_same_tenant",
        ),
        CheckConstraint(
            "parent_evidence_id <> child_evidence_id",
            name="ck_lineage_not_self_referencing",
        ),
        CheckConstraint(
            "relationship_type IN "
            "('derived_from', 'supports', 'contradicts', 'references')",
            name="ck_lineage_relationship_type",
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )

    parent_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )

    child_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )

    relationship_type: Mapped[str] = mapped_column(
        String(30),
        primary_key=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
