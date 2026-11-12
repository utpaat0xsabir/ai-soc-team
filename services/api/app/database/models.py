import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
    Boolean,
    text,
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
        Index(
            "uq_evidence_wazuh_source_reference",
            "tenant_id",
            "source_reference",
            unique=True,
            postgresql_where=text("source_type = 'wazuh'"),
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
class TenantAPIKey(Base):
    __tablename__ = "tenant_api_keys"

    __table_args__ = (
        UniqueConstraint(
            "key_hash",
            name="uq_tenant_api_keys_key_hash",
        ),
        Index(
            "ix_tenant_api_keys_tenant",
            "tenant_id",
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

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    key_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    __table_args__ = (
        Index(
            "ix_audit_logs_tenant_created",
            "tenant_id",
            "created_at",
        ),
        Index(
            "ix_audit_logs_tenant_action",
            "tenant_id",
            "action",
        ),
        CheckConstraint(
            "actor_type IN ('api_key', 'service', 'system')",
            name="ck_audit_actor_type",
        ),
        CheckConstraint(
            "length(action) > 0",
            name="ck_audit_action_not_empty",
        ),
        CheckConstraint(
            "length(resource_type) > 0",
            name="ck_audit_resource_type_not_empty",
        ),
                UniqueConstraint(
            "tenant_id",
            "sequence_number",
            name="uq_audit_tenant_sequence",
        ),
        CheckConstraint(
            "sequence_number > 0",
            name="ck_audit_sequence_positive",
        ),
        CheckConstraint(
            "length(entry_hash) = 64",
            name="ck_audit_entry_hash_length",
        ),
        CheckConstraint(
            "previous_hash IS NULL OR length(previous_hash) = 64",
            name="ck_audit_previous_hash_length",
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
    sequence_number: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    previous_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    entry_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    actor_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class WazuhIntegration(Base):
    __tablename__ = "wazuh_integrations"

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "id", name="uq_wazuh_integrations_tenant_id_id",
        ),
        UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_wazuh_integrations_tenant_name",
        ),
        CheckConstraint(
            "length(name) > 0",
            name="ck_wazuh_integration_name_not_empty",
        ),
        CheckConstraint(
            "base_url LIKE 'https://%'",
            name="ck_wazuh_integration_https",
        ),
        CheckConstraint(
            "length(username) > 0",
            name="ck_wazuh_integration_username_not_empty",
        ),
        CheckConstraint(
            "length(credential_reference) > 0",
            name="ck_wazuh_integration_credential_reference",
        ),
        Index(
            "ix_wazuh_integrations_tenant",
            "tenant_id",
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

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    base_url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    username: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    credential_reference: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    ca_certificate_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class WazuhSyncCheckpoint(Base):
    """Internal progress only; credentials and raw PIT IDs are never stored.

    Ownership is enforced by the composite FK. All reads still require a tenant
    predicate. Generation fencing/monotonic advancement belong to the ingestion
    transaction introduced in later phases, not arbitrary ORM updates.
    """

    __tablename__ = "wazuh_sync_checkpoints"
    __table_args__ = (
        CheckConstraint(
            "scope_fingerprint IS NULL OR scope_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_wazuh_checkpoint_scope_fingerprint",
        ),
        CheckConstraint(
            "(scope_fingerprint IS NULL) = (source_manifest IS NULL) AND "
            "(source_manifest IS NULL OR (jsonb_typeof(source_manifest) = 'object' "
            "AND source_manifest <> '{}'::jsonb AND octet_length(source_manifest::text) <= 65536))",
            name="ck_wazuh_checkpoint_source_manifest",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "integration_id"],
            ["wazuh_integrations.tenant_id", "wazuh_integrations.id"],
            ondelete="RESTRICT", onupdate="RESTRICT",
            name="fk_wazuh_checkpoint_integration_tenant",
        ),
        Index("ix_wazuh_checkpoints_tenant", "tenant_id"),
        CheckConstraint(
            "status IN ('uninitialized', 'idle', 'syncing', 'error', 'gap')",
            name="ck_wazuh_checkpoint_status",
        ),
        CheckConstraint(
            "generation >= 0 AND imported_count >= 0 AND duplicate_count >= 0",
            name="ck_wazuh_checkpoint_counters",
        ),
        CheckConstraint("cursor_version = 1", name="ck_wazuh_checkpoint_cursor_version"),
        CheckConstraint(
            "completed_window_end_ms IS NULL OR "
            "completed_window_end_ms BETWEEN 0 AND 253402300799999",
            name="ck_wazuh_checkpoint_completed_bounds",
        ),
        CheckConstraint(
            "query_fingerprint IS NULL OR query_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_wazuh_checkpoint_fingerprint",
        ),
        CheckConstraint(
            "safe_error_code IS NULL OR safe_error_code IN "
            "('indexer_timeout', 'indexer_unavailable', 'invalid_response', "
            "'snapshot_expired', 'source_changed', 'retention_gap', "
            "'identity_conflict', 'processing_failed')",
            name="ck_wazuh_checkpoint_safe_error",
        ),
        CheckConstraint(
            "num_nonnulls(window_start_ms, window_end_ms, snapshot_id, index_manifest) IN (0, 4)",
            name="ck_wazuh_checkpoint_active_fields",
        ),
        CheckConstraint(
            "window_start_ms IS NULL OR "
            "(window_start_ms >= 0 AND window_end_ms <= 253402300799999 "
            "AND window_start_ms < window_end_ms AND query_fingerprint IS NOT NULL)",
            name="ck_wazuh_checkpoint_window",
        ),
        CheckConstraint(
            "completed_window_end_ms IS NULL OR query_fingerprint IS NOT NULL",
            name="ck_wazuh_checkpoint_completed_scope",
        ),
        CheckConstraint(
            "index_manifest IS NULL OR (jsonb_typeof(index_manifest) = 'object' "
            "AND index_manifest <> '{}'::jsonb "
            "AND octet_length(index_manifest::text) <= 65536)",
            name="ck_wazuh_checkpoint_manifest",
        ),
        CheckConstraint(
            "(status <> 'uninitialized' OR (completed_window_end_ms IS NULL "
            "AND window_start_ms IS NULL AND query_fingerprint IS NULL "
            "AND last_success_at IS NULL AND imported_count = 0 AND duplicate_count = 0)) "
            "AND (status <> 'idle' OR (completed_window_end_ms IS NOT NULL AND window_start_ms IS NULL)) "
            "AND (status <> 'syncing' OR window_start_ms IS NOT NULL)",
            name="ck_wazuh_checkpoint_state",
        ),
        CheckConstraint(
            "CASE WHEN cursor_sort IS NULL THEN TRUE "
            "WHEN window_start_ms IS NULL THEN FALSE "
            "WHEN jsonb_typeof(cursor_sort) <> 'array' THEN FALSE "
            "ELSE (jsonb_array_length(cursor_sort) = 3 "
            "AND jsonb_typeof(cursor_sort->0) = 'number' "
            "AND CASE WHEN cursor_sort->>0 ~ '^[0-9]{1,15}$' "
            "THEN (cursor_sort->>0)::bigint >= window_start_ms "
            "AND (cursor_sort->>0)::bigint < window_end_ms ELSE FALSE END "
            "AND jsonb_typeof(cursor_sort->1) = 'string' "
            "AND jsonb_typeof(cursor_sort->2) = 'string' "
            "AND octet_length(cursor_sort->>1) BETWEEN 1 AND 512 "
            "AND octet_length(cursor_sort->>2) BETWEEN 1 AND 512 "
            "AND length(btrim(cursor_sort->>1)) > 0 "
            "AND length(btrim(cursor_sort->>2)) > 0 "
            "AND cursor_sort->>1 !~ '[[:cntrl:]]' "
            "AND cursor_sort->>2 !~ '[[:cntrl:]]') END IS TRUE",
            name="ck_wazuh_checkpoint_cursor_sort",
        ),
    )

    integration_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="uninitialized")
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    cursor_version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    completed_window_end_ms: Mapped[int | None] = mapped_column(BigInteger)
    window_start_ms: Mapped[int | None] = mapped_column(BigInteger)
    window_end_ms: Mapped[int | None] = mapped_column(BigInteger)
    query_fingerprint: Mapped[str | None] = mapped_column(String(64))
    scope_fingerprint: Mapped[str | None] = mapped_column(String(64))
    source_manifest: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    index_manifest: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    cursor_sort: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    safe_error_code: Mapped[str | None] = mapped_column(String(32))
    imported_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    duplicate_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )


class WazuhSyncLease(Base):
    """One fenced, expiring owner per tenant integration; no credentials."""

    __tablename__ = "wazuh_sync_leases"
    __table_args__ = (
        ForeignKeyConstraint(
            ['tenant_id', 'integration_id'],
            ['wazuh_integrations.tenant_id', 'wazuh_integrations.id'],
            name='fk_wazuh_lease_integration_tenant', ondelete='RESTRICT', onupdate='RESTRICT',
        ),
        CheckConstraint('fence > 0', name='ck_wazuh_lease_fence'),
        CheckConstraint('(owner_token IS NULL) = (expires_at IS NULL)', name='ck_wazuh_lease_owner'),
        CheckConstraint(
            "safe_error_code IS NULL OR safe_error_code IN "
            "('indexer_unavailable', 'invalid_response', 'snapshot_expired', 'source_changed', "
            "'retention_gap', 'identity_conflict', 'processing_failed', 'configuration_unavailable', "
            "'authorization_revoked', 'scope_mismatch', 'lease_lost', 'stale_generation')",
            name='ck_wazuh_lease_safe_error',
        ),
        CheckConstraint(
            "(last_attempt_at IS NULL AND last_finished_at IS NULL AND last_outcome IS NULL AND safe_error_code IS NULL) OR "
            "(last_attempt_at IS NOT NULL AND last_outcome IS NOT NULL AND ("
            "(last_outcome = 'running' AND last_finished_at IS NULL AND safe_error_code IS NULL) OR "
            "(last_outcome IN ('succeeded', 'not_due') AND last_finished_at IS NOT NULL AND safe_error_code IS NULL) OR "
            "(last_outcome IN ('failed', 'interrupted') AND last_finished_at IS NOT NULL AND safe_error_code IS NOT NULL)))",
            name='ck_wazuh_lease_attempt_state',
        ),
        CheckConstraint(
            'last_finished_at IS NULL OR last_finished_at >= last_attempt_at',
            name='ck_wazuh_lease_attempt_times',
        ),
        Index('ix_wazuh_leases_tenant', 'tenant_id'),
    )

    integration_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    owner_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    fence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_outcome: Mapped[str | None] = mapped_column(String(16))
    safe_error_code: Mapped[str | None] = mapped_column(String(32))
