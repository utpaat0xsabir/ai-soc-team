"""Add tenant-owned Wazuh synchronization checkpoints.

Existing integrations remain uninitialized: no evidence-derived backfill.
Production application requires separate approval.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b71a4c2d9e10'
down_revision = '013505dd4ffd'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        'uq_wazuh_integrations_tenant_id_id', 'wazuh_integrations', ['tenant_id', 'id']
    )
    op.create_table('wazuh_sync_checkpoints',
    sa.Column('integration_id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('status', sa.String(length=20), server_default='uninitialized', nullable=False),
    sa.Column('generation', sa.BigInteger(), server_default='0', nullable=False),
    sa.Column('cursor_version', sa.BigInteger(), server_default='1', nullable=False),
    sa.Column('completed_window_end_ms', sa.BigInteger(), nullable=True),
    sa.Column('window_start_ms', sa.BigInteger(), nullable=True),
    sa.Column('window_end_ms', sa.BigInteger(), nullable=True),
    sa.Column('query_fingerprint', sa.String(length=64), nullable=True),
    sa.Column('snapshot_id', sa.UUID(), nullable=True),
    sa.Column('index_manifest', postgresql.JSONB(none_as_null=True), nullable=True),
    sa.Column('cursor_sort', postgresql.JSONB(none_as_null=True), nullable=True),
    sa.Column('last_attempt_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('safe_error_code', sa.String(length=32), nullable=True),
    sa.Column('imported_count', sa.BigInteger(), server_default='0', nullable=False),
    sa.Column('duplicate_count', sa.BigInteger(), server_default='0', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status <> 'uninitialized' OR (completed_window_end_ms IS NULL AND window_start_ms IS NULL AND query_fingerprint IS NULL AND last_success_at IS NULL AND imported_count = 0 AND duplicate_count = 0)) AND (status <> 'idle' OR (completed_window_end_ms IS NOT NULL AND window_start_ms IS NULL)) AND (status <> 'syncing' OR window_start_ms IS NOT NULL)", name='ck_wazuh_checkpoint_state'),
    sa.CheckConstraint("CASE WHEN cursor_sort IS NULL THEN TRUE WHEN window_start_ms IS NULL THEN FALSE WHEN jsonb_typeof(cursor_sort) <> 'array' THEN FALSE ELSE (jsonb_array_length(cursor_sort) = 3 AND jsonb_typeof(cursor_sort->0) = 'number' AND CASE WHEN cursor_sort->>0 ~ '^[0-9]{1,15}$' THEN (cursor_sort->>0)::bigint >= window_start_ms AND (cursor_sort->>0)::bigint < window_end_ms ELSE FALSE END AND jsonb_typeof(cursor_sort->1) = 'string' AND jsonb_typeof(cursor_sort->2) = 'string' AND octet_length(cursor_sort->>1) BETWEEN 1 AND 512 AND octet_length(cursor_sort->>2) BETWEEN 1 AND 512 AND length(btrim(cursor_sort->>1)) > 0 AND length(btrim(cursor_sort->>2)) > 0 AND cursor_sort->>1 !~ '[[:cntrl:]]' AND cursor_sort->>2 !~ '[[:cntrl:]]') END IS TRUE", name='ck_wazuh_checkpoint_cursor_sort'),
    sa.CheckConstraint("index_manifest IS NULL OR (jsonb_typeof(index_manifest) = 'object' AND index_manifest <> '{}'::jsonb AND octet_length(index_manifest::text) <= 65536)", name='ck_wazuh_checkpoint_manifest'),
    sa.CheckConstraint("query_fingerprint IS NULL OR query_fingerprint ~ '^[0-9a-f]{64}$'", name='ck_wazuh_checkpoint_fingerprint'),
    sa.CheckConstraint("safe_error_code IS NULL OR safe_error_code IN ('indexer_timeout', 'indexer_unavailable', 'invalid_response', 'snapshot_expired', 'source_changed', 'retention_gap', 'identity_conflict', 'processing_failed')", name='ck_wazuh_checkpoint_safe_error'),
    sa.CheckConstraint("status IN ('uninitialized', 'idle', 'syncing', 'error', 'gap')", name='ck_wazuh_checkpoint_status'),
    sa.CheckConstraint('completed_window_end_ms IS NULL OR completed_window_end_ms BETWEEN 0 AND 253402300799999', name='ck_wazuh_checkpoint_completed_bounds'),
    sa.CheckConstraint('completed_window_end_ms IS NULL OR query_fingerprint IS NOT NULL', name='ck_wazuh_checkpoint_completed_scope'),
    sa.CheckConstraint('cursor_version = 1', name='ck_wazuh_checkpoint_cursor_version'),
    sa.CheckConstraint('generation >= 0 AND imported_count >= 0 AND duplicate_count >= 0', name='ck_wazuh_checkpoint_counters'),
    sa.CheckConstraint('num_nonnulls(window_start_ms, window_end_ms, snapshot_id, index_manifest) IN (0, 4)', name='ck_wazuh_checkpoint_active_fields'),
    sa.CheckConstraint('window_start_ms IS NULL OR (window_start_ms >= 0 AND window_end_ms <= 253402300799999 AND window_start_ms < window_end_ms AND query_fingerprint IS NOT NULL)', name='ck_wazuh_checkpoint_window'),
    sa.ForeignKeyConstraint(['tenant_id', 'integration_id'], ['wazuh_integrations.tenant_id', 'wazuh_integrations.id'], name='fk_wazuh_checkpoint_integration_tenant', onupdate='RESTRICT', ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('integration_id')
    )
    op.create_index('ix_wazuh_checkpoints_tenant', 'wazuh_sync_checkpoints', ['tenant_id'], unique=False)


def downgrade() -> None:
    # Data-losing downgrade is deliberately guarded; prefer leaving additive
    # storage unused during application rollback. Never execute automatically.
    raise RuntimeError('checkpoint_downgrade_requires_explicit_data_recovery_plan')
