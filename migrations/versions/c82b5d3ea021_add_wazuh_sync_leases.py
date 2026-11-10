"""Add fenced synchronization leases and durable source identity.

No progress is inferred or reset. Existing checkpoints require verified adoption.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'c82b5d3ea021'
down_revision = 'b71a4c2d9e10'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('wazuh_sync_checkpoints', sa.Column('scope_fingerprint', sa.String(64), nullable=True))
    op.add_column('wazuh_sync_checkpoints', sa.Column('source_manifest', postgresql.JSONB(none_as_null=True), nullable=True))
    op.create_check_constraint('ck_wazuh_checkpoint_scope_fingerprint', 'wazuh_sync_checkpoints', "scope_fingerprint IS NULL OR scope_fingerprint ~ '^[0-9a-f]{64}$'")
    op.create_check_constraint('ck_wazuh_checkpoint_source_manifest', 'wazuh_sync_checkpoints', "(scope_fingerprint IS NULL) = (source_manifest IS NULL) AND (source_manifest IS NULL OR (jsonb_typeof(source_manifest) = 'object' AND source_manifest <> '{}'::jsonb AND octet_length(source_manifest::text) <= 65536))")

    op.create_table('wazuh_sync_leases',
    sa.Column('integration_id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('owner_token', sa.UUID(), nullable=True),
    sa.Column('fence', sa.BigInteger(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint('(owner_token IS NULL) = (expires_at IS NULL)', name='ck_wazuh_lease_owner'),
    sa.CheckConstraint('fence > 0', name='ck_wazuh_lease_fence'),
    sa.ForeignKeyConstraint(['tenant_id', 'integration_id'], ['wazuh_integrations.tenant_id', 'wazuh_integrations.id'], name='fk_wazuh_lease_integration_tenant', onupdate='RESTRICT', ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('integration_id')
    )
    op.create_index('ix_wazuh_leases_tenant', 'wazuh_sync_leases', ['tenant_id'], unique=False)


def downgrade() -> None:
    raise RuntimeError('sync_lease_downgrade_requires_explicit_data_recovery_plan')
