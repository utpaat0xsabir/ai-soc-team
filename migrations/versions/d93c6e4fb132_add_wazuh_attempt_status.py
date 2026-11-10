"""Add safe synchronization attempt metadata to lease rows.

Existing outcomes remain unknown; checkpoint progress is untouched.
"""
from alembic import op
import sqlalchemy as sa

revision = 'd93c6e4fb132'
down_revision = 'c82b5d3ea021'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('wazuh_sync_leases', sa.Column('last_attempt_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('wazuh_sync_leases', sa.Column('last_finished_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('wazuh_sync_leases', sa.Column('last_outcome', sa.String(16), nullable=True))
    op.add_column('wazuh_sync_leases', sa.Column('safe_error_code', sa.String(32), nullable=True))
    op.create_check_constraint('ck_wazuh_lease_attempt_state', 'wazuh_sync_leases', "(last_attempt_at IS NULL AND last_finished_at IS NULL AND last_outcome IS NULL AND safe_error_code IS NULL) OR (last_attempt_at IS NOT NULL AND last_outcome IS NOT NULL AND ((last_outcome = 'running' AND last_finished_at IS NULL AND safe_error_code IS NULL) OR (last_outcome IN ('succeeded', 'not_due') AND last_finished_at IS NOT NULL AND safe_error_code IS NULL) OR (last_outcome IN ('failed', 'interrupted') AND last_finished_at IS NOT NULL AND safe_error_code IS NOT NULL)))")
    op.create_check_constraint('ck_wazuh_lease_attempt_times', 'wazuh_sync_leases', 'last_finished_at IS NULL OR last_finished_at >= last_attempt_at')
    op.create_check_constraint('ck_wazuh_lease_safe_error', 'wazuh_sync_leases', "safe_error_code IS NULL OR safe_error_code IN ('indexer_unavailable', 'invalid_response', 'snapshot_expired', 'source_changed', 'retention_gap', 'identity_conflict', 'processing_failed', 'configuration_unavailable', 'authorization_revoked', 'scope_mismatch', 'lease_lost', 'stale_generation')")


def downgrade() -> None:
    raise RuntimeError('sync_status_downgrade_requires_explicit_data_recovery_plan')
