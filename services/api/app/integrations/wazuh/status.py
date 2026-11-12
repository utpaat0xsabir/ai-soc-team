"""Allowlisted operational metadata; GET never touches Indexer or writes state."""

from typing import get_args

from sqlalchemy import and_, func, select

from app.database.models import WazuhIntegration, WazuhSyncCheckpoint, WazuhSyncLease
from app.schemas import WazuhSyncSafeErrorCode, WazuhSyncStatusResponse


SAFE_SYNC_ERRORS = frozenset(get_args(WazuhSyncSafeErrorCode))


def safe_sync_error(code: str) -> str:
    """Map exact internal codes; never return arbitrary exceptions or substrings."""
    return {
        'wazuh_sync_indexer_unavailable': 'indexer_unavailable',
        'wazuh_indexer_connection_failed': 'indexer_unavailable',
        'wazuh_indexer_request_failed': 'indexer_unavailable',
        'wazuh_indexer_invalid_response': 'invalid_response',
        'wazuh_indexer_invalid_metadata': 'invalid_response',
        'wazuh_snapshot_expired': 'snapshot_expired',
        'wazuh_sync_source_changed': 'source_changed',
        'wazuh_sync_retention_gap': 'retention_gap',
        'wazuh_sync_identity_conflict': 'identity_conflict',
        'wazuh_sync_configuration_unavailable': 'configuration_unavailable',
        'wazuh_sync_scope_unavailable': 'configuration_unavailable',
        'invalid_api_key': 'authorization_revoked',
        'wazuh_sync_scope_mismatch': 'scope_mismatch',
        'wazuh_sync_lease_lost': 'lease_lost',
        'wazuh_sync_lease_unavailable': 'lease_lost',
        'wazuh_sync_stale_generation': 'stale_generation',
    }.get(code, 'processing_failed')


def read_sync_status(db, tenant_id, integration_id):
    # Explicit projection excludes connection fields, tokens, cursors, manifests,
    # fingerprints and raw errors even before response-model serialization.
    live = and_(WazuhSyncLease.owner_token.is_not(None),
                WazuhSyncLease.expires_at > func.statement_timestamp())
    query = select(
        WazuhIntegration.id.label('integration_id'),
        WazuhIntegration.is_active.label('integration_active'),
        func.coalesce(WazuhSyncCheckpoint.status, 'uninitialized').label('checkpoint_status'),
        WazuhSyncCheckpoint.completed_window_end_ms,
        func.coalesce(WazuhSyncCheckpoint.generation, 0).label('generation'),
        func.coalesce(WazuhSyncCheckpoint.imported_count, 0).label('imported_count'),
        func.coalesce(WazuhSyncCheckpoint.duplicate_count, 0).label('duplicate_count'),
        WazuhSyncCheckpoint.cursor_sort.is_not(None).label('has_committed_cursor'),
        WazuhSyncCheckpoint.last_success_at,
        func.coalesce(WazuhSyncLease.last_attempt_at, WazuhSyncCheckpoint.last_attempt_at).label('last_attempt_at'),
        WazuhSyncLease.last_finished_at,
        WazuhSyncLease.last_outcome.label('last_attempt_outcome'),
        WazuhSyncLease.safe_error_code,
        func.coalesce(live, False).label('sync_lock_active'),
    ).select_from(WazuhIntegration).outerjoin(WazuhSyncCheckpoint, and_(
        WazuhSyncCheckpoint.integration_id == WazuhIntegration.id,
        WazuhSyncCheckpoint.tenant_id == tenant_id,
    )).outerjoin(WazuhSyncLease, and_(
        WazuhSyncLease.integration_id == WazuhIntegration.id,
        WazuhSyncLease.tenant_id == tenant_id,
    )).where(WazuhIntegration.id == integration_id, WazuhIntegration.tenant_id == tenant_id)
    row = db.execute(query).mappings().one_or_none()
    if row is None:
        return None
    data = dict(row)
    if data['last_attempt_outcome'] == 'running' and not data['sync_lock_active']:
        # Expiry proves lack of live ownership, not when the worker actually died.
        data['last_attempt_outcome'] = 'interrupted'
        data['safe_error_code'] = 'lease_lost'
    if data['safe_error_code'] is not None and data['safe_error_code'] not in SAFE_SYNC_ERRORS:
        data['safe_error_code'] = 'processing_failed'
    return WazuhSyncStatusResponse(**data)
