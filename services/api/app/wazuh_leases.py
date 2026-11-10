"""PostgreSQL-clock leases. Lock order: integration, lease, checkpoint, tenant."""

from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError

from app.config import settings
from app.models import WazuhIntegration, WazuhSyncLease
from app.wazuh_status import SAFE_SYNC_ERRORS


class WazuhLeaseError(Exception):
    pass


@dataclass(frozen=True)
class LeaseHandle:
    tenant_id: UUID
    integration_id: UUID
    owner_token: UUID
    fence: int


def _integration(db, tenant_id, integration_id, *, nowait=False):
    row = db.scalar(select(WazuhIntegration.id).where(
        WazuhIntegration.id == integration_id, WazuhIntegration.tenant_id == tenant_id,
        WazuhIntegration.is_active.is_(True),
    ).with_for_update(nowait=nowait))
    if row is None:
        raise WazuhLeaseError('wazuh_sync_lease_unavailable')


def claim_lease(db, tenant_id, integration_id) -> LeaseHandle:
    try:
        _integration(db, tenant_id, integration_id, nowait=True)
        row = db.scalar(select(WazuhSyncLease).where(
            WazuhSyncLease.integration_id == integration_id,
            WazuhSyncLease.tenant_id == tenant_id,
        ).with_for_update().execution_options(populate_existing=True))
        now = db.scalar(select(func.clock_timestamp()))
        if row is not None and row.owner_token is not None and row.expires_at > now:
            raise WazuhLeaseError('wazuh_sync_busy')
        if row is None:
            row = WazuhSyncLease(integration_id=integration_id, tenant_id=tenant_id, fence=1)
            db.add(row)
        else:
            row.fence += 1
        row.owner_token = uuid4()
        row.expires_at = now + timedelta(seconds=settings.wazuh_sync_lease_seconds)
        row.last_attempt_at = now
        row.last_finished_at = None
        row.last_outcome = 'running'
        row.safe_error_code = None
        handle = LeaseHandle(tenant_id, integration_id, row.owner_token, row.fence)
        db.commit()
        return handle
    except DBAPIError as exc:
        db.rollback()
        if getattr(exc.orig, 'sqlstate', None) == '55P03':
            raise WazuhLeaseError('wazuh_sync_busy') from None
        raise
    except BaseException:
        db.rollback()
        raise


def validate_lease(db, handle) -> WazuhSyncLease:
    """Caller holds integration lock. Keep lease row locked through page commit."""
    row = db.scalar(select(WazuhSyncLease).where(
        WazuhSyncLease.integration_id == handle.integration_id,
        WazuhSyncLease.tenant_id == handle.tenant_id,
    ).with_for_update().execution_options(populate_existing=True))
    now = db.scalar(select(func.clock_timestamp()))
    if (row is None or row.owner_token != handle.owner_token or row.fence != handle.fence
            or row.expires_at is None or row.expires_at <= now):
        raise WazuhLeaseError('wazuh_sync_lease_lost')
    return row


def extend_locked_lease(db, handle):
    row = validate_lease(db, handle)
    row.expires_at = db.scalar(select(func.clock_timestamp())) + timedelta(seconds=settings.wazuh_sync_lease_seconds)


def renew_lease(db, handle):
    try:
        _integration(db, handle.tenant_id, handle.integration_id)
        extend_locked_lease(db, handle)
        db.commit()
    except BaseException:
        db.rollback()
        raise


def release_lease(db, handle, *, outcome='interrupted', error_code=None) -> bool:
    if outcome not in ('succeeded', 'not_due', 'failed', 'interrupted'):
        raise ValueError('invalid_wazuh_attempt_outcome')
    if outcome == 'interrupted' and error_code is None:
        error_code = 'lease_lost'
    if ((outcome in ('failed', 'interrupted') and error_code not in SAFE_SYNC_ERRORS)
            or (outcome in ('succeeded', 'not_due') and error_code is not None)):
        raise ValueError('invalid_wazuh_attempt_error')
    try:
        result = db.execute(update(WazuhSyncLease).where(
            WazuhSyncLease.integration_id == handle.integration_id,
            WazuhSyncLease.tenant_id == handle.tenant_id,
            WazuhSyncLease.owner_token == handle.owner_token,
            WazuhSyncLease.fence == handle.fence,
        ).values(owner_token=None, expires_at=None, last_finished_at=func.clock_timestamp(),
                 last_outcome=outcome, safe_error_code=error_code).execution_options(synchronize_session=False))
        released = result.rowcount == 1
        db.commit()
        return released
    except BaseException:
        db.rollback()
        raise
