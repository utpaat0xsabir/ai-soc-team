"""Deprecated compatibility import; use app.integrations.wazuh.leases. Retire separately."""

from app.integrations.wazuh.leases import (
    DBAPIError as DBAPIError,
    LeaseHandle as LeaseHandle,
    SAFE_SYNC_ERRORS as SAFE_SYNC_ERRORS,
    UUID as UUID,
    WazuhIntegration as WazuhIntegration,
    WazuhLeaseError as WazuhLeaseError,
    WazuhSyncLease as WazuhSyncLease,
    _integration as _integration,
    claim_lease as claim_lease,
    dataclass as dataclass,
    extend_locked_lease as extend_locked_lease,
    func as func,
    release_lease as release_lease,
    renew_lease as renew_lease,
    select as select,
    settings as settings,
    timedelta as timedelta,
    update as update,
    uuid4 as uuid4,
    validate_lease as validate_lease,
)
