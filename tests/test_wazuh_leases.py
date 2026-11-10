from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import WazuhSyncLease
from app.wazuh_leases import claim_lease, release_lease, renew_lease, validate_lease, WazuhLeaseError
from test_wazuh_sync import context, owner


def test_lease_excludes_competitors_and_releases(context):
    _, db = context; identity, principal, _ = owner(db)
    first = claim_lease(db, principal.tenant_id, identity)
    with pytest.raises(WazuhLeaseError, match='wazuh_sync_busy'):
        claim_lease(db, principal.tenant_id, identity)
    assert release_lease(db, first)
    second = claim_lease(db, principal.tenant_id, identity)
    assert second.fence > first.fence and second.owner_token != first.owner_token
    assert not release_lease(db, first)
    validate_lease(db, second); db.rollback()
    assert release_lease(db, second)


def test_expired_owner_cannot_renew_commit_or_release_successor(context):
    _, db = context; identity, principal, _ = owner(db)
    first = claim_lease(db, principal.tenant_id, identity)
    row = db.get(WazuhSyncLease, identity)
    row.expires_at = db.scalar(select(func.clock_timestamp())) - timedelta(seconds=1)
    db.commit()
    with pytest.raises(WazuhLeaseError, match='wazuh_sync_lease_lost'):
        renew_lease(db, first)
    second = claim_lease(db, principal.tenant_id, identity)
    with pytest.raises(WazuhLeaseError, match='wazuh_sync_lease_lost'):
        validate_lease(db, first)
    db.rollback()
    assert not release_lease(db, first)
    validate_lease(db, second); db.rollback()
    release_lease(db, second)


def test_lease_uses_database_time_and_has_no_checkpoint_side_effect(context):
    _, db = context; identity, principal, _ = owner(db)
    before = db.scalar(select(func.clock_timestamp())); db.rollback()
    handle = claim_lease(db, principal.tenant_id, identity)
    row = db.get(WazuhSyncLease, identity)
    assert before < row.expires_at < before + timedelta(seconds=130)
    from app.models import WazuhSyncCheckpoint
    assert db.get(WazuhSyncCheckpoint, identity) is None
    db.rollback(); release_lease(db, handle)


def test_foreign_tenant_cannot_claim_or_validate_lease(context):
    _, db = context; identity, principal, _ = owner(db)
    with pytest.raises(WazuhLeaseError):
        claim_lease(db, uuid4(), identity)
    handle = claim_lease(db, principal.tenant_id, identity)
    with pytest.raises(WazuhLeaseError):
        validate_lease(db, replace(handle, tenant_id=uuid4()))
    db.rollback(); release_lease(db, handle)


def test_lease_database_rejects_invalid_ownership(context):
    _, db = context; identity, principal, _ = owner(db)
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(WazuhSyncLease(integration_id=identity, tenant_id=uuid4(), fence=1))
            db.flush()


@pytest.mark.parametrize('changes', [{'fence': 0}, {'owner_token': uuid4()},
                                     {'expires_at': '2020-01-01T00:00:00Z'}])
def test_lease_database_state_constraints(context, changes):
    _, db = context; identity, principal, _ = owner(db)
    values = dict(integration_id=identity, tenant_id=principal.tenant_id, fence=1)
    if 'expires_at' in changes:
        from datetime import datetime, timezone
        changes = {'expires_at': datetime(2020, 1, 1, tzinfo=timezone.utc)}
    values.update(changes)
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.execute(WazuhSyncLease.__table__.insert().values(**values))
