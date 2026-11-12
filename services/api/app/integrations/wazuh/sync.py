"""Tenant-scoped, page-atomic synchronization. No production scope defaults."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
from time import sleep as retry_wait
from threading import Event
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.exc import DBAPIError

from app.audit.integrity import record_audit_event
from app.iam.auth import AuthenticatedPrincipal
from app.core.config import settings
from app.evidence.hashing import calculate_evidence_hash
from app.database.models import EvidenceRecord, TenantAPIKey, WazuhIntegration, WazuhSyncCheckpoint
from app.integrations.wazuh.client import WazuhIndexerError, alert_query_fingerprint
from app.integrations.wazuh.leases import WazuhLeaseError, claim_lease, release_lease, renew_lease, validate_lease, extend_locked_lease
from app.integrations.wazuh.service import WazuhIntegrationError, open_wazuh_client
from app.integrations.wazuh.status import safe_sync_error


class WazuhSyncError(Exception):
    def __init__(self, code: str, status_code: int = 409):
        super().__init__(code)
        self.status_code = status_code


class WazuhSyncStopped(WazuhSyncError):
    def __init__(self):
        super().__init__('wazuh_sync_stopped')


def _check_stop(stop_event):
    if stop_event is not None and stop_event.is_set():
        raise WazuhSyncStopped()


class SyncScope(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    tenant_id: str
    bootstrap_start_ms: int = Field(ge=0, le=253402300799999)
    window_ms: int = Field(default=300000, ge=1000, le=86400000)
    overlap_ms: int = Field(default=60000, ge=0, le=86400000)
    safety_delay_ms: int = Field(default=30000, ge=0, le=86400000)
    dedicated_source: bool = False
    source_field: str | None = Field(default=None, pattern=r'^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$', max_length=200)
    source_value: str | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode='after')
    def validate_scope(self):
        UUID(self.tenant_id)
        if self.overlap_ms >= self.window_ms:
            raise ValueError('invalid_overlap')
        if self.dedicated_source:
            if self.source_field is not None or self.source_value is not None:
                raise ValueError('ambiguous_scope')
        elif not self.source_field or not self.source_value or not self.source_value.strip():
            raise ValueError('source_mapping_required')
        return self

    def source_filter(self):
        return {'match_all': {}} if self.dedicated_source else {'term': {self.source_field: self.source_value}}


def load_scope(integration_id: UUID, tenant_id: UUID) -> SyncScope:
    try:
        policies = {UUID(key): SyncScope.model_validate(value)
                    for key, value in settings.wazuh_sync_scopes.items()}
        policy = policies[integration_id]
        if UUID(policy.tenant_id) != tenant_id:
            raise ValueError()
        # All integrations currently use one configured physical source. Shared
        # sources require one common organization field and disjoint values.
        for other in policies.values():
            if UUID(other.tenant_id) == tenant_id:
                continue
            if (policy.dedicated_source or other.dedicated_source
                    or other.source_field != policy.source_field
                    or other.source_value == policy.source_value):
                raise ValueError()
        return policy
    except (KeyError, TypeError, ValueError, AttributeError):
        raise WazuhSyncError('wazuh_sync_scope_unavailable', 503) from None


def utcnow():
    return datetime.now(timezone.utc)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _source_allowed(policy, source):
    if policy.dedicated_source:
        return True
    value = source
    for part in policy.source_field.split('.'):
        if not isinstance(value, dict):
            return False
        value = value.get(part)
    return value == policy.source_value


def _integrity_hash(row):
    return calculate_evidence_hash(
        evidence_type=row.evidence_type, source_type=row.source_type,
        source_reference=row.source_reference, collector_name=row.collector_name,
        collector_version=row.collector_version, trust_level=row.trust_level,
        event_time=row.event_time, payload=row.payload)


def store_alert(db, principal, integration_id, alert, policy) -> bool:
    """Insert observation or validate replay; never replace existing evidence."""
    raw = alert['raw_document']
    if not _source_allowed(policy, raw['_source']):
        raise WazuhSyncError('wazuh_sync_scope_mismatch', 502)
    reference = f'integration:{integration_id}:{alert["source_reference"]}'
    if len(reference) > 500:
        raise WazuhSyncError('wazuh_sync_invalid_alert', 502)
    payload = dict(alert)
    payload['event_time'] = alert['event_time'].isoformat()
    envelope = dict(evidence_type='observation', source_type='wazuh', source_reference=reference,
                    collector_name='wazuh-indexer', collector_version='0.1.0',
                    trust_level='unverified', event_time=alert['event_time'], payload=payload)
    digest = calculate_evidence_hash(**envelope)
    inserted = db.execute(pg_insert(EvidenceRecord).values(
        **envelope, tenant_id=principal.tenant_id, schema_version='1.0', content_sha256=digest,
    ).on_conflict_do_nothing(
        index_elements=[EvidenceRecord.tenant_id, EvidenceRecord.source_reference],
        index_where=EvidenceRecord.source_type == 'wazuh',
    ).returning(EvidenceRecord.id)).scalar_one_or_none()
    if inserted is not None:
        return True
    original = db.scalar(select(EvidenceRecord).where(
        EvidenceRecord.tenant_id == principal.tenant_id,
        EvidenceRecord.source_type == 'wazuh', EvidenceRecord.source_reference == reference,
    ).execution_options(populate_existing=True))
    if (original is None or original.evidence_type != 'observation'
            or original.collector_name != 'wazuh-indexer'
            or not hmac.compare_digest(_integrity_hash(original), original.content_sha256)
            or _canonical(original.payload.get('raw_document', {}).get('_source')) != _canonical(raw['_source'])):
        raise WazuhSyncError('wazuh_sync_identity_conflict')
    return False


def _connection_identity(integration):
    return (integration.base_url, integration.username,
            integration.credential_reference, integration.ca_certificate_path)


def _authorize(db, principal, integration_id, *, lock=False):
    if db.scalar(select(TenantAPIKey.id).where(
        TenantAPIKey.id == principal.api_key_id, TenantAPIKey.tenant_id == principal.tenant_id,
        TenantAPIKey.revoked_at.is_(None),
    )) is None:
        raise WazuhSyncError('invalid_api_key', 401)
    query = select(WazuhIntegration).where(
        WazuhIntegration.id == integration_id, WazuhIntegration.tenant_id == principal.tenant_id,
    ).execution_options(populate_existing=True)
    integration = db.scalar(query.with_for_update() if lock else query)
    if integration is None:
        raise WazuhSyncError('wazuh_integration_not_found', 404)
    if not integration.is_active:
        raise WazuhSyncError('wazuh_integration_inactive')
    return integration


def _checkpoint(db, principal, integration_id, *, lock=False):
    query = select(WazuhSyncCheckpoint).where(
        WazuhSyncCheckpoint.integration_id == integration_id,
        WazuhSyncCheckpoint.tenant_id == principal.tenant_id,
    ).execution_options(populate_existing=True)
    return db.scalar(query.with_for_update() if lock else query)


def sync_wazuh(db: Session, principal: AuthenticatedPrincipal, integration_id: UUID,
               *, page_size: int = 50, stop_event: Event | None = None) -> dict:
    """Drain one finite window with one atomic commit per validated page.

    Owns this request's session transactions; callers must not stage unrelated
    writes. New PITs always replay active windows from their beginning.
    """
    if db.new or db.dirty or db.deleted:
        raise WazuhSyncError('wazuh_sync_session_not_clean', 503)
    if type(page_size) is not int or not 1 <= page_size <= 100:
        raise WazuhSyncError('invalid_wazuh_page_size', 422)
    _check_stop(stop_event)
    lease = None
    outcome, error_code = 'interrupted', 'processing_failed'
    try:
        _authorize(db, principal, integration_id)
        load_scope(integration_id, principal.tenant_id)
        db.rollback()
        _check_stop(stop_event)
        lease = claim_lease(db, principal.tenant_id, integration_id)
        before = _checkpoint(db, principal, integration_id)
        baseline = ((before.imported_count, before.duplicate_count, before.generation)
                    if before is not None else (0, 0, 0))
        db.rollback()
        for attempt in range(3):
            _check_stop(stop_event)
            renew_lease(db, lease)
            try:
                result = _sync(db, principal, integration_id, page_size, lease, stop_event)
                committed = _checkpoint(db, principal, integration_id)
                if committed is not None:
                    # Database deltas include a commit whose acknowledgement was lost.
                    result.update(imported=committed.imported_count - baseline[0],
                                  duplicates=committed.duplicate_count - baseline[1],
                                  pages=committed.generation - baseline[2])
                    result['fetched'] = result['imported'] + result['duplicates']
                db.rollback()
                outcome = 'succeeded' if result['status'] == 'completed' else 'not_due'
                error_code = None
                return result
            except WazuhIndexerError as exc:
                db.rollback()
                if not exc.retryable or attempt == 2:
                    raise
            except DBAPIError as exc:
                db.rollback()
                if not exc.connection_invalidated or attempt == 2:
                    raise
            delay = 0.1 * (2 ** attempt)
            if stop_event is None:
                retry_wait(delay)
            elif stop_event.wait(delay):
                raise WazuhSyncStopped()
    except WazuhSyncStopped:
        db.rollback()
        outcome, error_code = 'interrupted', 'processing_failed'
        raise
    except WazuhLeaseError as exc:
        db.rollback()
        outcome, error_code = 'failed', safe_sync_error(str(exc))
        raise WazuhSyncError(str(exc)) from None
    except WazuhSyncError as exc:
        db.rollback()
        outcome, error_code = 'failed', safe_sync_error(str(exc))
        raise
    except WazuhIndexerError as exc:
        db.rollback()
        outcome, error_code = 'failed', safe_sync_error(str(exc))
        raise WazuhSyncError('wazuh_sync_indexer_unavailable', 502) from None
    except (WazuhIntegrationError, OSError):
        db.rollback()
        outcome, error_code = 'failed', 'configuration_unavailable'
        raise WazuhSyncError('wazuh_sync_configuration_unavailable', 503) from None
    except Exception:
        db.rollback()
        outcome, error_code = 'failed', 'processing_failed'
        raise WazuhSyncError('wazuh_sync_processing_failed', 503) from None
    finally:
        if lease is not None:
            db.rollback()
            try:
                release_lease(db, lease, outcome=outcome, error_code=error_code)
            except Exception:
                # Failed cleanup must not replace the processing outcome. The
                # lease expires, and a stale owner cannot release its successor.
                db.rollback()


def _sync(db, principal, integration_id, page_size, lease, stop_event=None):
    integration = _authorize(db, principal, integration_id)
    policy = load_scope(integration_id, principal.tenant_id)
    connection_identity = _connection_identity(integration)
    previous = _checkpoint(db, principal, integration_id)
    existed = previous is not None
    generation = previous.generation if existed else 0
    completed = previous.completed_window_end_ms if existed else None
    old_fingerprint = previous.query_fingerprint if existed else None
    old_manifest = previous.index_manifest if existed else None
    durable_manifest = previous.source_manifest if existed else None
    old_scope = previous.scope_fingerprint if existed else None
    if existed and previous.window_start_ms is not None:
        start, end = previous.window_start_ms, previous.window_end_ms
    else:
        frontier = completed if completed is not None else policy.bootstrap_start_ms
        start = max(policy.bootstrap_start_ms, frontier - policy.overlap_ms)
        end = min(int(utcnow().timestamp() * 1000) - policy.safety_delay_ms,
                  frontier + policy.window_ms)
    db.expunge(integration)
    db.rollback()  # Release authentication/read transaction before network I/O.
    totals = dict(imported=0, duplicates=0, fetched=0, pages=0)
    if end <= start:
        return dict(integration_id=integration_id, status='not_due', **totals)
    policy_digest = hashlib.sha256(_canonical(policy.model_dump()).encode()).hexdigest()
    connection_digest = hashlib.sha256(_canonical(connection_identity).encode()).hexdigest()
    scope_fingerprint = hashlib.sha256(_canonical([policy_digest, connection_digest]).encode()).hexdigest()
    if old_scope is not None and old_scope != scope_fingerprint:
        raise WazuhSyncError('wazuh_sync_source_changed')
    _check_stop(stop_event)
    with open_wazuh_client(integration) as client:
        metadata_scope = dict(scope_field=policy.source_field, scope_value=policy.source_value)
        manifest = client.inspect_alert_indices(**metadata_scope)
        _check_stop(stop_event)
        protected = durable_manifest or old_manifest
        if protected is not None:
            _verify_manifest(protected, manifest)
        if old_scope is None and old_fingerprint is not None:
            # Old idle checkpoints did not retain manifests. Adopt only when
            # their full historical fingerprint can still be proved exactly.
            legacy_manifest = old_manifest or manifest
            expected = alert_query_fingerprint(tuple(legacy_manifest), policy.source_filter(), {
                'index_manifest': legacy_manifest, 'policy': policy_digest, 'connection': connection_digest})
            if expected != old_fingerprint:
                raise WazuhSyncError('wazuh_sync_source_changed')
        with client.alert_snapshot(
            tenant_id=principal.tenant_id, integration_id=integration_id,
            index_names=tuple(manifest), window_start_ms=start, window_end_ms=end,
            source_filter=policy.source_filter(),
            query_context={'index_manifest': manifest, 'policy': policy_digest,
                           'connection': connection_digest},
        ) as scan:
            fingerprint = scan.query_fingerprint
            _verify_manifest(manifest, client.inspect_alert_indices(**metadata_scope))
            cursor = None
            while True:
                _check_stop(stop_event)
                renew_lease(db, lease)
                page = scan.page(size=page_size, cursor=cursor, generation=generation)
                _verify_manifest(manifest, client.inspect_alert_indices(**metadata_scope))
                # Integration -> lease -> checkpoint -> tenant audit lock order.
                locked = _authorize(db, principal, integration_id, lock=True)
                validate_lease(db, lease)
                if (_connection_identity(locked) != connection_identity
                        or load_scope(integration_id, principal.tenant_id) != policy):
                    raise WazuhSyncError('wazuh_sync_source_changed')
                checkpoint = _checkpoint(db, principal, integration_id, lock=True)
                if ((checkpoint is not None) != existed
                        or (checkpoint is not None and checkpoint.generation != generation)):
                    raise WazuhSyncError('wazuh_sync_stale_generation')
                if checkpoint is None:
                    checkpoint = WazuhSyncCheckpoint(integration_id=integration_id,
                                                    tenant_id=principal.tenant_id,
                                                    imported_count=0, duplicate_count=0)
                    db.add(checkpoint)
                imported = sum(store_alert(db, principal, integration_id, alert, policy)
                               for alert in page['items'])
                duplicates = len(page['items']) - imported
                checkpoint.query_fingerprint = fingerprint
                checkpoint.scope_fingerprint = scope_fingerprint
                checkpoint.source_manifest = manifest
                checkpoint.generation = generation + 1
                checkpoint.last_attempt_at = utcnow()
                checkpoint.safe_error_code = None
                checkpoint.imported_count += imported
                checkpoint.duplicate_count += duplicates
                if page['exhausted']:
                    checkpoint.status = 'idle'
                    checkpoint.completed_window_end_ms = max(completed or 0, end)
                    checkpoint.window_start_ms = checkpoint.window_end_ms = None
                    checkpoint.index_manifest = checkpoint.snapshot_id = checkpoint.cursor_sort = None
                    checkpoint.last_success_at = utcnow()
                else:
                    checkpoint.status = 'syncing'
                    checkpoint.window_start_ms, checkpoint.window_end_ms = start, end
                    checkpoint.index_manifest = manifest
                    checkpoint.snapshot_id = scan.snapshot_id
                    checkpoint.cursor_sort = list(page['next_cursor'].sort_values)
                record_audit_event(
                    db, tenant_id=principal.tenant_id, actor_type='api_key', actor_id=principal.api_key_id,
                    action='wazuh.sync_page_committed', resource_type='wazuh_integration', resource_id=integration_id,
                    details=dict(fetched=len(page['items']), imported=imported, duplicates=duplicates,
                                 generation=generation + 1, exhausted=page['exhausted'], lease_fence=lease.fence),
                )
                extend_locked_lease(db, lease)
                db.commit()
                existed = True
                generation += 1
                totals['imported'] += imported
                totals['duplicates'] += duplicates
                totals['fetched'] += len(page['items'])
                totals['pages'] += 1
                if page['exhausted']:
                    break
                cursor = replace(page['next_cursor'], generation=generation)
    return dict(integration_id=integration_id, status='completed', **totals)


def _verify_manifest(protected, current):
    if set(protected) - set(current):
        raise WazuhSyncError('wazuh_sync_retention_gap')
    if any(current[name] != identity for name, identity in protected.items()):
        raise WazuhSyncError('wazuh_sync_source_changed')
