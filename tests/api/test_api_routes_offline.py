"""REF-01H1: offline HTTP behavior, dependency and route-registration snapshots."""
import functools
import hashlib
import json
import os
import subprocess
import sys

import pytest


CASES = (
    ('health', 'GET', '/health', 'ok'),
    ('ready_denied', 'GET', '/ready', 'ok'),
    ('ready', 'GET', '/ready', 'ready'),
    ('tenant', 'GET', '/v1/tenant', 'ok'),
    ('tenant_missing', 'GET', '/v1/tenant', 'missing'),
    ('evidence_create', 'POST', '/v1/evidence', 'ok'),
    ('evidence_rollback', 'POST', '/v1/evidence', 'rollback'),
    ('evidence_invalid', 'POST', '/v1/evidence', 'invalid_body'),
    ('evidence_list', 'GET', '/v1/evidence?limit=2&offset=1', 'ok'),
    ('evidence_page_invalid', 'GET', '/v1/evidence?limit=0', 'ok'),
    ('evidence_get', 'GET', '/v1/evidence/00000000-0000-0000-0000-000000000003', 'ok'),
    ('evidence_foreign', 'GET', '/v1/evidence/00000000-0000-0000-0000-000000000003', 'missing'),
    ('evidence_integrity', 'GET', '/v1/evidence/00000000-0000-0000-0000-000000000003/verify', 'ok'),
    ('evidence_integrity_bad', 'GET', '/v1/evidence/00000000-0000-0000-0000-000000000003/verify', 'bad_hash'),
    ('lineage_create', 'POST', '/v1/evidence/00000000-0000-0000-0000-000000000003/lineage', 'ok'),
    ('lineage_rollback', 'POST', '/v1/evidence/00000000-0000-0000-0000-000000000003/lineage', 'rollback'),
    ('lineage_self', 'POST', '/v1/evidence/00000000-0000-0000-0000-000000000003/lineage', 'self'),
    ('lineage_missing', 'POST', '/v1/evidence/00000000-0000-0000-0000-000000000003/lineage', 'missing'),
    ('lineage_duplicate', 'POST', '/v1/evidence/00000000-0000-0000-0000-000000000003/lineage', 'duplicate'),
    ('lineage_list', 'GET', '/v1/evidence/00000000-0000-0000-0000-000000000003/lineage', 'ok'),
    ('audit_list', 'GET', '/v1/audit-logs?limit=2&offset=1&action=test.observed', 'ok'),
    ('audit_filter_invalid', 'GET', '/v1/audit-logs?action=%20', 'ok'),
    ('audit_verify', 'GET', '/v1/audit-logs/verify', 'ok'),
    ('wazuh_list', 'GET', '/v1/integrations/wazuh', 'ok'),
    ('wazuh_get', 'GET', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005', 'ok'),
    ('wazuh_foreign', 'GET', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005', 'missing'),
    ('wazuh_sync', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/sync', 'ok'),
    ('wazuh_sync_denied', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/sync', 'sync_error'),
    ('wazuh_status', 'GET', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/sync/status', 'ok'),
    ('wazuh_status_missing', 'GET', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/sync/status', 'missing'),
    ('wazuh_status_failed', 'GET', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/sync/status', 'status_error'),
    ('wazuh_ingest', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'ok'),
    ('wazuh_ingest_duplicate', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'duplicate_insert'),
    ('wazuh_ingest_inactive', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'inactive'),
    ('wazuh_ingest_foreign', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'missing'),
    ('wazuh_ingest_indexer_error', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'indexer_error'),
    ('wazuh_ingest_config_error', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'config_error'),
    ('wazuh_ingest_malformed', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'malformed'),
    ('wazuh_ingest_rollback', 'POST', '/v1/integrations/wazuh/00000000-0000-0000-0000-000000000005/ingest', 'rollback'),
    ('revoked_key', 'GET', '/v1/tenant', 'revoked'),
)

# Frozen against preserved pre-extraction handlers, never derived from relocated handlers.
EXPECTED = {'audit_filter_invalid': '2559f519be723c4cf40cf6d1ab687d31640a2f475b05374a4aefcfa7f3444f78',
 'audit_list': 'd77e7f27b3a882d4bad314a46b9a40aa10569a19815a5697f0cc2ae9676879ec',
 'audit_verify': '568ad101af9086a70fc31750a0a16e35f06e71936813c1e3aca5658896b405e9',
 'create_evidence_lineage_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'evidence_create': 'ba8b3e99191dbe0c2fb94953431778eb288f44a291f1d992133657ae2b64c3b2',
 'evidence_foreign': '302861e07627c859fc68a6b70f6e4ce30e95743f880c019106cc91073514c771',
 'evidence_get': '908ac2a46695edbd188d547fc81b3f541b444e2d9c0776863b62949315d4e95b',
 'evidence_integrity': '47624c3152a0d306e495e754ec0eb7e065694870da185d496c9a7b39db1b3d22',
 'evidence_integrity_bad': 'b1963393bd5d94fb125e69d486eb7bc9d8c203523c24ce4a8fd90578843c41be',
 'evidence_invalid': '7a54dfbca877c0535b3130eb23fc37567c83279c8d9aaeaeaed28cd1350ee87b',
 'evidence_list': '7139098695f777de5360e59a228bd9eb07f3046a35f9d4bdf86c9913142cfb29',
 'evidence_page_invalid': '4926f9eafb1d14332ce4f4f067f8c62f88793c0f931317576609d1dbc75c4a7f',
 'evidence_rollback': '4753b8e080d8a6398f9fad466d5e2ab3682a116962b40fd4e72d41e1890e442d',
 'get_evidence_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'get_tenant_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'get_wazuh_integration_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'get_wazuh_sync_status_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'health': 'd3ccb43a6dca87b5272aded3d2339ec5ee29c1de3073853101bcc7c6c288d194',
 'ingest_evidence_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'ingest_wazuh_alerts_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'lineage_create': '9d9722f4fbf0da8d89cf1d6e251f00ed9329c5570454a1a0cc74133e8f854d7b',
 'lineage_duplicate': 'ead3d9e3a8d63e20d2fb24dc731ab42fec8a55e3dc883ca0617594f7162bcac3',
 'lineage_list': 'f04f4519262268276dbf8743b75947282cb4335a2961d73bce30f32f2755985b',
 'lineage_missing': '87bc7e78ac5f0c28660bfd7aceaffe16168195347083ba96f29fe934c8b61369',
 'lineage_rollback': '69078e6e17098b6848d44edbd80afac8380de7dd2f78dc15f87900729d255dfd',
 'lineage_self': '90716a23a05e99bedeea26bb06f70c7005cdec9ba967a3bfe3efa4476f1c8bea',
 'list_audit_logs_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'list_evidence_lineage_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'list_evidence_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'list_wazuh_integrations_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'ready': '3e8b94fb87b4edac743577c9104a7d963292363703c371a5b8ce632a80c54dc8',
 'ready_denied': '63f0f4bc979002df79f5b1ace085b45ed98f71770c1c159242c537fe6bbdd3da',
 'revoked_key': 'ddfd2b9bd3f67faf083c6a135e4b7975d5bad04c08955472494812a5989c6e83',
 'synchronize_wazuh_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'tenant': 'de4ae04f72f343a1854994d068d6a4b746b294490df6ea5d17f80131012b9efc',
 'tenant_missing': '30c4a7a92b78098c080ecd719116c38f96982e203bdbeafbbe7b130d97a5517f',
 'verify_audit_logs_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'verify_evidence_integrity_unauthenticated': '9819a2a56db57a0936a1a0bd14a5b08bd64baa0959ff6b8300717eb54edf8b1e',
 'wazuh_foreign': '54ff4955b1659f8e0222b50f70247698989f83e5ef796c578a5820d3b30cdcbd',
 'wazuh_get': '98e2d5df0f879d05ae9b73a7fc40b72880ebf4a6b41e814cd25709b7846993a0',
 'wazuh_ingest': '6f7aa895b9d76531a4c343a248512a9ed2c89a198da2eba99777acb30f177cbc',
 'wazuh_ingest_config_error': '2de9bc52ee3a7f8b8234a41f1175ce7f032fca3e13e797ff4e2662db00c89c73',
 'wazuh_ingest_duplicate': '96fd4fef8b6e76231b90ae821d2d84d51f72f5f6b0c21a310e5c18f0b1bbe258',
 'wazuh_ingest_foreign': '54ff4955b1659f8e0222b50f70247698989f83e5ef796c578a5820d3b30cdcbd',
 'wazuh_ingest_inactive': 'ccfb0185a5a79372d83475ca835c8081c25376c9ec9e886cb4ed086385d3731b',
 'wazuh_ingest_indexer_error': '6953512f8371dd3c11ce0a1dea17c6cc18d97558f35b9c499ca8c00e8d576b9f',
 'wazuh_ingest_malformed': 'd8c26e2783a1e01febc12d244822d124414e79aed0843572958ff44f1379c093',
 'wazuh_ingest_rollback': '5788583f0dfc6e0f21e39fc2f67061099df71ba79aa7e81f8f6af25ebbadd17d',
 'wazuh_list': '9cd910598cb2859b1721dd9f33e0f04e660b32b6c3ce797dbf48ef1f449eba5a',
 'wazuh_status': 'ad5b99cbce4ec96a66ccbbeb9d68a02604d5f00ce342744b27da981164a0aea1',
 'wazuh_status_failed': '34dc068c4359aaa528074e2d4508dccbe766d4678ac2d311a44cb8e207457b70',
 'wazuh_status_missing': 'd6d90f0429e3a9b92190b03f880e6ec4f0e2c78e67dc9a6ea72a8901604694e3',
 'wazuh_sync': '04e69d415afc16175168ff8d8a4f1fb7d74e0e78e6c526dbf98d1914cbf907c6',
 'wazuh_sync_denied': 'e2ed0ce09251f5fc2ba337512ce28541e4e8781b690edc1057392b10be658469'}
OPENAPI_SHA256 = '256172210dc058e903e16a8b33876885d3e23c3072f92db5fbd69e9f06783f28'
ROUTES_SHA256 = '743c9f3d9d6eb410d5e33d447fd4f99baed5bfae8302a2ff656925411a432057'


def _snapshot(first=None):
    """Run the real ASGI stack with recorded fake DB and Wazuh collaborators."""
    import importlib
    import inspect
    import re
    import socket
    import types
    from contextlib import contextmanager
    from datetime import datetime, timezone
    from uuid import UUID
    import httpx
    import sqlalchemy
    import sqlalchemy.orm
    from sqlalchemy.dialects import postgresql

    sys.path.insert(0, 'services/api')

    def forbidden(*args, **kwargs):
        raise AssertionError('external I/O forbidden')

    socket.create_connection = socket.socket.connect = forbidden
    httpx.HTTPTransport.handle_request = forbidden
    sqlalchemy.engine.Engine.connect = forbidden
    sqlalchemy.MetaData.create_all = sqlalchemy.MetaData.drop_all = forbidden
    config = types.ModuleType('app.core.config')
    config.settings = types.SimpleNamespace(database_url='synthetic-only')
    sys.modules['app.config'] = sys.modules['app.core.config'] = config
    engine = types.SimpleNamespace(connect=forbidden)
    sqlalchemy.create_engine = lambda *args, **kwargs: engine
    sqlalchemy.orm.sessionmaker = lambda **kwargs: forbidden
    from app import db
    sqlalchemy.create_engine = sqlalchemy.orm.sessionmaker = forbidden
    if first:
        importlib.import_module(first)
    from app import main, schemas
    from app.database import models
    from app.audit import integrity
    from app.evidence.hashing import calculate_evidence_hash
    import asyncio
    import anyio

    # Exercise ASGI contracts without the sandbox's blocked cross-thread portal.
    async def inline_sync(function, *args, **kwargs):
        return function(*args)

    anyio.to_thread.run_sync = inline_sync

    app = main.app
    from fastapi.routing import iter_route_contexts
    routes = [r for r in iter_route_contexts(app.routes) if getattr(r, 'dependant', None) is not None]
    from app.iam import auth

    def check_dependencies(node):
        expected = {'get_db': db.get_db, 'get_current_principal': auth.get_current_principal,
                    'get_current_tenant': auth.get_current_tenant}
        for child in node.dependencies:
            assert child.call is expected[child.call.__name__]
            check_dependencies(child)

    for route in routes:
        assert getattr(main, route.name) is route.endpoint is route.dependant.call
        check_dependencies(route.dependant)
        if route.response_model is not None:
            assert route.response_model is getattr(schemas, route.response_model.__name__)
    assert main.ingest_wazuh_alerts.__globals__ is vars(main)

    def dependencies(node):
        return [{'name': child.call.__name__, 'module': child.call.__module__,
                 'cache': child.use_cache, 'dependencies': dependencies(child)}
                for child in node.dependencies]

    inventory = [{'methods': sorted(r.methods), 'path': r.path, 'name': r.name,
                  'endpoint': r.endpoint.__name__, 'operation_id': r.unique_id,
                  'response_model': getattr(r.response_model, '__name__', None),
                  'status': r.status_code, 'tags': r.tags,
                  'signature': re.sub(r' at 0x[0-9a-f]+', '', str(inspect.signature(r.endpoint))),
                  'dependencies': dependencies(r.dependant)} for r in routes]
    document = app.openapi()
    tenant, key, evidence_id, child_id, integration_id = (UUID(int=i) for i in range(1, 6))

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 13, 12, tzinfo=timezone.utc)

    now = Clock.now()
    owner_globals = {id(r.endpoint.__globals__): r.endpoint.__globals__ for r in routes}
    for namespace in owner_globals.values():
        if 'datetime' in namespace:
            namespace['datetime'] = Clock
    integrity.datetime = Clock

    evidence = models.EvidenceRecord(
        id=evidence_id, tenant_id=tenant, evidence_type='observation', source_type='synthetic',
        source_reference='synthetic/1', event_time=now, collected_at=now, created_at=now,
        collector_name='test', collector_version='1', trust_level='unverified', schema_version='1.0',
        payload={'synthetic': True}, content_sha256='',
    )
    evidence.content_sha256 = calculate_evidence_hash(**{name: getattr(evidence, name) for name in
        ('evidence_type', 'source_type', 'source_reference', 'event_time', 'collector_name',
         'collector_version', 'trust_level', 'payload')})
    integration = models.WazuhIntegration(
        id=integration_id, tenant_id=tenant, name='Synthetic', base_url='https://indexer.invalid',
        username='synthetic', credential_reference='env:SYNTHETIC_ONLY',
        ca_certificate_path='/synthetic/unused', is_active=True, created_at=now,
    )
    lineage = models.EvidenceLineage(tenant_id=tenant, parent_evidence_id=evidence_id,
        child_evidence_id=child_id, relationship_type='supports', created_at=now)
    values = dict(tenant_id=tenant, sequence_number=1, previous_hash=integrity.GENESIS_HASH,
        actor_type='api_key', actor_id=key, action='test.observed', resource_type='evidence',
        resource_id=evidence_id, details={'synthetic': True}, created_at=now)
    audit = models.AuditLog(id=UUID(int=6), **values,
        entry_hash=integrity.calculate_audit_hash(**values))

    class FakeDB:
        def __init__(self, variant):
            self.variant, self.log, self.staged = variant, [], []

        def query(self, op, statement):
            compiled = statement.compile(dialect=postgresql.dialect())
            self.log.append({'op': op, 'sql': str(compiled),
                'params': json.loads(json.dumps(compiled.params, default=str, sort_keys=True))})

        def scalar(self, statement):
            self.query('scalar', statement)
            expr = statement.column_descriptions[0]['expr']
            entity = statement.column_descriptions[0].get('entity')
            if entity is models.TenantAPIKey:
                if self.variant == 'revoked': return None
                return types.SimpleNamespace(id=key, tenant_id=tenant) if expr is models.TenantAPIKey else tenant
            if entity is models.Tenant:
                return None if self.variant == 'missing' else types.SimpleNamespace(
                    id=tenant, name='Synthetic', slug='synthetic', created_at=now)
            if entity is models.EvidenceRecord:
                return None if self.variant == 'missing' else evidence_id if expr is models.EvidenceRecord.id else evidence
            if entity is models.WazuhIntegration:
                return None if self.variant == 'missing' else integration
            if entity is models.AuditLog: return None
            return 1

        def scalars(self, statement):
            self.query('scalars', statement)
            expr = statement.column_descriptions[0]['expr']
            entity = statement.column_descriptions[0].get('entity')
            if expr is models.EvidenceRecord.id:
                rows = [] if self.variant == 'missing' else [evidence_id, child_id]
            else:
                rows = {models.EvidenceRecord: [evidence], models.EvidenceLineage: [lineage],
                        models.AuditLog: [audit], models.WazuhIntegration: [integration]}.get(entity, [])
            return types.SimpleNamespace(all=lambda: rows)

        def get(self, model, identity):
            self.log.append({'op': 'get', 'model': model.__name__, 'identity': list(map(str, identity))})
            return lineage if self.variant == 'duplicate' else None

        def add(self, row):
            self.log.append({'op': 'add', 'model': type(row).__name__})
            self.staged.append(row)

        def flush(self):
            self.log.append({'op': 'flush'})
            for i, row in enumerate(self.staged):
                if hasattr(row, 'id') and row.id is None: row.id = UUID(int=100 + i)
                for name in ('created_at', 'collected_at'):
                    if hasattr(row, name) and getattr(row, name) is None: setattr(row, name, now)

        def commit(self):
            self.log.append({'op': 'commit'})
            if self.variant == 'rollback': raise RuntimeError('simulated commit failure')

        def rollback(self): self.log.append({'op': 'rollback'})
        def refresh(self, row): self.log.append({'op': 'refresh', 'model': type(row).__name__})

        def execute(self, statement):
            self.query('execute', statement)
            return types.SimpleNamespace(scalar_one_or_none=lambda:
                None if self.variant == 'duplicate_insert' else UUID(int=99))

    snapshots = {}
    protected = [(r.name + '_unauthenticated', next(iter(r.methods)),
                  r.path.replace('{evidence_id}', str(evidence_id))
                        .replace('{parent_evidence_id}', str(evidence_id))
                        .replace('{integration_id}', str(integration_id)), 'unauthenticated')
                 for r in routes if r.dependant.dependencies]
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                               base_url='http://testserver')
    for name, method, path, variant in (*CASES, *protected):
        fake = FakeDB(variant)
        integration.is_active = variant != 'inactive'
        evidence.content_sha256 = '0' * 64 if variant == 'bad_hash' else calculate_evidence_hash(**{
            field: getattr(evidence, field) for field in ('evidence_type', 'source_type', 'source_reference',
                'event_time', 'collector_name', 'collector_version', 'trust_level', 'payload')})

        def override_db():
            fake.log.append({'op': 'session_open'})
            try: yield fake
            finally: fake.log.append({'op': 'session_close'})

        def sync_stub(session, principal, identity, *, page_size):
            fake.log.append({'op': 'sync_stub', 'tenant': str(principal.tenant_id), 'limit': page_size})
            if variant == 'sync_error': raise main.WazuhSyncError('wazuh_sync_busy', 409)
            return dict(integration_id=identity, status='completed', fetched=1, imported=1, duplicates=0, pages=1)

        def status_stub(session, tenant_id, identity):
            fake.log.append({'op': 'status_stub', 'tenant': str(tenant_id)})
            if variant == 'status_error': raise sqlalchemy.exc.SQLAlchemyError('synthetic')
            if variant == 'missing': return None
            return dict(integration_id=identity, integration_active=True, checkpoint_status='uninitialized',
                generation=0, imported_count=0, duplicate_count=0, has_committed_cursor=False,
                last_success_at=None, last_attempt_at=None, last_finished_at=None,
                last_attempt_outcome=None, safe_error_code=None, sync_lock_active=False)

        @contextmanager
        def open_stub(record):
            fake.log.append({'op': 'open_stub', 'tenant': str(record.tenant_id)})
            if variant == 'indexer_error': raise main.WazuhIndexerError('synthetic')
            if variant == 'config_error': raise main.WazuhIntegrationError('synthetic')
            def search(*, size, offset):
                fake.log.append({'op': 'search_stub', 'size': size, 'offset': offset})
                return {'items': 'invalid' if variant == 'malformed' else [
                    {'source_reference': 'synthetic/1', 'event_time': now, 'synthetic': True}], 'total': 1}
            yield types.SimpleNamespace(search_alerts=search)

        original = []
        for namespace in owner_globals.values():
            for field, value in (('sync_wazuh', sync_stub), ('read_sync_status', status_stub)):
                if field in namespace:
                    original.append((namespace, field, namespace[field]));namespace[field] = value
        # Deliberately preserve the existing app.main patch target for ingestion.
        original.append((vars(main), 'open_wazuh_client', main.open_wazuh_client))
        main.open_wazuh_client = open_stub
        engine.connect = forbidden
        if variant == 'ready':
            @contextmanager
            def connect():
                yield types.SimpleNamespace(execute=lambda statement: fake.log.append(
                    {'op': 'readiness_stub', 'sql': str(statement)}))
            engine.connect = connect
        app.dependency_overrides[db.get_db] = override_db
        body = None
        if method == 'POST' and path == '/v1/evidence':
            body = dict(evidence_type='observation', source_type='synthetic', source_reference='synthetic/new',
                        event_time=now.isoformat(), payload={'synthetic': True})
            if variant == 'invalid_body': body['source_type'] = ' '
        if method == 'POST' and path.endswith('/lineage'):
            body = dict(child_evidence_id=str(evidence_id if variant == 'self' else child_id), relationship_type='supports')
        try:
            response = asyncio.run(client.request(method, path, json=body,
                headers={} if variant == 'unauthenticated' else {'X-API-Key': 'soc_synthetic_test_only'}))
            try: content = response.json()
            except ValueError: content = response.text
            snapshots[name] = {'status': response.status_code, 'body': content,
                               'wire': response.text, 'headers': dict(response.headers), 'calls': fake.log}
        finally:
            app.dependency_overrides.clear()
            for namespace, field, value in reversed(original): namespace[field] = value
    asyncio.run(client.aclose())
    return {'openapi': document, 'routes': inventory, 'cases': snapshots,
            'owners': {r.name: r.endpoint.__module__ for r in routes}}


@functools.lru_cache(maxsize=None)
def _run(first=None):
    result = subprocess.run([sys.executable, __file__, first or 'snapshot'],
        capture_output=True, text=True, timeout=45,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@pytest.mark.parametrize('first', ['app.main', 'app.api.v1.tenant', 'app.api.v1.evidence',
                                   'app.api.v1.audit', 'app.api.v1.wazuh'])
def test_fresh_router_import_order_and_contract(first):
    snapshot = _run(first)
    assert _digest(snapshot['openapi']) == OPENAPI_SHA256
    assert _digest(snapshot['routes']) == ROUTES_SHA256


@pytest.mark.parametrize('name', list(EXPECTED))
def test_http_behavior_and_db_call_order_unchanged(name):
    actual = _run()['cases'][name]
    assert _digest(actual) == EXPECTED[name], actual



def test_endpoint_owners_and_retained_patch_boundary():
    owners = _run()['owners']
    expected = {name: 'app.api.v1.evidence' for name in (
        'ingest_evidence', 'list_evidence', 'get_evidence', 'verify_evidence_integrity',
        'create_evidence_lineage', 'list_evidence_lineage')}
    expected.update({name: 'app.api.v1.audit' for name in ('list_audit_logs', 'verify_audit_logs')})
    expected.update({name: 'app.api.v1.wazuh' for name in (
        'synchronize_wazuh', 'get_wazuh_sync_status', 'list_wazuh_integrations', 'get_wazuh_integration')})
    expected['get_tenant'] = 'app.api.v1.tenant'
    expected.update({name: 'app.main' for name in ('health', 'readiness', 'ingest_wazuh_alerts')})
    assert owners == expected


if __name__ == '__main__':
    print(json.dumps(_snapshot(None if sys.argv[1] == 'snapshot' else sys.argv[1]), sort_keys=True))
