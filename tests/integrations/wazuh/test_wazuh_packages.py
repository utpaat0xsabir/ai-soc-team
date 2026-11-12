"""REF-01E compatibility, guarded imports and offline fencing/status checks."""
import os
import subprocess
import sys

import pytest


MODULES = (
    ('wazuh', 'client'), ('wazuh_cursor', 'cursor'),
    ('wazuh_gateway', 'gateway'), ('wazuh_manifest', 'manifest'),
    ('wazuh_service', 'service'), ('wazuh_status', 'status'),
    ('wazuh_leases', 'leases'), ('wazuh_sync', 'sync'),
    ('wazuh_scheduler', 'scheduler'),
)


@pytest.mark.parametrize('first', [name for old, new in MODULES
                                 for name in (old, 'integrations.wazuh.' + new)])
def test_fresh_import_order_shared_identity_without_application_io(first):
    code = '''
import builtins, importlib, inspect, pathlib, socket, subprocess, sys, types
import fastapi, httpx, pydantic, sqlalchemy, sqlalchemy.orm, sqlalchemy.dialects.postgresql
class Warmup(pydantic.BaseModel):
    pass
sys.path.insert(0, 'services/api')
def forbidden(*args, **kwargs):
    raise AssertionError('forbidden application I/O')
db = types.ModuleType('app.db')
db.get_db = db.SessionLocal = forbidden
sys.modules['app.db'] = db
config = types.ModuleType('app.config','app.core.config')
config.settings = types.SimpleNamespace()
sys.modules['app.config'] = sys.modules['app.core.config'] = config
for owner, name in ((builtins, 'open'), (pathlib.Path, 'open'),
                    (socket, 'socket'), (socket, 'create_connection'),
                    (subprocess, 'Popen'), (sqlalchemy, 'create_engine'),
                    (sqlalchemy.orm, 'sessionmaker'),
                    (sqlalchemy.engine.Engine, 'connect'),
                    (httpx.Client, 'send'), (httpx.HTTPTransport, '__init__')):
    setattr(owner, name, forbidden)
importlib.import_module('app.' + FIRST)
for old, new in PAIRS:
    legacy = importlib.import_module('app.' + old)
    canonical = importlib.import_module('app.integrations.wazuh.' + new)
    for name, value in vars(canonical).items():
        if not name.startswith('__'):
            assert getattr(legacy, name) is value
from app.integrations.wazuh import client, cursor, leases, scheduler, sync, gateway
from app.gateway import tool_gateway
from app.iam import auth
from app import models
assert client.WazuhCursor is cursor.WazuhCursor
assert sync.WazuhLeaseError is leases.WazuhLeaseError
assert scheduler.WazuhSyncError is sync.WazuhSyncError
assert scheduler.logger.name == 'app.wazuh_scheduler'
assert tool_gateway.wazuh_gateway is gateway
assert leases.WazuhSyncLease is models.WazuhSyncLease
assert sync.AuthenticatedPrincipal is auth.AuthenticatedPrincipal
assert inspect.signature(scheduler.run_scheduled_job).parameters['session_factory'].default is db.SessionLocal
'''.replace('PAIRS', repr(MODULES)).replace('FIRST', repr(first))
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('condition', ['valid', 'owner', 'fence', 'expired', 'missing'])
def test_lease_validation_keeps_fencing_and_tenant_query(condition):
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from uuid import UUID
    from sqlalchemy.dialects import postgresql
    from app.integrations.wazuh import leases

    handle = leases.LeaseHandle(UUID(int=1), UUID(int=2), UUID(int=3), 4)
    now = datetime(2026, 11, 13, tzinfo=timezone.utc)
    row = SimpleNamespace(owner_token=handle.owner_token, fence=handle.fence,
                          expires_at=now + timedelta(seconds=1))
    if condition == 'owner': row.owner_token = UUID(int=9)
    if condition == 'fence': row.fence += 1
    if condition == 'expired': row.expires_at = now
    responses = iter((None if condition == 'missing' else row, now))
    statements = []

    def scalar(statement):
        statements.append(statement)
        return next(responses)

    db = SimpleNamespace(scalar=scalar)
    if condition == 'valid':
        assert leases.validate_lease(db, handle) is row
    else:
        with pytest.raises(leases.WazuhLeaseError, match='wazuh_sync_lease_lost'):
            leases.validate_lease(db, handle)
    query = statements[0].compile(dialect=postgresql.dialect())
    assert handle.tenant_id in query.params.values()
    assert handle.integration_id in query.params.values()
    assert 'FOR UPDATE' in str(query)


def test_status_missing_integration_is_tenant_scoped_and_read_only():
    from types import SimpleNamespace
    from uuid import UUID
    from sqlalchemy.dialects import postgresql
    from app.integrations.wazuh.status import read_sync_status

    tenant, integration = UUID(int=1), UUID(int=2)
    statements = []

    def execute(statement):
        statements.append(statement)
        return SimpleNamespace(mappings=lambda: SimpleNamespace(one_or_none=lambda: None))

    assert read_sync_status(SimpleNamespace(execute=execute), tenant, integration) is None
    query = statements[0].compile(dialect=postgresql.dialect())
    assert tenant in query.params.values() and integration in query.params.values()
    assert str(query).startswith('SELECT ')
    assert 'key_hash' not in str(query) and 'credential_reference' not in str(query)
