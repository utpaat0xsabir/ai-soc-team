"""REF-01C: import order, compatibility identities and infrastructure boundaries."""
import os
import subprocess
import sys

import pytest


MODULES = (
    ('iam_contracts', 'iam.contracts'),
    ('iam_policy', 'iam.policy'),
    ('iam_admission', 'iam.admission'),
    ('iam_authority_provider', 'iam.authority_provider'),
    ('iam_postgres_authority', 'iam.postgres_authority'),
    ('auth', 'iam.auth'),
    ('api_keys', 'iam.api_keys'),
)


@pytest.mark.parametrize('first', [name for pair in MODULES for name in pair])
def test_fresh_import_order_identity_and_no_application_io(first):
    code = '''
import builtins, importlib, inspect, pathlib, socket, subprocess, sys, types
import fastapi, pydantic, sqlalchemy, sqlalchemy.orm, sqlalchemy.dialects.postgresql
# Initialize third-party discovery before guarding application imports.
class Warmup(pydantic.BaseModel):
    pass
sys.path.insert(0, 'services/api')
def forbidden(*args, **kwargs):
    raise AssertionError('forbidden application I/O')
db = types.ModuleType('app.db')
db.get_db = forbidden
sys.modules['app.db'] = db
original = builtins.__import__
def guarded(name, globals=None, *args, **kwargs):
    if name in ('app.config', 'app.core.config') or name.startswith(('psycopg', 'httpx', 'ollama')):
        raise AssertionError('forbidden infrastructure import')
    if name == 'app.db' and globals.get('__name__') != 'app.iam.auth':
        raise AssertionError('only existing HTTP authentication may import get_db')
    return original(name, globals, *args, **kwargs)
for owner, name in ((builtins, 'open'), (pathlib.Path, 'open'),
                    (socket, 'socket'), (socket, 'create_connection'),
                    (subprocess, 'Popen'), (sqlalchemy, 'create_engine'),
                    (sqlalchemy.orm, 'sessionmaker'),
                    (sqlalchemy.engine.Engine, 'connect')):
    setattr(owner, name, forbidden)
builtins.__import__ = guarded
pairs = PAIRS
importlib.import_module('app.' + FIRST)
for legacy, canonical in pairs:
    old = importlib.import_module('app.' + legacy)
    new = importlib.import_module('app.' + canonical)
    for name, value in vars(new).items():
        if not name.startswith('__'):
            assert getattr(old, name) is value
from app.iam import auth, postgres_authority
from app import models
assert postgres_authority.Tenant is models.Tenant
assert postgres_authority.TenantAPIKey is models.TenantAPIKey
assert auth.TenantAPIKey is models.TenantAPIKey
for dependency in (auth.get_current_principal, auth.get_current_tenant):
    assert inspect.signature(dependency).parameters['db'].default.dependency is db.get_db
assert 'app.config' not in sys.modules
'''.replace('PAIRS', repr(MODULES)).replace('FIRST', repr(first))
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr
