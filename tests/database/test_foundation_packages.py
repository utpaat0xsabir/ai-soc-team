"""REF-01G identity, metadata and transaction-ownership checks without a DB."""
import os
import subprocess
import sys

import pytest


MODULES = (
    ('config', 'core.config'), ('audit', 'audit.integrity'),
    ('models', 'database.models'), ('database_roles', 'database.roles'),
)


@pytest.mark.parametrize('first', [name for pair in MODULES for name in pair])
def test_fresh_import_order_identity_metadata_without_io(first):
    code = '''
import builtins, importlib, pathlib, socket, subprocess, sys, types
import fastapi, pydantic, pydantic_settings, sqlalchemy, sqlalchemy.orm, sqlalchemy.dialects.postgresql
class Warmup(pydantic.BaseModel):
    pass
sys.path.insert(0, 'services/api')
constructions = []
def settings_init(self, **kwargs):
    # Test construction identity without consulting environment or dotenv sources.
    constructions.append(type(self))
    value = type(self).model_construct()
    object.__setattr__(self, '__dict__', value.__dict__)
    object.__setattr__(self, '__pydantic_fields_set__', set())
pydantic_settings.BaseSettings.__init__ = settings_init
def forbidden(*args, **kwargs):
    raise AssertionError('forbidden application I/O')
for owner, name in ((builtins, 'open'), (pathlib.Path, 'open'),
                    (socket, 'socket'), (socket, 'create_connection'),
                    (subprocess, 'Popen'), (sqlalchemy, 'create_engine'),
                    (sqlalchemy.orm, 'sessionmaker'), (sqlalchemy.engine.Engine, 'connect'),
                    (sqlalchemy.MetaData, 'create_all'), (sqlalchemy.MetaData, 'drop_all')):
    setattr(owner, name, forbidden)
importlib.import_module('app.' + FIRST)
for old, new in PAIRS:
    legacy = importlib.import_module('app.' + old)
    canonical = importlib.import_module('app.' + new)
    for name, value in vars(canonical).items():
        if not name.startswith('__'):
            assert getattr(legacy, name) is value
from app import models
from app.database import models as canonical, roles
from app.core import config
from app.audit import integrity
assert constructions == [config.Settings]
assert type(config.settings) is config.Settings
assert models.Base is canonical.Base
assert roles.Base is canonical.Base
assert integrity.AuditLog is canonical.AuditLog
assert models.Base.metadata is canonical.Base.metadata
assert len(canonical.Base.registry.mappers) == len(canonical.Base.metadata.tables) == 8
for mapper in canonical.Base.registry.mappers:
    assert getattr(models, mapper.class_.__name__) is mapper.class_
    assert mapper.local_table is canonical.Base.metadata.tables[mapper.local_table.name]
assert 'app.db' not in sys.modules
'''.replace('PAIRS', repr(MODULES)).replace('FIRST', repr(first))
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_retained_session_globals_and_factory_wiring_without_connection():
    code = '''
import importlib, sys, types, socket, sqlalchemy, sqlalchemy.orm
sys.path.insert(0, 'services/api')
def forbidden(*args, **kwargs):
    raise AssertionError('connection forbidden')
socket.create_connection = sqlalchemy.engine.Engine.connect = forbidden
engine = object()
session = types.SimpleNamespace(close=forbidden)
factory = lambda: session
calls = []
def create_engine(url, **kwargs):
    calls.append(('engine', url, kwargs))
    return engine
def sessionmaker(**kwargs):
    calls.append(('factory', kwargs))
    return factory
sqlalchemy.create_engine = create_engine
sqlalchemy.orm.sessionmaker = sessionmaker
config = types.ModuleType('app.core.config')
config.settings = types.SimpleNamespace(database_url='synthetic-config-only')
sys.modules['app.config'] = sys.modules['app.core.config'] = config
from app import db
from app.audit.integrity import AUDIT_LOCK_PROTOCOL
assert db.engine is engine and db.SessionLocal is factory
assert db.get_db.__globals__ is vars(db)
assert calls == [('engine', 'synthetic-config-only', dict(pool_pre_ping=True, pool_size=5, max_overflow=5, pool_timeout=10,
                                                        connect_args={'application_name': f'ai-soc-team/{AUDIT_LOCK_PROTOCOL}'})),
                 ('factory', dict(bind=engine, autoflush=False, autocommit=False))]
closed = []
replacement = types.SimpleNamespace(close=lambda: closed.append(True))
db.SessionLocal = lambda: replacement
generator = db.get_db()
assert next(generator) is replacement
generator.close()
assert closed == [True]
from app import main
from app.iam import auth
from app.integrations.wazuh import scheduler
assert main.engine is db.engine and main.get_db is db.get_db
assert auth.get_db is db.get_db
assert scheduler.SessionLocal is db.SessionLocal
'''
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('outcome', ['success', 'tenant_missing', 'flush_failure'])
def test_audit_writer_keeps_lock_and_caller_transaction_ownership(outcome):
    from types import SimpleNamespace
    from uuid import UUID
    from sqlalchemy.dialects import postgresql
    from app.audit.integrity import GENESIS_HASH, calculate_audit_hash, record_audit_event

    tenant = UUID(int=1)
    statements, staged, calls = [], [], []
    responses = iter((None if outcome == 'tenant_missing' else object(), None))

    def scalar(statement):
        statements.append(statement)
        return next(responses)

    def flush():
        calls.append('flush')
        if outcome == 'flush_failure':
            raise RuntimeError('forced flush failure')

    # No commit/rollback methods: the caller owns the transaction.
    db = SimpleNamespace(scalar=scalar, add=staged.append, flush=flush)
    args = dict(tenant_id=tenant, actor_type='system', actor_id=None,
                action='test.observed', resource_type='evidence', details={'synthetic': True})
    if outcome == 'tenant_missing':
        with pytest.raises(ValueError, match='^audit_tenant_not_found$'):
            record_audit_event(db, **args)
        assert not staged and not calls and len(statements) == 1
    else:
        if outcome == 'flush_failure':
            with pytest.raises(RuntimeError, match='^forced flush failure$'):
                record_audit_event(db, **args)
        else:
            assert record_audit_event(db, **args) is staged[0]
        event, = staged
        assert event.sequence_number == 1 and event.previous_hash == GENESIS_HASH
        assert event.entry_hash == calculate_audit_hash(
            **args, sequence_number=1, previous_hash=GENESIS_HASH,
            resource_id=None, created_at=event.created_at,
        )
        assert calls == ['flush'] and len(statements) == 2
    query = statements[0].compile(dialect=postgresql.dialect())
    assert tenant in query.params.values() and 'FOR NO KEY UPDATE' in str(query)
