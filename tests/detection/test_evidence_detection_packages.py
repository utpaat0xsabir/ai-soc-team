"""REF-01F identity and fresh-process imports without application I/O."""
import os
import subprocess
import sys

import pytest


MODULES = (
    ('evidence', 'evidence.hashing'),
    ('security_events', 'detection.security_events'),
    ('detection_rules', 'detection.rules'),
    ('event_correlation', 'detection.correlation'),
)


@pytest.mark.parametrize('first', [name for pair in MODULES for name in pair])
def test_fresh_import_order_identity_without_application_io(first):
    code = '''
import builtins, importlib, pathlib, socket, subprocess, sys
import datetime, hashlib, hmac, ipaddress, json, math, re, typing, uuid, httpx, pydantic
class Warmup(pydantic.BaseModel):
    pass
sys.path.insert(0, 'services/api')
def forbidden(*args, **kwargs):
    raise AssertionError('forbidden application I/O')
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('sqlalchemy', 'psycopg')) or name in ('app.db', 'app.config', 'app.core.config'):
        raise AssertionError('forbidden infrastructure import')
    return original(name, *args, **kwargs)
for owner, name in ((builtins, 'open'), (pathlib.Path, 'open'),
                    (socket, 'socket'), (socket, 'create_connection'),
                    (subprocess, 'Popen'), (httpx.Client, 'send'),
                    (httpx.HTTPTransport, '__init__')):
    setattr(owner, name, forbidden)
builtins.__import__ = guarded
importlib.import_module('app.' + FIRST)
for old, new in PAIRS:
    legacy = importlib.import_module('app.' + old)
    canonical = importlib.import_module('app.' + new)
    for name, value in vars(canonical).items():
        if not name.startswith('__'):
            assert getattr(legacy, name) is value
from app.evidence import hashing
from app.detection import security_events, rules, correlation
from app.analysts import contracts
assert contracts.calculate_evidence_hash is security_events.calculate_evidence_hash is hashing.calculate_evidence_hash
assert correlation.NormalizedSecurityEvent is rules.NormalizedSecurityEvent is security_events.NormalizedSecurityEvent
assert correlation.DetectionRule is rules.DetectionRule
assert correlation.DetectionMatch is rules.DetectionMatch
assert correlation.match_event is rules.match_event
assert 'app.db' not in sys.modules and 'app.config' not in sys.modules
'''.replace('PAIRS', repr(MODULES)).replace('FIRST', repr(first))
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr
