"""REF-01D: canonical/legacy imports share security contracts without I/O."""
import os
import subprocess
import sys

import pytest


MODULES = (
    ('gateway_contracts', 'gateway.contracts'),
    ('tool_gateway', 'gateway.tool_gateway'),
    ('disclosure_policy', 'gateway.disclosure_policy'),
)


@pytest.mark.parametrize('first', [name for pair in MODULES for name in pair])
def test_fresh_import_order_identity_and_no_application_io(first):
    code = '''
import builtins, importlib, pathlib, socket, subprocess, sys
import datetime, hashlib, hmac, ipaddress, json, typing, uuid, pydantic
# Initialize third-party plugin discovery before guarding application imports.
class Warmup(pydantic.BaseModel):
    pass
sys.path.insert(0, 'services/api')
def forbidden(*args, **kwargs):
    raise AssertionError('forbidden application I/O')
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('sqlalchemy', 'psycopg', 'httpx', 'ollama')) or name in ('app.db', 'app.config', 'app.core.config'):
        raise AssertionError('forbidden infrastructure import')
    return original(name, *args, **kwargs)
for owner, name in ((builtins, 'open'), (pathlib.Path, 'open'),
                    (socket, 'socket'), (socket, 'create_connection'),
                    (subprocess, 'Popen')):
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
from app.gateway import contracts, tool_gateway, disclosure_policy
from app.iam import contracts as iam
from app.analysts import contracts as analysts
from app import wazuh_gateway, wazuh_manifest
assert iam.TrustedContext is analysts.TrustedContext is tool_gateway.TrustedContext is contracts.TrustedContext
assert wazuh_gateway.ToolRequest is tool_gateway.ToolRequest is contracts.ToolRequest
assert wazuh_manifest.Destination is disclosure_policy.Destination
assert 'app.db' not in sys.modules and 'app.config' not in sys.modules
'''.replace('PAIRS', repr(MODULES)).replace('FIRST', repr(first))
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr
