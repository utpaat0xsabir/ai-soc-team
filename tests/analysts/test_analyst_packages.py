"""REF-01B canonical imports and temporary legacy object identities."""
import importlib

import pytest


MODULES = (
    ('analyst_contracts', 'analysts.contracts'),
    ('analyst_evaluation', 'analysts.evaluation'),
    ('analyst_protocol', 'analysts.protocol'),
    ('analyst_inference', 'analysts.inference'),
    ('ollama_inference', 'analysts.providers.ollama'),
    ('ollama_prompt', 'analysts.providers.ollama_prompt'),
    ('ollama_transport', 'analysts.providers.ollama_transport'),
)


@pytest.mark.parametrize('legacy,canonical', MODULES)
def test_legacy_exports_preserve_canonical_identity(legacy, canonical):
    implementation = importlib.import_module('app.' + canonical)
    compatibility = importlib.import_module('app.' + legacy)
    exports = {name: value for name, value in vars(implementation).items()
               if not name.startswith('__')}
    assert exports
    for name, value in exports.items():
        assert getattr(compatibility, name) is value


@pytest.mark.parametrize('first', [name for pair in MODULES for name in pair])
def test_fresh_import_order_without_application_io(first):
    import os
    import subprocess
    import sys

    code = '''
import builtins, importlib, pathlib, socket, subprocess, sys
import dataclasses, datetime, hashlib, hmac, ipaddress, json, math, re, threading
import typing, unicodedata, uuid, httpx, pydantic
# Initialize third-party plugin discovery before guarding application imports.
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
pairs = PAIRS
importlib.import_module('app.' + FIRST)
for legacy, canonical in pairs:
    old = importlib.import_module('app.' + legacy)
    new = importlib.import_module('app.' + canonical)
    for name, value in vars(new).items():
        if not name.startswith('__'):
            assert getattr(old, name) is value
'''.replace('PAIRS', repr(MODULES)).replace('FIRST', repr(first))
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=30,
    )
    assert result.returncode == 0, result.stderr
