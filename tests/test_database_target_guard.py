import importlib.util
import json
import subprocess
from ipaddress import IPv4Address
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

spec = importlib.util.spec_from_file_location(
    'project_test_conftest', Path(__file__).with_name('conftest.py')
)
conftest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(conftest)

GOOD_URL = 'postgresql+psycopg://test:secret@127.0.0.1:5432/ai_soc_test'
CONTAINER_ID = 'a' * 64
GOOD_PORTS = {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5432'}]}
GOOD_NETWORKS = {
    'compose_default': {'IPAddress': '198.51.100.2', 'Gateway': '198.51.100.1'},
}


class Result:
    def __init__(self, row):
        self.row = row

    def one(self):
        return self.row


class Connection:
    def __init__(self, row):
        self.row = row
        self.rolled_back = False

    def execute(self, statement):
        assert 'current_database()' in str(statement)
        assert 'inet_client_addr()' in str(statement)
        assert 'inet_server_addr()' in str(statement)
        return Result(self.row)

    def rollback(self):
        self.rolled_back = True


def inspect_output(*, container_id=CONTAINER_ID, name='/ai-soc-postgres',
                   image='postgres:16', state='running', ports=None, networks=None):
    values = (
        container_id, name, image, state,
        json.dumps(GOOD_PORTS if ports is None else ports),
        json.dumps(GOOD_NETWORKS if networks is None else networks),
    )
    return '|'.join(values) + '\n'


def setup(monkeypatch, *, url=GOOD_URL, output=None, row=None):
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setattr(
        conftest.subprocess, 'run',
        lambda args, **kwargs: SimpleNamespace(
            stdout=inspect_output() if output is None else output,
            returncode=0,
        ),
    )
    connection = Connection(row or (
        'ai_soc_test', 'test', '198.51.100.1', 54976, '198.51.100.2', 5432,
    ))
    return connection


def validate(monkeypatch, *, url=GOOD_URL, output=None, row=None):
    connection = setup(monkeypatch, url=url, output=output, row=row)
    conftest._validate_connected_target(connection, make_url(url))
    return connection


def test_valid_docker_bridge_configuration(monkeypatch):
    connection = validate(monkeypatch)
    assert connection.rolled_back


def test_explicit_advisory_url_requires_exact_disposable_database_and_no_password(monkeypatch):
    url = 'postgresql+psycopg://ai_soc_advisory_runner@127.0.0.1:49123/ai_soc_advisory_test'
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setenv('AI_SOC_ADVISORY_RUNTIME_ROLE', 'ai_soc_advisory_runner')
    monkeypatch.setenv('AI_SOC_ADVISORY_HOST_PORT', '49123')
    assert conftest._configured_advisory_url(make_url(url)) == make_url(url)


@pytest.mark.parametrize('url', [
    'postgresql+psycopg://ai_soc_advisory_runner@127.0.0.1:49123/ai_soc_test',
    'postgresql+psycopg://ai_soc_advisory_runner:secret@127.0.0.1:49123/ai_soc_advisory_test',
    'postgresql+psycopg://ai_soc_advisory_runner@0.0.0.0:49123/ai_soc_advisory_test',
])
def test_advisory_url_rejects_shared_password_or_non_loopback_target(monkeypatch, url):
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setenv('AI_SOC_ADVISORY_RUNTIME_ROLE', 'ai_soc_advisory_runner')
    monkeypatch.setenv('AI_SOC_ADVISORY_HOST_PORT', '49123')
    with pytest.raises(pytest.UsageError):
        conftest._configured_advisory_url(make_url(url))


def test_advisory_container_requires_labeled_internal_network_and_owned_volume(monkeypatch):
    run_id = '20261116-1234abcd'
    values = {
        'RUN_ID': run_id,
        'CONTAINER_NAME': f'ai-soc-advisory-pg-{run_id}',
        'NETWORK_NAME': f'ai-soc-advisory-net-{run_id}',
        'VOLUME_NAME': f'ai-soc-advisory-data-{run_id}',
        'CONTAINER_ID': 'b' * 64,
        'IMAGE_ID': 'sha256:' + 'c' * 64,
        'HOST_PORT': '49123',
    }
    for key, value in values.items():
        monkeypatch.setenv(f'AI_SOC_ADVISORY_{key}', value)
    run_label = {'ai-soc.advisory.run': run_id}
    container_json = '|'.join([
        values['CONTAINER_ID'], '/' + values['CONTAINER_NAME'], values['IMAGE_ID'], 'postgres:16', 'running',
        json.dumps({**run_label, 'ai-soc.advisory.kind': 'postgres'}),
        json.dumps({'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '49123'}]}),
        json.dumps({values['NETWORK_NAME']: {'IPAddress': '172.30.0.2', 'Gateway': '172.30.0.1'}}),
        json.dumps([{'Name': values['VOLUME_NAME'], 'Destination': '/var/lib/postgresql/data'}]),
    ])
    outputs = [
        container_json,
        'd' * 12 + '|true|' + json.dumps(run_label) + '|' + json.dumps({values['CONTAINER_ID']: {}}),
        values['VOLUME_NAME'] + '|' + json.dumps(run_label),
    ]
    monkeypatch.setattr(conftest.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(stdout=outputs.pop(0)))
    addresses, gateways = conftest._advisory_docker_identity()
    assert addresses == {IPv4Address('172.30.0.2')}
    assert gateways == {IPv4Address('172.30.0.1')}


def test_advisory_container_runner_requires_exact_database_role_and_peer_ips(monkeypatch):
    run_id = '20261116-1234abcd'
    url = 'postgresql+psycopg://ai_soc_advisory_runner@pg:5432/ai_soc_advisory_test'
    values = {
        'RUN_ID': run_id,
        'EXECUTION': 'container',
        'DB_CONTAINER_ID': 'a' * 64,
        'DB_IMAGE_ID': 'sha256:' + 'b' * 64,
        'DB_IP': '172.30.0.2',
        'RUNNER_CONTAINER_ID': 'c' * 64,
        'RUNNER_IMAGE_ID': 'sha256:db6ee5170ebce0f4d165af242e8e77addc08bd9ffc37e8b1815752cf027aa4f8',
        'RUNNER_IP': '172.30.0.3',
        'NETWORK_ID': 'd' * 64,
        'VOLUME_NAME': f'ai-soc-advisory-data-{run_id}',
        'DB_HOST': 'pg',
        'RUNTIME_ROLE': 'ai_soc_advisory_runner',
        'MIGRATION_ROLE': 'ai_soc_advisory_migrator',
    }
    monkeypatch.setenv('DATABASE_URL', url)
    for name, value in values.items():
        monkeypatch.setenv(f'AI_SOC_ADVISORY_{name}', value)
    row = ('ai_soc_advisory_test', 'ai_soc_advisory_runner', '172.30.0.3', 40712, '172.30.0.2', 5432)
    connection = Connection(row)
    conftest._validate_connected_target(connection, make_url(url))
    assert connection.rolled_back


@pytest.mark.parametrize('row', [
    ('ai_soc_test', 'ai_soc_advisory_runner', '172.30.0.3', 40712, '172.30.0.2', 5432),
    ('ai_soc_advisory_test', 'ai_soc', '172.30.0.3', 40712, '172.30.0.2', 5432),
    ('ai_soc_advisory_test', 'ai_soc_advisory_runner', '172.30.0.9', 40712, '172.30.0.2', 5432),
    ('ai_soc_advisory_test', 'ai_soc_advisory_runner', '172.30.0.3', 40712, '172.30.0.9', 5432),
])
def test_advisory_container_rejects_wrong_sql_identity(monkeypatch, row):
    url = 'postgresql+psycopg://ai_soc_advisory_runner@pg:5432/ai_soc_advisory_test'
    monkeypatch.setenv('DATABASE_URL', url)
    values = {
        'RUN_ID': '20261116-1234abcd', 'EXECUTION': 'container',
        'DB_CONTAINER_ID': 'a' * 64, 'DB_IMAGE_ID': 'sha256:' + 'b' * 64,
        'DB_IP': '172.30.0.2', 'RUNNER_CONTAINER_ID': 'c' * 64,
        'RUNNER_IMAGE_ID': 'sha256:db6ee5170ebce0f4d165af242e8e77addc08bd9ffc37e8b1815752cf027aa4f8',
        'RUNNER_IP': '172.30.0.3', 'NETWORK_ID': 'd' * 64,
        'VOLUME_NAME': 'ai-soc-advisory-data-20261116-1234abcd', 'DB_HOST': 'pg',
        'RUNTIME_ROLE': 'ai_soc_advisory_runner', 'MIGRATION_ROLE': 'ai_soc_advisory_migrator',
    }
    for name, value in values.items():
        monkeypatch.setenv(f'AI_SOC_ADVISORY_{name}', value)
    connection = Connection(row)
    with pytest.raises(pytest.UsageError, match='connection does not match'):
        conftest._validate_connected_target(connection, make_url(url))
    assert connection.rolled_back


def test_missing_database_url_fails_closed(monkeypatch):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    monkeypatch.setattr(conftest.subprocess, 'run', lambda *a, **k: pytest.fail('Docker must not be inspected'))
    with pytest.raises(pytest.UsageError, match='explicit DATABASE_URL'):
        conftest._validate_connected_target(Connection(()), make_url(GOOD_URL))


def test_empty_database_url_fails_closed(monkeypatch):
    setup(monkeypatch, url='')
    with pytest.raises(pytest.UsageError, match='explicit DATABASE_URL'):
        conftest._configured_test_url(make_url(GOOD_URL))


@pytest.mark.parametrize('url', [
    GOOD_URL.replace('/ai_soc_test', '/ai_soc'),
    GOOD_URL.replace('/ai_soc_test', '/other_db'),
])
def test_wrong_database_fails_closed(monkeypatch, url):
    setup(monkeypatch, url=url)
    with pytest.raises(pytest.UsageError, match='explicit ai_soc_test'):
        conftest._configured_test_url(make_url(url))


def test_non_loopback_client_endpoint_fails_closed(monkeypatch):
    url = GOOD_URL.replace('127.0.0.1', '192.0.2.4')
    setup(monkeypatch, url=url)
    with pytest.raises(pytest.UsageError, match='explicit ai_soc_test'):
        conftest._configured_test_url(make_url(url))


def test_unexpected_client_port_fails_closed(monkeypatch):
    url = GOOD_URL.replace(':5432/', ':5433/')
    setup(monkeypatch, url=url)
    with pytest.raises(pytest.UsageError, match='explicit ai_soc_test'):
        conftest._configured_test_url(make_url(url))


def test_engine_target_must_match_explicit_url(monkeypatch):
    setup(monkeypatch)
    engine_url = make_url(GOOD_URL.replace('ai_soc_test', 'ai_soc'))
    with pytest.raises(pytest.UsageError, match='explicit ai_soc_test'):
        conftest._configured_test_url(engine_url)


def test_ambiguous_connection_query_parameters_fail_closed(monkeypatch):
    url = GOOD_URL + '?hostaddr=127.0.0.1'
    setup(monkeypatch, url=url)
    with pytest.raises(pytest.UsageError, match='explicit ai_soc_test'):
        conftest._configured_test_url(make_url(url))


def test_missing_docker_container_fails_closed(monkeypatch):
    setup(monkeypatch, output='')
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._validate_connected_target(Connection(()), make_url(GOOD_URL))


def test_stopped_docker_container_fails_closed(monkeypatch):
    setup(monkeypatch, output=inspect_output(state='exited'))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_wrong_docker_image_fails_closed(monkeypatch):
    setup(monkeypatch, output=inspect_output(image='postgres:15'))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_wrong_container_name_fails_closed(monkeypatch):
    setup(monkeypatch, output=inspect_output(name='/other-postgres'))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


@pytest.mark.parametrize('ports', [
    {'5432/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '5432'}]},
    {'5432/tcp': [{'HostIp': '::', 'HostPort': '5432'}]},
])
def test_wildcard_host_binding_fails_closed(monkeypatch, ports):
    setup(monkeypatch, output=inspect_output(ports=ports))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_multiple_host_bindings_fail_closed(monkeypatch):
    ports = {'5432/tcp': [
        {'HostIp': '127.0.0.1', 'HostPort': '5432'},
        {'HostIp': '0.0.0.0', 'HostPort': '5432'},
    ]}
    setup(monkeypatch, output=inspect_output(ports=ports))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_additional_published_port_fails_closed(monkeypatch):
    ports = {**GOOD_PORTS, '5433/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '5433'}]}
    setup(monkeypatch, output=inspect_output(ports=ports))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_missing_container_ip_fails_closed(monkeypatch):
    setup(monkeypatch, output=inspect_output(networks={
        'compose_default': {'IPAddress': '', 'Gateway': '172.18.0.1'},
    }))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_wrong_postgresql_database_fails_closed(monkeypatch):
    setup(monkeypatch)
    with pytest.raises(pytest.UsageError, match='connection does not match'):
        conftest._validate_connected_target(Connection(('ai_soc', 'test', '198.51.100.1', 54976,
                                                       '198.51.100.2', 5432)), make_url(GOOD_URL))


def test_server_address_must_match_inspected_container(monkeypatch):
    setup(monkeypatch)
    with pytest.raises(pytest.UsageError, match='connection does not match'):
        conftest._validate_connected_target(Connection(('ai_soc_test', 'test', '198.51.100.1', 54976,
                                                       '198.51.100.9', 5432)), make_url(GOOD_URL))


def test_server_port_must_match_container_port(monkeypatch):
    setup(monkeypatch)
    with pytest.raises(pytest.UsageError, match='connection does not match'):
        conftest._validate_connected_target(Connection(('ai_soc_test', 'test', '198.51.100.1', 54976,
                                                       '198.51.100.2', 5433)), make_url(GOOD_URL))


def test_client_address_must_match_docker_gateway(monkeypatch):
    setup(monkeypatch)
    with pytest.raises(pytest.UsageError, match='connection does not match'):
        conftest._validate_connected_target(Connection(('ai_soc_test', 'test', '198.51.100.9', 54976,
                                                       '198.51.100.2', 5432)), make_url(GOOD_URL))


def test_connected_user_must_match_explicit_database_url(monkeypatch):
    setup(monkeypatch)
    with pytest.raises(pytest.UsageError, match='connection does not match'):
        conftest._validate_connected_target(Connection(('ai_soc_test', 'other_user', '198.51.100.1', 54976,
                                                       '198.51.100.2', 5432)), make_url(GOOD_URL))


def test_docker_inspection_failure_fails_closed(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(conftest.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(
        subprocess.CalledProcessError(1, 'docker inspect')))
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_malformed_docker_metadata_fails_closed(monkeypatch):
    setup(monkeypatch, output='not|valid|json|metadata|{bad}|{}')
    with pytest.raises(pytest.UsageError, match='cannot verify'):
        conftest._docker_postgres_identity()


def test_engine_from_secondary_fixture_is_covered():
    engine = create_engine(GOOD_URL)
    factory = sessionmaker(bind=engine)
    def fixture():
        pass
    imported_fixture = FunctionType(fixture.__code__, {'SessionLocal': factory})

    class FixtureManager:
        def getfixturedefs(self, name, node):
            return [SimpleNamespace(func=imported_fixture)]

    request = SimpleNamespace(
        module=SimpleNamespace(), fixturenames=['database_session'],
        _fixturemanager=FixtureManager(), node=object(),
    )
    try:
        assert conftest._engines_for_request(request) == [engine]
    finally:
        engine.dispose()


def test_multiple_engines_validate_their_own_targets(monkeypatch):
    engines = [SimpleNamespace(url="unapproved"), SimpleNamespace(url="approved")]
    callbacks = {}
    checked = []
    request = SimpleNamespace(addfinalizer=lambda callback: None)
    monkeypatch.delenv("AI_SOC_ADVISORY_RUN_ID", raising=False)
    monkeypatch.setattr(conftest, "_engines_for_request", lambda request: engines)
    monkeypatch.setattr(conftest.event, "listen",
                        lambda engine, name, handler: callbacks.update({(engine.url, name): handler}))

    def validate(url):
        checked.append(url)
        if url == "unapproved":
            raise pytest.UsageError("unapproved target")

    monkeypatch.setattr(conftest, "_configured_test_url", validate)
    monkeypatch.setattr(conftest, "_validate_connected_target", lambda connection, url: validate(url))
    conftest._database_test_target_guard.__wrapped__(request)

    with pytest.raises(pytest.UsageError, match="unapproved target"):
        callbacks["unapproved", "do_connect"](None, None, [], {})
    with pytest.raises(pytest.UsageError, match="unapproved target"):
        callbacks["unapproved", "engine_connect"](object())
    callbacks["approved", "do_connect"](None, None, [], {})
    callbacks["approved", "engine_connect"](object())
    assert checked == ["unapproved", "unapproved", "approved", "approved"]
