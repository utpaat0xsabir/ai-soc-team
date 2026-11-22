"""Fail-closed target guard for PostgreSQL-backed tests."""
import json
import os
import re
import subprocess
from ipaddress import IPv4Address, ip_address
from types import FunctionType

import pytest
from sqlalchemy import Engine, event, text
from sqlalchemy.engine import make_url

from app.database.test_target import docker_postgres_identity

_ADVISORY_CONTAINER_FORMAT = (
    '{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{.State.Status}}|'
    '{{json .Config.Labels}}|{{json .NetworkSettings.Ports}}|'
    '{{json .NetworkSettings.Networks}}|{{json .Mounts}}'
)


def _engine_from_namespaces(namespaces):
    found = []
    for namespace in namespaces:
        candidate = namespace.get('engine')
        if isinstance(candidate, Engine) and all(candidate is not item for item in found):
            found.append(candidate)
        factory = namespace.get('SessionLocal')
        bind = getattr(factory, 'kw', {}).get('bind')
        if isinstance(bind, Engine) and all(bind is not item for item in found):
            found.append(bind)
    return found


def _engines_for_request(request):
    namespaces = [vars(request.module)]
    namespaces.extend(
        value.__globals__
        for value in vars(request.module).values()
        if isinstance(value, FunctionType)
    )
    for name in request.fixturenames:
        for fixture in request._fixturemanager.getfixturedefs(name, request.node) or ():
            if isinstance(fixture.func, FunctionType):
                namespaces.append(fixture.func.__globals__)
    return _engine_from_namespaces(namespaces)


def _configured_test_url(engine_url):
    raw = os.environ.get('DATABASE_URL')
    if not raw:
        raise pytest.UsageError('database tests require explicit DATABASE_URL')
    try:
        configured = make_url(raw)
    except Exception:
        raise pytest.UsageError('DATABASE_URL is malformed') from None
    if (
        configured.drivername.split('+', 1)[0] != 'postgresql'
        or configured.database != 'ai_soc_test'
        or configured.host != '127.0.0.1'
        or configured.port != 5432
        or not configured.username
        or configured.query
        or engine_url != configured
    ):
        raise pytest.UsageError('database tests require explicit ai_soc_test at 127.0.0.1:5432')
    return configured


def _advisory_env(name):
    value = os.environ.get(f'AI_SOC_ADVISORY_{name}', '')
    if not value or '\n' in value or '|' in value:
        raise pytest.UsageError('incomplete advisory test identity')
    return value


def _configured_advisory_url(engine_url):
    raw = os.environ.get('DATABASE_URL')
    if not raw:
        raise pytest.UsageError('advisory tests require explicit DATABASE_URL')
    try:
        configured = make_url(raw)
        mode = os.environ.get('AI_SOC_ADVISORY_EXECUTION', 'host')
        if mode == 'container':
            _container_advisory_identity()
            valid_endpoint = configured.host == _advisory_env('DB_HOST') == 'pg' and configured.port == 5432
        elif mode == 'host':
            port = int(_advisory_env('HOST_PORT'))
            valid_endpoint = configured.host == '127.0.0.1' and configured.port == port
        else:
            raise ValueError('unsupported advisory execution mode')
    except Exception:
        raise pytest.UsageError('advisory test configuration is malformed') from None
    if (
        configured.drivername.split('+', 1)[0] != 'postgresql'
        or configured.database != 'ai_soc_advisory_test'
        or not valid_endpoint
        or configured.password is not None
        or configured.username != _advisory_env('RUNTIME_ROLE')
        or configured.query
        or engine_url != configured
    ):
        raise pytest.UsageError('advisory tests require the explicit disposable target')
    return configured


def _container_advisory_identity():
    run_id = _advisory_env('RUN_ID')
    container_id = _advisory_env('DB_CONTAINER_ID')
    runner_id = _advisory_env('RUNNER_CONTAINER_ID')
    network_id = _advisory_env('NETWORK_ID')
    volume_name = _advisory_env('VOLUME_NAME')
    image_id = _advisory_env('RUNNER_IMAGE_ID')
    db_image_id = _advisory_env('DB_IMAGE_ID')
    if (
        not re.fullmatch(r'[0-9]{8}-[a-f0-9]{8}', run_id)
        or not re.fullmatch(r'[0-9a-f]{64}', container_id)
        or not re.fullmatch(r'[0-9a-f]{64}', runner_id)
        or not re.fullmatch(r'[0-9a-f]{64}', network_id)
        or volume_name != f'ai-soc-advisory-data-{run_id}'
        or image_id != 'sha256:db6ee5170ebce0f4d165af242e8e77addc08bd9ffc37e8b1815752cf027aa4f8'
        or not re.fullmatch(r'sha256:[0-9a-f]{64}', db_image_id)
        or _advisory_env('DB_HOST') != 'pg'
        or _advisory_env('RUNTIME_ROLE') != 'ai_soc_advisory_runner'
        or _advisory_env('MIGRATION_ROLE') != 'ai_soc_advisory_migrator'
    ):
        raise pytest.UsageError('invalid isolated advisory container identity')
    try:
        database_ip = IPv4Address(_advisory_env('DB_IP'))
        runner_ip = IPv4Address(_advisory_env('RUNNER_IP'))
    except ValueError:
        raise pytest.UsageError('invalid isolated advisory network address') from None
    if database_ip.is_loopback or database_ip.is_unspecified or runner_ip.is_loopback or runner_ip.is_unspecified or database_ip == runner_ip:
        raise pytest.UsageError('invalid isolated advisory network address')
    return database_ip, runner_ip


def _advisory_docker_identity():
    run_id = _advisory_env('RUN_ID')
    container_name = _advisory_env('CONTAINER_NAME')
    network_name = _advisory_env('NETWORK_NAME')
    volume_name = _advisory_env('VOLUME_NAME')
    expected_id = _advisory_env('CONTAINER_ID')
    image_id = _advisory_env('IMAGE_ID')
    host_port = _advisory_env('HOST_PORT')
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--type', 'container', '--format', _ADVISORY_CONTAINER_FORMAT, container_name],
            check=True, capture_output=True, text=True, timeout=3,
        )
        if len(result.stdout) > 16384:
            raise ValueError('oversized container metadata')
        fields = result.stdout.strip().split('|', 8)
        if len(fields) != 9:
            raise ValueError('malformed container metadata')
        container_id, name, image, configured_image, status, raw_labels, raw_ports, raw_networks, raw_mounts = fields
        labels, ports, networks, mounts = map(json.loads, (raw_labels, raw_ports, raw_networks, raw_mounts))
        if (
            container_id != expected_id
            or name != f'/{container_name}'
            or image != image_id
            or configured_image != 'postgres:16'
            or status != 'running'
            or labels.get('ai-soc.advisory.run') != run_id
            or labels.get('ai-soc.advisory.kind') != 'postgres'
            or ports != {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': host_port}]}
            or set(networks) != {network_name}
            or len(mounts) != 1
            or mounts[0].get('Name') != volume_name
            or mounts[0].get('Destination') != '/var/lib/postgresql/data'
        ):
            raise ValueError('unexpected disposable container metadata')
        container_network = networks[network_name]
        address = IPv4Address(container_network['IPAddress'])
        gateway = IPv4Address(container_network['Gateway'])
        network = subprocess.run(
            ['docker', 'network', 'inspect', '--format', '{{.Id}}|{{.Internal}}|{{json .Labels}}|{{json .Containers}}', network_name],
            check=True, capture_output=True, text=True, timeout=3,
        ).stdout.strip().split('|', 3)
        if len(network) != 4 or network[1] != 'true':
            raise ValueError('network is not internal')
        network_labels, endpoints = json.loads(network[2]), json.loads(network[3])
        if (
            network_labels.get('ai-soc.advisory.run') != run_id
            or set(endpoints) != {container_id}
        ):
            raise ValueError('unexpected isolated network')
        volume = subprocess.run(
            ['docker', 'volume', 'inspect', '--format', '{{.Name}}|{{json .Labels}}', volume_name],
            check=True, capture_output=True, text=True, timeout=3,
        ).stdout.strip().split('|', 1)
        if len(volume) != 2 or volume[0] != volume_name:
            raise ValueError('malformed volume metadata')
        volume_labels = json.loads(volume[1])
        if volume_labels.get('ai-soc.advisory.run') != run_id:
            raise ValueError('unexpected volume')
        if address.is_loopback or address.is_unspecified or gateway.is_unspecified:
            raise ValueError('invalid network address')
        return {address}, {gateway}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
        raise pytest.UsageError('cannot verify the isolated advisory PostgreSQL target') from None


def _docker_postgres_identity():
    try:
        return docker_postgres_identity()
    except ValueError as exc:
        raise pytest.UsageError(str(exc)) from None


def _validate_connected_target(connection, engine_url):
    advisory_run = bool(os.environ.get('AI_SOC_ADVISORY_RUN_ID'))
    if advisory_run:
        configured = _configured_advisory_url(engine_url)
        expected_database = 'ai_soc_advisory_test'
        if os.environ.get('AI_SOC_ADVISORY_EXECUTION') == 'container':
            expected_server, expected_client = _container_advisory_identity()
            expected_host = 'pg'
        else:
            container_addresses, container_gateways = _advisory_docker_identity()
            expected_server = container_addresses
            expected_client = container_gateways
            expected_host = '127.0.0.1'
    else:
        configured = _configured_test_url(engine_url)
        pairs = _docker_postgres_identity()
        expected_database = 'ai_soc_test'
        expected_host = '127.0.0.1'
    try:
        database, current_user, client_address, client_port, server_address, server_port = connection.execute(
            text(
                'SELECT current_database(), current_user, inet_client_addr(), '
                'inet_client_port(), inet_server_addr(), inet_server_port()'
            )
        ).one()
        client_address = IPv4Address(str(client_address))
        server_address = IPv4Address(str(server_address))
        if not advisory_run:
            client_matches = server_matches = (server_address, client_address) in pairs
        else:
            client_matches = client_address == expected_client if isinstance(expected_client, IPv4Address) else client_address in expected_client
            server_matches = server_address == expected_server if isinstance(expected_server, IPv4Address) else server_address in expected_server
        if (
            database != expected_database
            or not isinstance(current_user, str)
            or current_user != configured.username
            or not client_matches
            or not isinstance(client_port, int)
            or not 1 <= client_port <= 65535
            or not server_matches
            or server_port != 5432
            or configured.host != expected_host
        ):
            raise pytest.UsageError('PostgreSQL connection does not match the verified test container')
    except (TypeError, ValueError):
        raise pytest.UsageError('PostgreSQL connection identity is malformed') from None
    finally:
        connection.rollback()


@pytest.fixture(autouse=True)
def _database_test_target_guard(request):
    def install_guard(engine):
        def validate_before_connect(dialect, connection_record, cargs, cparams):
            if os.environ.get('AI_SOC_ADVISORY_RUN_ID'):
                _configured_advisory_url(engine.url)
            else:
                _configured_test_url(engine.url)

        def validate_before_use(connection):
            _validate_connected_target(connection, engine.url)

        event.listen(engine, 'do_connect', validate_before_connect)
        event.listen(engine, 'engine_connect', validate_before_use)
        request.addfinalizer(lambda e=engine, cb=validate_before_connect: event.remove(e, 'do_connect', cb))
        request.addfinalizer(lambda e=engine, cb=validate_before_use: event.remove(e, 'engine_connect', cb))

    for engine in _engines_for_request(request):
        install_guard(engine)
