"""Identity checks shared by local PostgreSQL test tooling."""
import json
import re
import subprocess
from ipaddress import IPv4Address

_DOCKER_FORMAT = (
    '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|'
    '{{json .NetworkSettings.Ports}}|{{json .NetworkSettings.Networks}}'
)


def docker_postgres_identity(*, container_id=None, local=False, exact=None):
    if exact is not None and (not local or container_id is None):
        raise ValueError("exact target requires a local container pin")
    docker = ['docker']
    if local:
        docker.extend(('--host', 'unix:///var/run/docker.sock'))
    try:
        result = subprocess.run(
            [
                *docker, 'inspect', '--type', 'container', '--format',
                _DOCKER_FORMAT + ('|{{.Image}}' if exact is not None else ''), 'ai-soc-postgres',
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        if len(result.stdout) > 8192:
            raise ValueError('oversized Docker metadata')
        output = result.stdout.strip()
        if exact is not None:
            output, separator, image_id = output.rpartition('|')
            if not separator or image_id != exact[0]:
                raise ValueError('unexpected immutable image')
        fields = output.split('|', 5)
        if len(fields) != 6:
            raise ValueError('malformed Docker metadata')
        observed_id, name, image, status, raw_ports, raw_networks = fields
        ports = json.loads(raw_ports)
        networks = json.loads(raw_networks)
        if (
            not re.fullmatch(r'[0-9a-f]{64}', observed_id)
            or (container_id is not None and observed_id != container_id)
            or name != '/ai-soc-postgres'
            or image != 'postgres:16'
            or status != 'running'
            or ports != {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5432'}]}
            or not isinstance(networks, dict)
            or not networks
        ):
            raise ValueError('unexpected PostgreSQL container metadata')

        pairs = set()
        if exact is not None and (tuple(networks) != (exact[1],)
                                  or networks[exact[1]].get("NetworkID") != exact[2]):
            raise ValueError("unexpected network")
        if local and len(networks) != 1:
            raise ValueError("ambiguous PostgreSQL network")
        for network in networks.values():
            if not isinstance(network, dict):
                raise ValueError('malformed Docker network metadata')
            address = IPv4Address(network.get('IPAddress', ''))
            gateway = IPv4Address(network.get('Gateway', ''))
            if (address.is_unspecified or address.is_loopback or gateway.is_unspecified
                    or gateway.is_loopback or address == gateway):
                raise ValueError('invalid Docker network address')
            pairs.add((address, gateway))
        return frozenset(pairs)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        raise ValueError('cannot verify the local ai-soc-postgres container') from None
