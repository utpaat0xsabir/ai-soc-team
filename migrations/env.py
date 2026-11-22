import os
import sys
import json
import re
import subprocess
from logging.config import fileConfig
from ipaddress import IPv4Address

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy import text
from sqlalchemy.engine import make_url

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

API_PATH = os.path.join(PROJECT_ROOT, "services", "api")

sys.path.insert(0, API_PATH)

from app.database.migration_guard import (
    Denied, check_legacy_revisions, deny_purge, guarded_environment, restrict_legacy_context,
    run_guarded_environment, run_locked_legacy, verify_legacy_heads,
)
from app.database.models import Base, Tenant, EvidenceRecord, EvidenceLineage, TenantAPIKey, AuditLog, WazuhIntegration, WazuhSyncCheckpoint, WazuhSyncLease  # noqa: F401,E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _advisory_migration_target(connection):
    """Fail closed before DDL when running the explicitly opted-in disposable migration."""
    run_id = os.environ.get("AI_SOC_ADVISORY_RUN_ID")
    if not run_id:
        return
    execution = os.environ.get("AI_SOC_ADVISORY_EXECUTION", "host")
    if execution not in {"host", "container"}:
        raise RuntimeError("unsupported advisory migration execution mode")
    if execution == "container":
        raw_url = os.environ.get("DATABASE_URL")
        expected = {
            name: os.environ.get(f"AI_SOC_ADVISORY_{name}", "")
            for name in (
                "DB_CONTAINER_ID", "DB_IMAGE_ID", "DB_IP", "RUNNER_CONTAINER_ID",
                "RUNNER_IMAGE_ID", "RUNNER_IP", "NETWORK_ID", "VOLUME_NAME",
                "DB_HOST", "MIGRATION_ROLE", "RUNTIME_ROLE",
            )
        }
        if (
            not re.fullmatch(r"[0-9]{8}-[a-f0-9]{8}", run_id)
            or not raw_url
            or any(not value or "|" in value or "\n" in value for value in expected.values())
            or not re.fullmatch(r"[0-9a-f]{64}", expected["DB_CONTAINER_ID"])
            or not re.fullmatch(r"[0-9a-f]{64}", expected["RUNNER_CONTAINER_ID"])
            or not re.fullmatch(r"[0-9a-f]{64}", expected["NETWORK_ID"])
            or expected["VOLUME_NAME"] != f"ai-soc-advisory-data-{run_id}"
            or expected["DB_HOST"] != "pg"
            or expected["MIGRATION_ROLE"] != "ai_soc_advisory_migrator"
            or expected["RUNTIME_ROLE"] != "ai_soc_advisory_runner"
            or expected["RUNNER_IMAGE_ID"] != "sha256:db6ee5170ebce0f4d165af242e8e77addc08bd9ffc37e8b1815752cf027aa4f8"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected["DB_IMAGE_ID"])
        ):
            raise RuntimeError("advisory container migration identity is incomplete")
        url = make_url(raw_url)
        if (
            url.drivername.split("+", 1)[0] != "postgresql"
            or url.database != "ai_soc_advisory_test"
            or url.username != expected["MIGRATION_ROLE"]
            or url.host != expected["DB_HOST"]
            or url.port != 5432
            or url.password is not None
            or url.query
        ):
            raise RuntimeError("advisory migration URL is not the explicit private target")
        database, current_user, client_address, server_address, server_port = connection.execute(
            text("SELECT current_database(), current_user, inet_client_addr(), inet_server_addr(), inet_server_port()")
        ).one()
        if (
            database != "ai_soc_advisory_test"
            or current_user != expected["MIGRATION_ROLE"]
            or IPv4Address(str(server_address)) != IPv4Address(expected["DB_IP"])
            or IPv4Address(str(client_address)) != IPv4Address(expected["RUNNER_IP"])
            or server_port != 5432
        ):
            raise RuntimeError("connected PostgreSQL identity does not match the isolated migration target")
        connection.rollback()
        return
    raw_url = os.environ.get("DATABASE_URL")
    expected = {
        "RUN_ID": run_id,
        "CONTAINER_ID": os.environ.get("AI_SOC_ADVISORY_CONTAINER_ID", ""),
        "CONTAINER_NAME": os.environ.get("AI_SOC_ADVISORY_CONTAINER_NAME", ""),
        "NETWORK_NAME": os.environ.get("AI_SOC_ADVISORY_NETWORK_NAME", ""),
        "VOLUME_NAME": os.environ.get("AI_SOC_ADVISORY_VOLUME_NAME", ""),
        "IMAGE_ID": os.environ.get("AI_SOC_ADVISORY_IMAGE_ID", ""),
        "HOST_PORT": os.environ.get("AI_SOC_ADVISORY_HOST_PORT", ""),
        "MIGRATION_ROLE": os.environ.get("AI_SOC_ADVISORY_MIGRATION_ROLE", ""),
    }
    if (
        not re.fullmatch(r"[a-z0-9-]{8,40}", run_id)
        or not raw_url
        or any(not value or "|" in value or "\n" in value for value in expected.values())
    ):
        raise RuntimeError("advisory migration target configuration is incomplete")
    url = make_url(raw_url)
    host_port = int(expected["HOST_PORT"])
    if (
        url.drivername.split("+", 1)[0] != "postgresql"
        or url.database != "ai_soc_advisory_test"
        or url.username != expected["MIGRATION_ROLE"]
        or url.host != "127.0.0.1"
        or url.port != host_port
        or url.password is not None
        or url.query
    ):
        raise RuntimeError("advisory migration URL is not the explicit disposable target")
    container_format = (
        "{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{.State.Status}}|"
        "{{json .Config.Labels}}|{{json .NetworkSettings.Ports}}|"
        "{{json .NetworkSettings.Networks}}|{{json .Mounts}}"
    )
    try:
        output = subprocess.run(
            ["docker", "inspect", "--type", "container", "--format", container_format, expected["CONTAINER_NAME"]],
            check=True, capture_output=True, text=True, timeout=3,
        ).stdout.strip().split("|", 8)
        if len(output) != 9:
            raise ValueError("container metadata")
        container_id, name, image, configured_image, state, raw_labels, raw_ports, raw_networks, raw_mounts = output
        labels, ports, networks, mounts = map(json.loads, (raw_labels, raw_ports, raw_networks, raw_mounts))
        bootstrap_source = os.environ.get("AI_SOC_ADVISORY_BOOTSTRAP_SOURCE")
        mounts_valid = (
            len(mounts) == 1
            and mounts[0].get("Type") == "volume"
            and mounts[0].get("Name") == expected["VOLUME_NAME"]
            and mounts[0].get("Destination") == "/var/lib/postgresql/data"
        )
        if bootstrap_source:
            mounts_valid = (
                len(mounts) == 2
                and any(
                    mount.get("Type") == "volume"
                    and mount.get("Name") == expected["VOLUME_NAME"]
                    and mount.get("Destination") == "/var/lib/postgresql/data"
                    for mount in mounts
                )
                and any(
                    mount.get("Type") == "bind"
                    and mount.get("Source") == bootstrap_source
                    and mount.get("Destination") == "/run/bootstrap"
                    and mount.get("RW") is False
                    for mount in mounts
                )
            )
        if (
            container_id != expected["CONTAINER_ID"]
            or name != f"/{expected['CONTAINER_NAME']}"
            or image != expected["IMAGE_ID"]
            or configured_image != "postgres:16"
            or state != "running"
            or labels.get("ai-soc.advisory.run") != run_id
            or labels.get("ai-soc.advisory.kind") != "postgres"
            or ports != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}]}
            or set(networks) != {expected["NETWORK_NAME"]}
            or not mounts_valid
        ):
            raise ValueError("container identity")
        network_output = subprocess.run(
            ["docker", "network", "inspect", "--format", "{{.Internal}}|{{json .Labels}}|{{json .Containers}}", expected["NETWORK_NAME"]],
            check=True, capture_output=True, text=True, timeout=3,
        ).stdout.strip().split("|", 2)
        volume_output = subprocess.run(
            ["docker", "volume", "inspect", "--format", "{{.Name}}|{{json .Labels}}", expected["VOLUME_NAME"]],
            check=True, capture_output=True, text=True, timeout=3,
        ).stdout.strip().split("|", 1)
        if (
            len(network_output) != 3
            or network_output[0] != "true"
            or json.loads(network_output[1]).get("ai-soc.advisory.run") != run_id
            or set(json.loads(network_output[2])) != {container_id}
            or len(volume_output) != 2
            or volume_output[0] != expected["VOLUME_NAME"]
            or json.loads(volume_output[1]).get("ai-soc.advisory.run") != run_id
        ):
            raise ValueError("isolated resource identity")
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError("cannot verify isolated advisory migration container") from None
    database, current_user, client_address, server_address, server_port = connection.execute(
        text("SELECT current_database(), current_user, inet_client_addr(), inet_server_addr(), inet_server_port()")
    ).one()
    network = networks[expected["NETWORK_NAME"]]
    if (
        database != "ai_soc_advisory_test"
        or current_user != expected["MIGRATION_ROLE"]
        or IPv4Address(str(server_address)) != IPv4Address(network["IPAddress"])
        or IPv4Address(str(client_address)) != IPv4Address(network["Gateway"])
        or server_port != 5432
    ):
        raise RuntimeError("connected PostgreSQL identity does not match isolated migration target")
    connection.rollback()


def run_migrations_offline():
    if os.environ.get("AI_SOC_ADVISORY_RUN_ID"):
        raise RuntimeError("offline migrations are forbidden for advisory disposable target")
    from app.core.config import settings

    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    run_legacy_migrations()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section) or {}
    disposable = bool(os.environ.get("AI_SOC_ADVISORY_RUN_ID"))
    if disposable and os.environ.get("AI_SOC_ADVISORY_EXECUTION", "host") not in {"host", "container"}:
        raise RuntimeError("unsupported advisory migration execution mode")
    if disposable:
        database_url = os.environ.get("DATABASE_URL")
    else:
        from app.core.config import settings

        database_url = settings.database_url
    configuration["sqlalchemy.url"] = database_url.replace("%", "%%")

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    try:
        with connectable.connect() as connection:
            _advisory_migration_target(connection)
            run_locked_legacy(context, target_metadata, connection)
    finally:
        connectable.dispose()


def run_legacy_migrations():
    migration = context.get_context()
    deny_purge(migration)
    restrict_legacy_context(migration)
    with context.begin_transaction():
        verify_legacy_heads(migration.get_current_heads())
        context.run_migrations()


def main():
    active = guarded_environment()
    if active is not None:
        run_guarded_environment(context, active, target_metadata)
        return
    if "connection" in config.attributes:
        raise Denied("guarded_connection_required")
    try:
        destination = context.get_revision_argument()
    except KeyError:
        # Commands such as autogenerate have no explicit destination.
        destination = None
    if destination:
        check_legacy_revisions((destination,) if isinstance(destination, str) else destination)
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()


main()
