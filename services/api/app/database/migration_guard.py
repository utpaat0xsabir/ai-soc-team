"""Guarded AI-05B upgrades for a trusted local host, Docker daemon, and revision source.

The SQL boundary covers the supplied SQLAlchemy connection. Direct driver use,
server routines with side effects, and replay of offline SQL are outside it.
Provisioning must independently enforce database login/CONNECT restrictions,
trusted function ownership and ACLs, and isolation from administrative writers.
"""
from contextlib import ExitStack
from contextvars import ContextVar
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import IPv4Address, ip_address
from pathlib import Path
import re
import ssl
from tempfile import TemporaryDirectory

from alembic import command
from alembic.runtime.migration import RevisionStep
from alembic.script import ScriptDirectory
from psycopg import Cursor
from sqlalchemy import create_engine, event, pool, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.database.roles import APPLICATION_TABLES
from app.database.source_registry_migration_plan import STAGED_REVISION, verify_legacy_audit
from app.database.test_target import docker_postgres_identity


BASELINE = "d93c6e4fb132"
LOCK_KEY = 58051002241001
LOGIN = "ai_soc_test_migrator"
OWNER = "ai_soc_test_owner"
TARGET = "ai_soc_test"
# Freeze the compatibility set. Every new revision requires the guarded path.
LEGACY = frozenset({
    "6cf3679d8b90", "1e6b673facf2", "211e576b1806", "20d4e84d93ca",
    "5ad5e0e78db3", "013505dd4ffd", "b71a4c2d9e10", "c82b5d3ea021", BASELINE,
})
_ACTIVE = ContextVar("guarded_migration", default=None)


class Denied(RuntimeError):
    """A fixed, non-secret denial reason."""


@dataclass(frozen=True)
class Request:
    request_id: str
    container_id: str
    predecessor: str
    successor: str
    database_url: str = field(repr=False)


@dataclass(frozen=True)
class B4Transport:
    """Transport supplied only by a separately authorized, trusted rehearsal caller."""

    container_id: str
    image_id: str
    network: str
    network_id: str
    address_pair: tuple[IPv4Address, IPv4Address]
    ca_sha256: str
    ca: bytes = field(repr=False)


def _b4_connect_args(pin, request, cleanup):
    if (type(pin) is not B4Transport or pin.container_id != request.container_id
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin.image_id)
            or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", pin.network)
            or not re.fullmatch(r"[0-9a-f]{64}", pin.network_id)
            or type(pin.address_pair) is not tuple or len(pin.address_pair) != 2
            or any(type(ip) is not IPv4Address or ip.is_loopback or ip.is_unspecified for ip in pin.address_pair)
            or pin.address_pair[0] == pin.address_pair[1]
            or type(pin.ca) is not bytes or not 0 < len(pin.ca) <= 256_000
            or sha256(pin.ca).hexdigest() != pin.ca_sha256):
        raise Denied("b4_transport_required")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pin.ca.decode("ascii"))
    except (UnicodeError, ssl.SSLError):
        raise Denied("b4_transport_required") from None
    ca_path = Path(cleanup.enter_context(TemporaryDirectory(prefix="b4-migration-ca-", dir="/tmp"))) / "approved.pem"
    ca_path.write_bytes(pin.ca)
    return {"sslmode": "verify-full", "sslrootcert": str(ca_path), "sslcertmode": "disable",
            "gssencmode": "disable", "channel_binding": "require", "passfile": "/dev/null"}


def validate_request(request, environ):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request.request_id):
        raise Denied("invalid_request_id")
    if not re.fullmatch(r"[0-9a-f]{64}", request.container_id):
        raise Denied("invalid_container_id")
    if (not re.fullmatch(r"[0-9a-f]{12}", request.predecessor)
            or not re.fullmatch(r"[0-9a-f]{12}", request.successor)
            or request.successor in LEGACY or request.predecessor == request.successor
            or (request.predecessor in LEGACY and request.predecessor != BASELINE)):
        raise Denied("invalid_revision_request")
    if any(key.startswith("PG") or key in {"DOCKER_CONTEXT", "DOCKER_HOST", "AI_SOC_ADVISORY_RUN_ID"}
           for key in environ):
        raise Denied("ambient_connection_configuration")
    try:
        url = make_url(request.database_url)
        valid = (url.drivername == "postgresql+psycopg" and url.host == "127.0.0.1"
                 and url.port == 5432 and url.database == TARGET and url.username == LOGIN
                 and bool(url.password) and not url.query)
    except (ArgumentError, ValueError, TypeError):
        valid = False
    if not valid or "?" in request.database_url:
        raise Denied("invalid_explicit_target")
    return url


def validate_graph(script, request):
    if tuple(script.get_heads()) != (request.successor,):
        raise Denied("unexpected_repository_heads")
    revision = script.get_revision(request.successor)
    if (revision.revision != request.successor or revision.down_revision != request.predecessor
            or revision.dependencies or revision.branch_labels):
        raise Denied("unexpected_upgrade_path")


def check_legacy_revisions(revisions):
    if not set(revisions) <= LEGACY:
        raise Denied("guarded_migration_required")


def restrict_legacy_context(migration):
    """Check the actual Alembic plan, including stamp and downgrade endpoints."""
    plan = migration._migrations_fn

    def legacy_steps(heads, context):
        verify_legacy_heads(heads)
        steps = list(plan(heads, context))
        for step in steps:
            check_legacy_revisions((*step.from_revisions, *step.to_revisions))
        return steps

    migration._migrations_fn = legacy_steps


def verify_identity(connection, addresses, expected_role):
    database, login, role, server, client, port, client_port = connection.execute(text("""
        SELECT current_database(), session_user, current_user, inet_server_addr(),
               inet_client_addr(), inet_server_port(), inet_client_port()
    """)).one()
    if type(addresses) is B4Transport:
        addresses = (addresses.address_pair,)
    if (database != TARGET or login != LOGIN or role != expected_role or port != 5432
            or (ip_address(server), ip_address(client)) not in addresses
            or not 1 <= client_port <= 65535):
        raise Denied("connected_identity_mismatch")


def approved_role_graph(oids, names, grants, options, unrestricted_oids):
    """Validate the exact protected graph, including dormant and ADMIN-only edges."""
    if (not all(isinstance(rows, (tuple, list)) for rows in (oids, names, grants, options, unrestricted_oids))
            or len(oids) != len(names) or len(grants) != len(options)
            or any(type(oid) is not int or oid <= 0 for oid in oids)
            or any(type(name) is not str or not name for name in names)
            or len(set(names)) != len(names) or len(set(oids)) != len(oids)):
        return False
    roles = dict(zip(oids, names))
    if (any(type(oid) is not int or oid not in roles for oid in unrestricted_oids)
            or len(set(unrestricted_oids)) != len(unrestricted_oids)):
        return False
    unrestricted = {roles[oid] for oid in unrestricted_oids}
    edges = {}
    for grant, flags in zip(grants, options):
        if (not isinstance(grant, (list, tuple)) or len(grant) != 3
                or any(type(oid) is not int or oid not in roles for oid in grant)
                or not isinstance(flags, (list, tuple)) or len(flags) != 3
                or any(type(flag) is not bool for flag in flags)):
            return False
        member, target = (roles[oid] for oid in grant[:2])
        if member == target or (member, target) in edges:
            return False
        edges[member, target] = tuple(flags)
    if not {LOGIN, OWNER} <= set(names) or edges.get((LOGIN, OWNER)) != (False, False, True):
        return False
    # Cluster-wide predefined roles can bypass file or audit controls without an owner grant.
    unrestricted.update({"pg_write_all_data", "pg_write_server_files", "pg_read_server_files",
                         "pg_execute_server_program"})
    if any(target in unrestricted for _, target in edges):
        return False
    # Any chain into or out of the protected pair must cross this cut. Reject
    # every unapproved crossing, including edges whose options are all off.
    return all(edge == (LOGIN, OWNER) or not {LOGIN, OWNER}.intersection(edge) for edge in edges)


def verify_roles(connection):
    if not connection.execute(text(
        "SELECT current_setting('server_version_num')::integer / 10000 = 16"
    )).scalar_one():
        raise Denied("unsupported_postgresql_version")
    params = {"login": LOGIN, "owner": OWNER}
    roles = dict(connection.execute(text("""
        SELECT rolname, ARRAY[rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                              rolreplication, rolbypassrls, rolinherit]
        FROM pg_roles WHERE rolname IN (:login, :owner)
    """), params).all())
    if roles != {LOGIN: [True, False, False, False, False, False, False],
                 OWNER: [False, False, False, False, False, False, False]}:
        raise Denied("migration_roles_not_approved")
    roles_and_memberships = connection.execute(text("""
        SELECT ARRAY(SELECT oid FROM pg_catalog.pg_roles ORDER BY oid),
               ARRAY(SELECT rolname::text FROM pg_catalog.pg_roles ORDER BY oid),
               ARRAY(SELECT ARRAY[member, roleid, grantor] FROM pg_catalog.pg_auth_members
                     ORDER BY member, roleid, grantor),
               ARRAY(SELECT ARRAY[admin_option, inherit_option, set_option]
                     FROM pg_catalog.pg_auth_members ORDER BY member, roleid, grantor),
               ARRAY(SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolsuper OR rolreplication OR rolbypassrls ORDER BY oid)
    """)).one()
    if not approved_role_graph(*roles_and_memberships):
        raise Denied("migration_memberships_not_approved")
    db_owner, schema_owner = connection.execute(text("""
        SELECT pg_get_userbyid(datdba), pg_get_userbyid(nspowner)
        FROM pg_database CROSS JOIN pg_namespace
        WHERE datname = current_database() AND nspname = 'public'
    """)).one()
    if db_owner != OWNER or schema_owner not in (OWNER, "pg_database_owner"):
        raise Denied("migration_ownership_mismatch")
    privileges = connection.execute(text("""
        SELECT has_database_privilege(current_database(), 'CREATE,TEMP'),
               EXISTS (SELECT FROM pg_namespace WHERE has_schema_privilege(oid, 'CREATE')),
               has_table_privilege('public.alembic_version', 'SELECT'),
               has_schema_privilege(:owner, 'public', 'CREATE')
    """), params).one()
    if privileges != (False, False, True, True):
        raise Denied("migration_privileges_not_approved")
    excessive = connection.execute(text("""
        SELECT EXISTS (
            SELECT FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass
              AND refobjid = (SELECT oid FROM pg_roles WHERE rolname = current_user) AND deptype = 'o'
        ) OR EXISTS (
            SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
              AND CASE
                WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'USAGE,SELECT,UPDATE')
                WHEN c.relkind IN ('r','p','v','m','f') THEN
                    has_table_privilege(c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                    OR has_any_column_privilege(c.oid, 'INSERT,UPDATE,REFERENCES')
                    OR (c.oid <> 'public.alembic_version'::regclass
                        AND has_any_column_privilege(c.oid, 'SELECT'))
                ELSE false
              END
        ) OR EXISTS (
            SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.prosecdef AND (
                (has_schema_privilege(n.oid, 'USAGE') AND has_function_privilege(p.oid, 'EXECUTE'))
                OR (p.proowner <> CAST(:owner AS regrole)
                    AND has_schema_privilege(:owner, n.oid, 'USAGE')
                    AND has_function_privilege(:owner, p.oid, 'EXECUTE'))
            )
        )
    """), params).scalar_one()
    if excessive:
        raise Denied("migration_privileges_not_approved")
    objects = dict(connection.execute(text("""
        SELECT relname, pg_get_userbyid(relowner)
        FROM pg_class WHERE relnamespace = 'public'::regnamespace
          AND relname = ANY(:names) AND relkind IN ('r', 'p')
    """), {"names": [*APPLICATION_TABLES, "alembic_version"]}).all())
    function_owner = connection.execute(text("""
        SELECT pg_get_userbyid(proowner) FROM pg_proc
        WHERE oid = to_regprocedure('public.prevent_audit_log_mutation()')
    """)).scalar_one_or_none()
    if objects != dict.fromkeys((*APPLICATION_TABLES, "alembic_version"), OWNER) or function_owner != OWNER:
        raise Denied("migration_ownership_mismatch")
    if not verify_legacy_audit(connection, owner=OWNER):
        raise Denied("migration_audit_protection_not_approved")


def verify_revision(connection, expected):
    heads = connection.execute(text("SELECT version_num FROM public.alembic_version")).scalars().all()
    if heads != [expected]:
        raise Denied("unexpected_database_revision")


def verify_transaction(connection, transaction):
    if (connection.get_transaction() is not transaction or not transaction.is_active
            or str(connection.get_execution_options().get("isolation_level", "")).upper() == "AUTOCOMMIT"
            or connection.connection.driver_connection.autocommit):
        raise Denied("migration_transaction_lost")


def _check_execution_options(connection, options):
    if "isolation_level" in options:
        _deny_transaction_break()


_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9$]*|\$[0-9]+")
_DOLLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")
_ALLOWED = frozenset("CREATE ALTER DROP COMMENT GRANT REVOKE SELECT INSERT UPDATE DELETE WITH".split())


def _quoted_end(sql, start, escape=False):
    quote = sql[start]
    end = start + 1
    while end < len(sql):
        char = sql[end]
        if char == "\\" and escape:
            end += 2
        elif char == "\\" and quote == "'":
            break  # Require E strings for backslashes.
        elif char == quote:
            if sql[end + 1:end + 2] != quote:
                return end + 1
            end += 2
        else:
            end += 1
    _deny_transaction_break()


def _check_statement(connection, cursor, statement, parameters, context, executemany):
    """Accept one statement in a deliberately limited PostgreSQL lexical subset."""
    index = 0
    terminated = False
    words = []
    if "\x00" in statement:
        _deny_transaction_break()
    while index < len(statement):
        char = statement[index]
        if char in " \r\n\t\f\v":
            index += 1
            continue
        if statement.startswith("--", index):
            end = re.search(r"[\r\n]", statement[index:])
            index += end.start() if end else len(statement)
            continue
        if statement.startswith("/*", index):
            depth = 1
            for comment in re.compile(r"/\*|\*/").finditer(statement, index + 2):
                depth += 1 if comment[0] == "/*" else -1
                if not depth:
                    index = comment.end()
                    break
            if depth:
                _deny_transaction_break()
            continue
        if terminated or (not words and not char.isalpha()):
            _deny_transaction_break()
        if char == ";":
            terminated = True
            index += 1
            continue
        if (statement[index:index + 2].lower() == "u&"
                or (char in "bBxXnN" and statement[index + 1:index + 2] == "'")):
            _deny_transaction_break()
        escape = char in "eE" and statement[index + 1:index + 2] == "'"
        if escape or char in "\"'":
            if not words:
                _deny_transaction_break()
            start = index + int(escape)
            index = _quoted_end(statement, start, escape)
            if char == '"':
                words.append(statement[start + 1:index - 1].replace('""', '"').lower())
            continue
        dollar = _DOLLAR.match(statement, index)
        if dollar:
            if index and (statement[index - 1].isalnum() or statement[index - 1] in "_$"):
                _deny_transaction_break()
            end = statement.find(dollar[0], dollar.end())
            if end < 0:
                _deny_transaction_break()
            index = end + len(dollar[0])
            continue
        token = _TOKEN.match(statement, index)
        if token:
            word = token[0].lower()
            words.append(word)
            index = token.end()
            continue
        if not char.isascii() or char not in "0123456789.,:()[]+-*/%=<>!~^|&?#@":
            _deny_transaction_break()
        index += 1
    if (not words or words[0].upper() not in _ALLOWED
            or any(word in {"set_config", "pg_reload_conf", "pg_terminate_backend"}
                   or word.startswith("pg_advisory_") for word in words)
            or (words[0] in {"alter", "create", "drop"}
                and words[1:2] in (["role"], ["user"], ["group"], ["database"], ["system"], ["owned"]))):
        _deny_transaction_break()


def configure_migration_transaction(connection):
    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
    connection.execute(text("SET LOCAL search_path = public, pg_temp"))
    connection.execute(text("SET LOCAL standard_conforming_strings = on"))


def acquire_migration_lock(connection):
    if not connection.execute(text("SELECT pg_try_advisory_xact_lock(:key)"),
                              {"key": LOCK_KEY}).scalar_one():
        raise Denied("migration_lock_busy")
    return server_transaction(connection)


def server_transaction(connection):
    xid, writable, locked, trigger_mode = connection.execute(text("""
        SELECT pg_current_xact_id()::text, current_setting('transaction_read_only') = 'off'
               AND current_setting('transaction_isolation') = 'read committed'
               AND current_setting('standard_conforming_strings') = 'on'
               AND current_setting('client_encoding') = 'UTF8'
               AND current_setting('server_encoding') = 'UTF8'
               AND current_setting('search_path') = 'public, pg_temp'
               AND current_setting('statement_timeout') = '30s'
               AND current_setting('lock_timeout') = '5s',
               EXISTS (
                   SELECT FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'
                     AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
                     AND classid::bigint = :high AND objid::bigint = :low AND objsubid = 1
                     AND mode = 'ExclusiveLock' AND granted
               ), current_setting('session_replication_role')
    """), {"high": LOCK_KEY >> 32, "low": LOCK_KEY & 0xffffffff}).one()
    if not xid or not writable or not locked or trigger_mode != "origin":
        raise Denied("server_transaction_lost")
    return xid


def verify_server_transaction(connection, xid):
    if server_transaction(connection) != xid:
        raise Denied("server_transaction_lost")


def protect_transaction(connection, cleanup):
    for name, handler in (
        ("commit", _deny_transaction_break),
        ("rollback", _deny_transaction_break),
        ("set_connection_execution_options", _check_execution_options),
        ("before_cursor_execute", _check_statement),
    ):
        event.listen(connection, name, handler)
        cleanup.callback(event.remove, connection, name, handler)


def _deny_transaction_break(*args, **kwargs):
    raise Denied("migration_transaction_break")


def guarded_environment():
    return _ACTIVE.get()


def run_guarded_environment(context, active, metadata):
    connection, transaction, request, addresses, xid = active
    if (context.is_offline_mode() or context.config.attributes.get("connection") is not connection
            or context.get_revision_argument() != request.successor
            or context.get_starting_revision_argument() is not None):
        raise Denied("guarded_connection_required")
    verify_transaction(connection, transaction)
    verify_docker_target(request, addresses)
    verify_identity(connection, addresses, OWNER)
    verify_server_transaction(connection, xid)
    verify_revision(connection, request.predecessor)
    context.configure(connection=connection, target_metadata=metadata, transactional_ddl=True,
                      version_table_schema="public")
    migration = context.get_context()
    deny_purge(migration)
    migration.autocommit_block = _deny_transaction_break
    plan = migration._migrations_fn

    def upgrade_only(heads, migration_context):
        steps = list(plan(heads, migration_context))
        if (len(steps) != 1 or not isinstance(steps[0], RevisionStep) or not steps[0].is_upgrade
                or steps[0].from_revisions != (request.predecessor,)
                or steps[0].to_revisions != (request.successor,)):
            raise Denied("unexpected_upgrade_plan")
        return steps

    migration._migrations_fn = upgrade_only
    context.run_migrations()
    verify_transaction(connection, transaction)
    verify_server_transaction(connection, xid)
    verify_revision(connection, request.successor)


def verify_docker_target(request, expected):
    if type(expected) is B4Transport:
        pairs = docker_postgres_identity(container_id=request.container_id, local=True,
                                         exact=(expected.image_id, expected.network, expected.network_id))
        if pairs != frozenset({expected.address_pair}):
            raise Denied("docker_identity_changed")
        return
    if docker_postgres_identity(container_id=request.container_id, local=True) != expected:
        raise Denied("docker_identity_changed")


def deny_purge(migration):
    if migration.purge:
        raise Denied("migration_purge_forbidden")


def verify_legacy_heads(heads):
    if len(heads) > 1:
        raise Denied("unexpected_database_revision")
    check_legacy_revisions(heads)


def run_locked_legacy(context, metadata, connection):
    connection = connection.execution_options(isolation_level="READ COMMITTED")
    with connection.begin() as transaction:
        verify_transaction(connection, transaction)
        configure_migration_transaction(connection)
        xid = acquire_migration_lock(connection)
        context.configure(connection=connection, target_metadata=metadata, compare_type=True,
                          transactional_ddl=True, version_table_schema="public")
        migration = context.get_context()
        deny_purge(migration)
        verify_legacy_heads(migration.get_current_heads())
        restrict_legacy_context(migration)
        migration.autocommit_block = _deny_transaction_break
        with ExitStack() as cleanup:
            protect_transaction(connection, cleanup)
            context.run_migrations()
        verify_transaction(connection, transaction)
        verify_server_transaction(connection, xid)
        verify_legacy_heads(migration.get_current_heads())


class SingleStatementCursor(Cursor):
    """Use Psycopg's extended protocol even for parameterless SQL."""

    def execute(self, query, params=None, *, prepare=None, binary=None):
        return super().execute(query, params, prepare=True, binary=binary)


def execute(config, request, environ, report, *, b4_transport=None):
    report("input")
    if "connection" in config.attributes:
        raise Denied("guarded_connection_required")
    url = validate_request(request, environ)
    report("graph")
    validate_graph(ScriptDirectory.from_config(config), request)
    with ExitStack() as cleanup:
        connect_args = {"hostaddr": "127.0.0.1", "connect_timeout": 5,
                        "cursor_factory": SingleStatementCursor}
        if request.successor == STAGED_REVISION:
            connect_args.update(_b4_connect_args(b4_transport, request, cleanup))
        report("docker")
        if request.successor == STAGED_REVISION:
            verify_docker_target(request, b4_transport)
            addresses = b4_transport
        else:
            addresses = docker_postgres_identity(container_id=request.container_id, local=True)
        report("connect")
        engine = create_engine(url, poolclass=pool.NullPool, hide_parameters=True,
                               isolation_level="READ COMMITTED", connect_args=connect_args)
        _execute_transaction(engine, config, request, addresses, report)


def _execute_transaction(engine, config, request, addresses, report):
    try:
        with engine.connect() as connection, connection.begin() as transaction:
            verify_transaction(connection, transaction)
            configure_migration_transaction(connection)
            report("identity")
            verify_docker_target(request, addresses)
            verify_identity(connection, addresses, LOGIN)
            report("roles")
            verify_roles(connection)
            report("lock")
            xid = acquire_migration_lock(connection)
            report("revision")
            verify_revision(connection, request.predecessor)
            verify_docker_target(request, addresses)
            verify_identity(connection, addresses, LOGIN)
            connection.execute(text("SET LOCAL ROLE ai_soc_test_owner"))
            verify_identity(connection, addresses, OWNER)
            report("upgrade")
            with ExitStack() as cleanup:
                token = _ACTIVE.set((connection, transaction, request, addresses, xid))
                cleanup.callback(_ACTIVE.reset, token)
                config.attributes["connection"] = connection
                cleanup.callback(config.attributes.pop, "connection", None)
                protect_transaction(connection, cleanup)
                command.upgrade(config, request.successor)
            verify_transaction(connection, transaction)
            verify_identity(connection, addresses, OWNER)
            verify_server_transaction(connection, xid)
            verify_revision(connection, request.successor)
            if type(addresses) is B4Transport:
                verify_docker_target(request, addresses)
    finally:
        engine.dispose()
