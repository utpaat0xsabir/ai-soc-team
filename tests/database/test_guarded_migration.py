"""Offline checks for the AI-05B migration boundary."""
from contextlib import contextmanager
from ipaddress import ip_address
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.database import migration_guard as guard, test_target


URL = "postgresql+psycopg://ai_soc_test_migrator:synthetic@127.0.0.1:5432/ai_soc_test"
BASE = guard.BASELINE


def request_for(url=URL, successor="123456789abc"):
    return guard.Request("test-request", "a" * 64, BASE, successor, url)


@pytest.mark.parametrize("url", [
    "", URL.replace("/ai_soc_test", "/ai_soc"), URL.replace("127.0.0.1", "localhost"),
    URL.replace("5432", "5433"), URL + "?service=other",
    URL.replace("ai_soc_test_migrator", "ai_soc"),
    URL.replace("ai_soc_test_migrator", "ai_soc_test_runner"),
])
def test_unsafe_url_rejected(url):
    with pytest.raises(guard.Denied):
        guard.validate_request(request_for(url), {})


def test_environment_redirection_rejected():
    with pytest.raises(guard.Denied):
        guard.validate_request(request_for(), {"PGHOSTADDR": "192.0.2.1"})


ROOT = Path(__file__).resolve().parents[2]
SERVER = ip_address("192.0.2.2")
CLIENT = ip_address("192.0.2.1")
ADDRESSES = frozenset({(SERVER, CLIENT)})


def test_repository_successor_requires_guarded_execution():
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    script = ScriptDirectory.from_config(config)
    from app.database.source_registry_migration_plan import STAGED_REVISION

    assert script.get_heads() == [STAGED_REVISION]
    assert {rev.revision for rev in script.walk_revisions()} == guard.LEGACY | {STAGED_REVISION}
    guard.validate_graph(script, request_for(successor=STAGED_REVISION))
    with pytest.raises(guard.Denied, match="unexpected_repository_heads"):
        guard.validate_graph(script, request_for())
    with pytest.raises(guard.Denied, match="guarded_migration_required"):
        guard.check_legacy_revisions((STAGED_REVISION,))


@pytest.mark.parametrize("heads,parent,dependencies", [
    (["123456789abc", "abcdefabcdef"], BASE, None),
    (["123456789abc"], "abcdefabcdef", None),
    (["123456789abc"], BASE, "abcdefabcdef"),
])
def test_graph_ambiguity(heads, parent, dependencies):
    script = Mock()
    script.get_heads.return_value = heads
    script.get_revision.return_value = SimpleNamespace(
        revision="123456789abc", down_revision=parent, dependencies=dependencies, branch_labels=set())
    with pytest.raises(guard.Denied):
        guard.validate_graph(script, request_for())


@pytest.mark.parametrize("container_id,host", [("b" * 64, "127.0.0.1"), ("a" * 64, "0.0.0.0")])
def test_docker_pin_and_exact_publication(monkeypatch, container_id, host):
    output = "|".join((container_id, "/ai-soc-postgres", "postgres:16", "running",
                       json.dumps({"5432/tcp": [{"HostIp": host, "HostPort": "5432"}]}),
                       json.dumps({"bridge": {"IPAddress": str(SERVER), "Gateway": str(CLIENT)}})))
    inspect = Mock(return_value=SimpleNamespace(stdout=output))
    monkeypatch.setattr(test_target.subprocess, "run", inspect)
    with pytest.raises(ValueError, match="cannot verify"):
        test_target.docker_postgres_identity(container_id="a" * 64, local=True)
    assert inspect.call_args.args[0][1:3] == ["--host", "unix:///var/run/docker.sock"]


@pytest.mark.parametrize("index,value", [
    (0, "ai_soc"), (1, "unexpected_login"), (2, guard.OWNER),
    (3, "198.51.100.2"), (4, "198.51.100.1"), (5, 5433),
])
def test_live_identity_mismatch(index, value):
    row = [guard.TARGET, guard.LOGIN, guard.LOGIN, SERVER, CLIENT, 5432, 50000]
    row[index] = value
    connection = Mock()
    connection.execute.return_value.one.return_value = row
    with pytest.raises(guard.Denied, match="connected_identity_mismatch"):
        guard.verify_identity(connection, ADDRESSES, guard.LOGIN)


@pytest.mark.parametrize("flag", [1, 2, 3, 4, 5, 6])
def test_privileged_login_flags_denied(flag):
    flags = [True, False, False, False, False, False, False]
    flags[flag] = True
    connection = Mock()
    connection.execute.return_value.all.return_value = [
        (guard.LOGIN, flags), (guard.OWNER, [False] * 7),
    ]
    with pytest.raises(guard.Denied, match="migration_roles_not_approved"):
        guard.verify_roles(connection)


def role_connection(memberships, owners=(guard.OWNER, "pg_database_owner"),
                    privileges=(False, False, True, True), excessive=False):
    connection = Mock()
    names = list(dict.fromkeys([guard.LOGIN, guard.OWNER, "postgres",
                                *(name for membership in memberships for name in membership[:2])]))
    grants = [[names.index(member) + 1, names.index(target) + 1, 3]
              for member, target, *_ in memberships]
    graph = (list(range(1, len(names) + 1)), names, grants, [edge[2:] for edge in memberships], [3])
    connection.execute.side_effect = [
        Mock(**{"scalar_one.return_value": True}),
        Mock(**{"all.return_value": [(guard.LOGIN, [True] + [False] * 6),
                                     (guard.OWNER, [False] * 7)]}),
        Mock(**{"one.return_value": graph}),
        Mock(**{"one.return_value": owners}),
        Mock(**{"one.return_value": privileges}),
        Mock(**{"scalar_one.return_value": excessive}),
        Mock(**{"all.return_value": [(name, guard.OWNER)
                                     for name in (*guard.APPLICATION_TABLES, "alembic_version")]}),
        Mock(**{"scalar_one_or_none.return_value": guard.OWNER}),
        [(guard.OWNER, "plpgsql", False, None,
          " BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; ", True)],
        [("audit_logs_append_only", "O", 58, True, True)],
        [],
    ]
    return connection


MEMBERSHIP = (guard.LOGIN, guard.OWNER, False, False, True)


@pytest.mark.parametrize("memberships", [
    [], [(guard.LOGIN, guard.OWNER, True, False, True)],
    [(guard.LOGIN, guard.OWNER, False, True, True)],
    [(guard.LOGIN, guard.OWNER, False, False, False)],
    [MEMBERSHIP, (guard.OWNER, "other", False, False, True)],
])
def test_missing_or_unapproved_role_paths(memberships):
    with pytest.raises(guard.Denied, match="migration_memberships_not_approved"):
        guard.verify_roles(role_connection(memberships))


def test_owner_identity_required():
    guard.verify_roles(role_connection([MEMBERSHIP]))
    with pytest.raises(guard.Denied, match="migration_ownership_mismatch"):
        guard.verify_roles(role_connection([MEMBERSHIP], (guard.LOGIN, "pg_database_owner")))


@pytest.mark.parametrize("heads", [[], ["abcdefabcdef"], [BASE, "abcdefabcdef"], [BASE, BASE]])
def test_exact_database_predecessor(heads):
    connection = Mock()
    connection.execute.return_value.scalars.return_value.all.return_value = heads
    with pytest.raises(guard.Denied, match="unexpected_database_revision"):
        guard.verify_revision(connection, BASE)


def test_legacy_plan_rejects_protected_stamp_and_downgrade():
    future = request_for().successor
    migration = SimpleNamespace(_migrations_fn=lambda *args: [
        SimpleNamespace(from_revisions=(BASE,), to_revisions=(future,)),
    ])
    guard.restrict_legacy_context(migration)
    with pytest.raises(guard.Denied):
        migration._migrations_fn((BASE,), migration)
    with pytest.raises(guard.Denied):
        migration._migrations_fn((future,), migration)


def load_env(monkeypatch, destination, attributes=None, *, offline=False, advisory=False):
    from alembic import context
    import sqlalchemy

    config = Config()
    config.attributes.update(attributes or {})
    engine = Mock(side_effect=AssertionError("database must not be contacted"))
    monkeypatch.setattr(context, "config", config, raising=False)
    monkeypatch.setattr(context, "get_revision_argument", lambda: destination, raising=False)
    monkeypatch.setattr(context, "is_offline_mode", lambda: offline, raising=False)
    monkeypatch.setattr(sqlalchemy, "engine_from_config", engine)
    if advisory:
        monkeypatch.setenv("AI_SOC_ADVISORY_RUN_ID", "synthetic")
    return ROOT / "migrations" / "env.py"


@pytest.mark.parametrize("offline", [False, True])
def test_direct_alembic_target_rejected_before_connect(monkeypatch, offline):
    path = load_env(monkeypatch, request_for().successor, offline=offline)
    with pytest.raises(guard.Denied, match="guarded_migration_required"):
        runpy.run_path(str(path))


def test_programmatic_connection_attribute_is_not_authority(monkeypatch):
    path = load_env(monkeypatch, request_for().successor, {"connection": object()})
    with pytest.raises(guard.Denied, match="guarded_connection_required"):
        runpy.run_path(str(path))


def test_advisory_offline_denial_preserved(monkeypatch):
    path = load_env(monkeypatch, BASE, offline=True, advisory=True)
    with pytest.raises(RuntimeError, match="offline migrations are forbidden"):
        runpy.run_path(str(path))


def test_replacement_connection_rejected():
    context = Mock()
    context.is_offline_mode.return_value = False
    context.config.attributes = {"connection": object()}
    with pytest.raises(guard.Denied, match="guarded_connection_required"):
        guard.run_guarded_environment(context, (object(), object(), request_for(), ADDRESSES, "7"), None)


@pytest.mark.parametrize("isolation,driver_autocommit,replacement", [
    ("AUTOCOMMIT", False, False), ("", True, False), ("", False, True),
])
def test_transaction_cannot_be_missing_or_autocommit(isolation, driver_autocommit, replacement):
    connection = Mock()
    tx = SimpleNamespace(is_active=True)
    connection.get_transaction.return_value = object() if replacement else tx
    connection.get_execution_options.return_value = {"isolation_level": isolation}
    connection.connection.driver_connection.autocommit = driver_autocommit
    with pytest.raises(guard.Denied, match="migration_transaction_lost"):
        guard.verify_transaction(connection, tx)


def test_autocommit_option_denied():
    with pytest.raises(guard.Denied, match="migration_transaction_break"):
        guard._check_execution_options(None, {"isolation_level": "AUTOCOMMIT"})


@pytest.mark.parametrize("outcome", ["success", "busy", "lock_error", "upgrade_error"])
def test_runner_transaction_and_lock_order(monkeypatch, outcome):
    trace = []
    connection = Mock()
    transaction = SimpleNamespace(is_active=True)
    connection.get_transaction.return_value = transaction
    connection.get_execution_options.return_value = {}
    connection.connection.driver_connection.autocommit = False

    @contextmanager
    def begin():
        try:
            yield transaction
        except Exception:
            trace.append("rollback")
            raise
        else:
            trace.append("commit")

    def sql(statement, params=None):
        if "pg_try_advisory_xact_lock" in str(statement):
            trace.append("lock sql")
            if outcome == "lock_error":
                raise RuntimeError("lock unavailable")
            return Mock(**{"scalar_one.return_value": outcome != "busy"})
        return Mock(**{"one.return_value": ("7", True, True, "origin")})

    engine = Mock()
    @contextmanager
    def connect():
        yield connection

    engine.connect.side_effect = connect
    connection.begin.side_effect = begin
    connection.execute.side_effect = sql
    monkeypatch.setattr(guard, "create_engine", Mock(return_value=engine))
    monkeypatch.setattr(guard, "validate_graph", Mock())
    monkeypatch.setattr(guard, "docker_postgres_identity", Mock(return_value=ADDRESSES))
    monkeypatch.setattr(guard, "verify_roles", Mock())
    monkeypatch.setattr(guard, "verify_identity", Mock())
    monkeypatch.setattr(guard, "verify_revision", Mock(side_effect=lambda c, r: trace.append(r)))
    monkeypatch.setattr(guard, "event", Mock())

    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    request = request_for()

    def upgrade(c, revision):
        assert guard.guarded_environment() == (connection, transaction, request, ADDRESSES, "7")
        assert c.attributes["connection"] is connection
        assert revision == request.successor
        if outcome == "upgrade_error":
            raise RuntimeError("synthetic migration failure")

    monkeypatch.setattr(guard.command, "upgrade", upgrade)
    if outcome == "success":
        guard.execute(config, request, {}, trace.append)
        assert trace[-1] == "commit"
        assert trace.index("lock sql") < trace.index(BASE) < trace.index(request.successor)
    else:
        with pytest.raises(RuntimeError):
            guard.execute(config, request, {}, trace.append)
        assert trace[-1] == "rollback"
        assert request.successor not in trace
        if outcome in {"busy", "lock_error"}:
            assert BASE not in trace
    assert guard.guarded_environment() is None
    assert "connection" not in config.attributes
    engine.dispose.assert_called_once()


@pytest.mark.parametrize("exception", [RuntimeError, guard.Denied])
def test_cli_ignores_application_url_and_sanitizes_errors(monkeypatch, capsys, exception):
    cli = runpy.run_path(str(ROOT / "scripts" / "run_guarded_migration.py"))
    monkeypatch.setenv("DATABASE_URL", URL)
    monkeypatch.delenv("AI_SOC_MIGRATION_DATABASE_URL", raising=False)

    def reject(config, request, environ, report):
        assert request.database_url == ""
        report("connect")
        raise exception(URL)

    monkeypatch.setattr(guard, "execute", reject)
    result = cli["main"](["--request-id", "test", "--container-id", "a" * 64,
                          "--predecessor", BASE, "--successor", request_for().successor])
    error = capsys.readouterr().err
    assert result == 1
    assert URL not in error and "synthetic@" not in error
    assert json.loads(error)["reason"] == "execution_failed"


def test_migration_login_requires_only_preflight_reads():
    with pytest.raises(guard.Denied, match="migration_privileges_not_approved"):
        guard.verify_roles(role_connection([MEMBERSHIP], privileges=(False, True, True, True)))


@pytest.mark.parametrize("sql", ["COMMIT", "/* migration */ END", "-- comment\nROLLBACK",
                                "PREPARE TRANSACTION 'example'"])
def test_explicit_transaction_control_sql_denied(sql):
    with pytest.raises(guard.Denied, match="migration_transaction_break"):
        guard._check_statement(None, None, sql, None, None, False)


def test_guarded_env_uses_verified_transaction_and_exact_step(monkeypatch):
    from alembic.runtime.migration import RevisionStep

    connection, transaction = Mock(), Mock()
    request = request_for()
    context = Mock()
    context.is_offline_mode.return_value = False
    context.get_revision_argument.return_value = request.successor
    context.get_starting_revision_argument.return_value = None
    context.config.attributes = {"connection": connection}
    step = Mock(spec=RevisionStep)
    step.is_upgrade = True
    step.from_revisions = (BASE,)
    step.to_revisions = (request.successor,)
    migration = SimpleNamespace(_migrations_fn=lambda heads, ctx: [step], purge=False)
    context.get_context.return_value = migration

    def run():
        assert migration._migrations_fn((BASE,), migration) == [step]
        with pytest.raises(guard.Denied, match="migration_transaction_break"):
            migration.autocommit_block()
        step.is_upgrade = False
        with pytest.raises(guard.Denied, match="unexpected_upgrade_plan"):
            migration._migrations_fn((BASE,), migration)

    context.run_migrations.side_effect = run
    check_tx, check_identity, check_revision = Mock(), Mock(), Mock()
    monkeypatch.setattr(guard, "verify_transaction", check_tx)
    monkeypatch.setattr(guard, "verify_identity", check_identity)
    monkeypatch.setattr(guard, "verify_revision", check_revision)
    monkeypatch.setattr(guard, "verify_docker_target", Mock())
    monkeypatch.setattr(guard, "verify_server_transaction", Mock())
    guard.run_guarded_environment(context, (connection, transaction, request, ADDRESSES, "7"), None)
    assert context.configure.call_args.kwargs["connection"] is connection
    assert check_tx.call_count == 2
    check_identity.assert_called_once_with(connection, ADDRESSES, guard.OWNER)
    assert [call.args[1] for call in check_revision.call_args_list] == [BASE, request.successor]


def test_online_advisory_target_check_remains_before_migrations(monkeypatch):
    from alembic import context
    import sqlalchemy

    path = load_env(monkeypatch, BASE, advisory=True)
    monkeypatch.setenv("AI_SOC_ADVISORY_EXECUTION", "container")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test@pg:5432/ai_soc_advisory_test")
    engine = Mock()
    engine.connect.return_value = contextmanager(lambda: (yield Mock()))()
    monkeypatch.setattr(sqlalchemy, "engine_from_config", Mock(return_value=engine))
    configure = Mock()
    monkeypatch.setattr(context, "configure", configure, raising=False)
    with pytest.raises(RuntimeError, match="advisory container migration identity is incomplete"):
        runpy.run_path(str(path))
    configure.assert_not_called()
    engine.dispose.assert_called_once()


def test_missing_migration_login_denied():
    connection = Mock()
    connection.execute.return_value.all.return_value = [(guard.OWNER, [False] * 7)]
    with pytest.raises(guard.Denied, match="migration_roles_not_approved"):
        guard.verify_roles(connection)


def test_no_successor_stops_before_docker_or_postgresql(monkeypatch):
    config = Config()
    script = Mock()
    script.get_heads.return_value = [BASE]
    monkeypatch.setattr(guard.ScriptDirectory, "from_config", Mock(return_value=script))
    docker, engine = Mock(), Mock()
    monkeypatch.setattr(guard, "docker_postgres_identity", docker)
    monkeypatch.setattr(guard, "create_engine", engine)
    with pytest.raises(guard.Denied, match="unexpected_repository_heads"):
        guard.execute(config, request_for(), {}, lambda stage: None)
    docker.assert_not_called()
    engine.assert_not_called()


@pytest.mark.parametrize("sql", [
    "; SELECT 1", "SELECT 1;;", "SELECT 1; SELECT 2",
    "CREATE TABLE example (id int); /* next */ COMMIT",
    "SET ROLE other", "RESET ALL", "SELECT set_config('role', 'other', false)",
    "/* comment */ COMMIT", "SELECT 1; /* between */ SELECT 2",
    "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "DISCARD ALL",
    """SELECT pg_catalog."set_config"('role', 'other', false)""",
    "SELECT U&'unsupported'",
    "SELECT 'unterminated", "SELECT $$unterminated",
])
def test_unsafe_statements_never_reach_driver(sql):
    from sqlalchemy import create_engine, event

    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        dispatched = Mock()
        event.listen(connection, "before_cursor_execute", guard._check_statement)
        event.listen(connection, "before_cursor_execute", dispatched)
        with pytest.raises(guard.Denied):
            connection.exec_driver_sql(sql)
        dispatched.assert_not_called()
    engine.dispose()


@pytest.mark.parametrize("sql", [
    "SELECT 1",
    "SELECT '; COMMIT', 'it''s fine'; -- trailing comment",
    r"SELECT E'it\'s fine; COMMIT'",
    "/* outer /* inner */ still a comment */ SELECT 1",
    "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $body$ SELECT ';'; $body$;",
])
def test_supported_sql_reaches_driver(sql):
    from sqlalchemy import create_engine, event

    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        dispatched = Mock()
        event.listen(connection, "before_cursor_execute", guard._check_statement)

        def fake_driver(cursor, statement, parameters, context):
            dispatched(statement)
            cursor.execute("SELECT 1")
            return True

        event.listen(engine, "do_execute", fake_driver)
        connection.exec_driver_sql(sql)
        dispatched.assert_called_once_with(sql)
    engine.dispose()


def test_guarded_cursor_requires_extended_protocol(monkeypatch):
    dispatch = Mock()
    monkeypatch.setattr(guard.Cursor, "execute", dispatch)
    guard.SingleStatementCursor.execute(object.__new__(guard.SingleStatementCursor), "SELECT 1",
                                        prepare=False)
    assert dispatch.call_args.kwargs["prepare"] is True


@pytest.mark.parametrize("row", [("8", True, True), ("7", False, True), ("7", True, False)])
def test_server_transaction_and_lock_continuity(row):
    connection = Mock()
    connection.execute.return_value.one.return_value = (*row, "origin")
    with pytest.raises(guard.Denied, match="server_transaction_lost"):
        guard.verify_server_transaction(connection, "7")


@pytest.mark.parametrize("mode", ["origin", "replica", "local", None])
def test_server_transaction_requires_origin_trigger_mode(mode):
    connection = Mock()
    connection.execute.return_value.one.return_value = ("7", True, True, mode)
    if mode == "origin":
        guard.verify_server_transaction(connection, "7")
    else:
        with pytest.raises(guard.Denied, match="server_transaction_lost"):
            guard.verify_server_transaction(connection, "7")
    assert "current_setting('session_replication_role')" in str(connection.execute.call_args.args[0])


def test_crossed_network_pairs_rejected():
    other_server = ip_address("198.51.100.2")
    other_client = ip_address("198.51.100.1")
    connection = Mock()
    connection.execute.return_value.one.return_value = [
        guard.TARGET, guard.LOGIN, guard.LOGIN, SERVER, other_client, 5432, 50000,
    ]
    with pytest.raises(guard.Denied, match="connected_identity_mismatch"):
        guard.verify_identity(connection, ADDRESSES | {(other_server, other_client)}, guard.LOGIN)


@pytest.mark.parametrize("replacement,host", [
    ("b" * 64, "127.0.0.1"), ("a" * 64, "0.0.0.0"),
])
def test_docker_drift_reinspection(monkeypatch, replacement, host):
    def metadata(container_id, published_host):
        return "|".join((container_id, "/ai-soc-postgres", "postgres:16", "running",
                        json.dumps({"5432/tcp": [{"HostIp": published_host, "HostPort": "5432"}]}),
                        json.dumps({"bridge": {"IPAddress": str(SERVER), "Gateway": str(CLIENT)}})))

    monkeypatch.setattr(test_target.subprocess, "run", Mock(side_effect=[
        SimpleNamespace(stdout=metadata("a" * 64, "127.0.0.1")),
        SimpleNamespace(stdout=metadata(replacement, host)),
    ]))
    target = guard.docker_postgres_identity(container_id="a" * 64, local=True)
    with pytest.raises(ValueError, match="cannot verify"):
        guard.verify_docker_target(request_for(), target)


def test_docker_changed_address_denied(monkeypatch):
    inspect = Mock(return_value=frozenset({(ip_address("192.0.2.3"), CLIENT)}))
    monkeypatch.setattr(guard, "docker_postgres_identity", inspect)
    with pytest.raises(guard.Denied, match="docker_identity_changed"):
        guard.verify_docker_target(request_for(), ADDRESSES)


def test_excessive_authority_denied():
    connection = role_connection([MEMBERSHIP], excessive=True)
    with pytest.raises(guard.Denied, match="migration_privileges_not_approved"):
        guard.verify_roles(connection)
    sql = str(connection.execute.call_args.args[0])
    assert "pg_shdepend" in sql and "has_any_column_privilege" in sql and "p.prosecdef" in sql


def test_unsupported_postgresql_major_denied():
    connection = Mock()
    connection.execute.return_value.scalar_one.return_value = False
    with pytest.raises(guard.Denied, match="unsupported_postgresql_version"):
        guard.verify_roles(connection)
    connection.execute.assert_called_once()


@pytest.mark.parametrize("outcome", ["success", "busy", "purge", "protected", "multiple", "failure"])
def test_online_legacy_serializes_head_checks_and_writes(monkeypatch, outcome):
    trace = []
    tx = Mock()
    connection = Mock()
    connection.execution_options.return_value = connection

    @contextmanager
    def transaction():
        try:
            yield tx
        except BaseException:
            trace.append("rollback")
            raise
        else:
            trace.append("commit")

    def lock(conn):
        assert conn is connection
        trace.append(("lock", guard.LOCK_KEY))
        if outcome == "busy":
            raise guard.Denied("migration_lock_busy")
        # Model a guarded run committing while this legacy caller waits.
        return "7"

    def heads():
        trace.append("heads")
        if outcome == "protected":
            return (request_for().successor,)
        if outcome == "multiple":
            return (BASE, "20d4e84d93ca")
        return (BASE,)

    def run():
        trace.append("run")
        if outcome == "failure":
            raise guard.Denied("migration_transaction_break")

    connection.begin.side_effect = transaction
    context = Mock()
    migration = Mock(purge=outcome == "purge")
    migration.get_current_heads.side_effect = heads
    context.get_context.return_value = migration
    context.run_migrations.side_effect = run
    monkeypatch.setattr(guard, "verify_transaction", Mock())
    monkeypatch.setattr(guard, "verify_server_transaction", Mock())
    monkeypatch.setattr(guard, "acquire_migration_lock", lock)
    monkeypatch.setattr(guard, "protect_transaction", Mock())
    if outcome == "success":
        guard.run_locked_legacy(context, None, connection)
        assert trace == [("lock", guard.LOCK_KEY), "heads", "run", "heads", "commit"]
    else:
        with pytest.raises(guard.Denied):
            guard.run_locked_legacy(context, None, connection)
        assert trace[0] == ("lock", guard.LOCK_KEY)
        assert trace[-1] == "rollback"
        assert ("run" in trace) == (outcome == "failure")
        assert ("heads" in trace) == (outcome not in {"busy", "purge"})


@pytest.mark.parametrize("outcome", ["success", "callback_error", "revision_drift", "transaction_break", "wrong_predecessor"])
def test_composed_alembic_execution(monkeypatch, tmp_path, outcome):
    import sqlite3
    from contextlib import ExitStack
    from types import ModuleType

    from alembic import op
    from alembic.runtime.environment import EnvironmentContext
    from alembic.script.base import Script
    from sqlalchemy import create_engine, text

    class FakeDriverConnection(sqlite3.Connection):
        autocommit = False

    request = request_for()
    execution = Mock()

    def apply():
        execution()
        assert op.get_bind() is connection
        op.execute("CREATE TABLE synthetic_output (id int)")
        if outcome == "callback_error":
            raise RuntimeError("synthetic callback failure")
        if outcome == "transaction_break":
            op.execute("SELECT 1; COMMIT")

    def revisions(self):
        for revision, parent, upgrade in ((BASE, None, Mock()), (request.successor, BASE, apply)):
            module = ModuleType("synthetic_" + revision)
            module.down_revision = parent
            module.upgrade = upgrade
            yield Script(module, revision, str(tmp_path / revision))

    monkeypatch.setattr(ScriptDirectory, "_load_revisions", revisions)
    script = ScriptDirectory(str(tmp_path))
    guard.validate_graph(script, request)
    config = Config()
    engine = create_engine("sqlite://", creator=lambda: sqlite3.connect(
        ":memory:", factory=FakeDriverConnection))
    monkeypatch.setattr(guard, "verify_docker_target", Mock())
    monkeypatch.setattr(guard, "verify_identity", Mock())
    monkeypatch.setattr(guard, "verify_server_transaction", Mock())

    monkeypatch.setattr(engine.dialect, "has_table", lambda conn, name, schema: conn.execute(
        text("SELECT 1 FROM public.sqlite_master WHERE name = :name"), {"name": name}
    ).scalar() == 1)
    initial = "abcdefabcdef" if outcome == "wrong_predecessor" else BASE
    with engine.connect() as connection:
        connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS public")
        connection.exec_driver_sql("CREATE TABLE public.alembic_version (version_num varchar(32) PRIMARY KEY)")
        connection.execute(text("INSERT INTO public.alembic_version VALUES (:rev)"), {"rev": initial})
        if outcome == "revision_drift":
            connection.exec_driver_sql(
                "CREATE TRIGGER public.synthetic_drift AFTER UPDATE ON alembic_version "
                "BEGIN UPDATE alembic_version SET version_num = OLD.version_num; END")
        connection.commit()
        config.attributes["connection"] = connection

        def run():
            with connection.begin() as transaction:
                connection.exec_driver_sql("BEGIN")
                with ExitStack() as cleanup:
                    guard.protect_transaction(connection, cleanup)
                    with EnvironmentContext(
                        config, script, fn=lambda heads, ctx: script._upgrade_revs(request.successor, heads),
                        starting_rev=None, destination_rev=request.successor,
                    ) as environment:
                        guard.run_guarded_environment(
                            environment, (connection, transaction, request, ADDRESSES, "7"), None)

        if outcome == "success":
            run()
        else:
            with pytest.raises(RuntimeError):
                run()
        if outcome == "wrong_predecessor":
            execution.assert_not_called()
        else:
            execution.assert_called_once()
        guard.verify_revision(connection, request.successor if outcome == "success" else initial)
        exists = connection.exec_driver_sql(
            "SELECT count(*) FROM sqlite_master WHERE name = 'synthetic_output'").scalar_one()
        assert exists == (outcome == "success")
    engine.dispose()


@pytest.mark.parametrize("advisory", [False, True])
def test_online_env_uses_locked_legacy_path(monkeypatch, advisory):
    from alembic import context
    import sqlalchemy

    path = load_env(monkeypatch, BASE, advisory=advisory)
    if advisory:
        run_id = "20261116-1234abcd"
        for name, value in {
            "RUN_ID": run_id, "EXECUTION": "container", "DB_HOST": "pg",
            "DB_CONTAINER_ID": "a" * 64, "DB_IMAGE_ID": "sha256:" + "b" * 64,
            "DB_IP": str(SERVER), "RUNNER_CONTAINER_ID": "c" * 64,
            "RUNNER_IMAGE_ID": "sha256:db6ee5170ebce0f4d165af242e8e77addc08bd9ffc37e8b1815752cf027aa4f8",
            "RUNNER_IP": str(CLIENT), "NETWORK_ID": "d" * 64,
            "VOLUME_NAME": f"ai-soc-advisory-data-{run_id}",
            "MIGRATION_ROLE": "ai_soc_advisory_migrator", "RUNTIME_ROLE": "ai_soc_advisory_runner",
        }.items():
            monkeypatch.setenv(f"AI_SOC_ADVISORY_{name}", value)
        monkeypatch.setenv("DATABASE_URL",
                           "postgresql+psycopg://ai_soc_advisory_migrator@pg:5432/ai_soc_advisory_test")
    else:
        monkeypatch.delenv("AI_SOC_ADVISORY_RUN_ID", raising=False)

    trace = Mock()
    connection = trace.connection
    connection.execute.return_value.one.return_value = (
        "ai_soc_advisory_test", "ai_soc_advisory_migrator", str(CLIENT), str(SERVER), 5432)
    engine = Mock()
    engine.connect.return_value = contextmanager(lambda: (yield connection))()
    monkeypatch.setattr(sqlalchemy, "engine_from_config", Mock(return_value=engine))
    monkeypatch.setattr(guard, "run_locked_legacy", trace.locked)
    runpy.run_path(str(path))
    trace.locked.assert_called_once()
    assert trace.locked.call_args.args[0] is context
    assert trace.locked.call_args.args[2] is connection
    if advisory:
        connection.rollback.assert_called_once()
        assert [call[0] for call in trace.mock_calls][-2:] == ["connection.rollback", "locked"]
    else:
        connection.execute.assert_not_called()


def test_offline_legacy_does_not_use_online_lock(monkeypatch):
    from alembic import context

    path = load_env(monkeypatch, BASE, offline=True)
    monkeypatch.delenv("AI_SOC_ADVISORY_RUN_ID", raising=False)
    monkeypatch.setattr(context, "configure", Mock(), raising=False)
    monkeypatch.setattr(context, "get_context", lambda: SimpleNamespace(
        purge=False, _migrations_fn=lambda heads, ctx: [], get_current_heads=lambda: (BASE,)),
        raising=False)
    monkeypatch.setattr(context, "begin_transaction", contextmanager(lambda: (yield)), raising=False)
    run = Mock()
    monkeypatch.setattr(context, "run_migrations", run, raising=False)
    lock = Mock()
    monkeypatch.setattr(guard, "acquire_migration_lock", lock)
    runpy.run_path(str(path))
    run.assert_called_once()
    lock.assert_not_called()


def test_pinned_docker_target_rejects_multiple_networks(monkeypatch):
    metadata = "|".join(("a" * 64, "/ai-soc-postgres", "postgres:16", "running",
                         json.dumps({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]}),
                         json.dumps({
                             "bridge": {"IPAddress": str(SERVER), "Gateway": str(CLIENT)},
                             "other": {"IPAddress": "198.51.100.2", "Gateway": "198.51.100.1"},
                         })))
    monkeypatch.setattr(test_target.subprocess, "run", Mock(return_value=SimpleNamespace(stdout=metadata)))
    with pytest.raises(ValueError, match="cannot verify"):
        guard.docker_postgres_identity(container_id="a" * 64, local=True)


@pytest.mark.parametrize("extra", [
    [("serving", guard.OWNER, False, True, False)],
    [("serving", guard.LOGIN, False, False, True)],
    [("serving", guard.OWNER, True, False, False)],
    [("serving", "middle", False, True, True), ("middle", guard.OWNER, False, False, True)],
    [("serving", guard.OWNER, False, False, False)],
    [("serving", "pg_execute_server_program", False, False, True)],
    [("serving", "postgres", False, False, True)],
    [MEMBERSHIP],
])
def test_inbound_and_equivalent_role_paths_are_rejected(extra):
    with pytest.raises(guard.Denied, match="migration_memberships_not_approved"):
        guard.verify_roles(role_connection([MEMBERSHIP, *extra]))


@pytest.mark.parametrize(("oids", "grants", "options"), [
    (None, [[1, 2, 3]], [[False, False, True]]),
    ([1, 1, 3], [[1, 2, 3]], [[False, False, True]]),
    ([1, 2, 3], [[1, 2, 9]], [[False, False, True]]),
    ([1, 2, 3], [[1, 2, 3]], [[False, False, 1]]),
    ([1, 2, 3], [[1, 2, 3]], []),
])
def test_incomplete_role_graph_denied(oids, grants, options):
    assert not guard.approved_role_graph(oids, [guard.LOGIN, guard.OWNER, "postgres"], grants, options, [3])


def test_unrelated_roles_do_not_change_protected_capabilities():
    guard.verify_roles(role_connection([MEMBERSHIP, ("reporting", "report_reader", True, True, True)]))


def test_b4_requires_authenticated_transport_before_docker_or_engine(monkeypatch):
    from app.database.source_registry_migration_plan import STAGED_REVISION

    monkeypatch.setattr(guard, "validate_graph", Mock())
    monkeypatch.setattr(guard, "docker_postgres_identity", Mock())
    monkeypatch.setattr(guard, "create_engine", Mock())
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    with pytest.raises(guard.Denied, match="b4_transport_required"):
        guard.execute(config, request_for(successor=STAGED_REVISION), {}, Mock())
    guard.docker_postgres_identity.assert_not_called()
    guard.create_engine.assert_not_called()


def test_b4_guard_uses_exact_docker_pin_and_verified_tls(monkeypatch):
    from hashlib import sha256
    from app.database.source_registry_migration_plan import STAGED_REVISION

    request = request_for(successor=STAGED_REVISION)
    pair, = ADDRESSES
    ca = b"synthetic approved CA"
    pin = guard.B4Transport(request.container_id, "sha256:" + "c" * 64, "bridge", "d" * 64,
                            pair, sha256(ca).hexdigest(), ca)
    monkeypatch.setattr(guard, "validate_graph", Mock())
    monkeypatch.setattr(guard, "docker_postgres_identity", Mock(return_value=ADDRESSES))
    context = Mock()
    monkeypatch.setattr(guard.ssl, "SSLContext", Mock(return_value=context))
    monkeypatch.setattr(guard, "_execute_transaction", Mock())

    def engine(url, *, connect_args, **kwargs):
        assert url.host == "127.0.0.1" and url.database == "ai_soc_test"
        assert connect_args["hostaddr"] == "127.0.0.1"
        assert connect_args["sslmode"] == "verify-full" and connect_args["channel_binding"] == "require"
        assert connect_args["sslcertmode"] == connect_args["gssencmode"] == "disable"
        assert connect_args["passfile"] == "/dev/null"
        assert Path(connect_args["sslrootcert"]).read_bytes() == ca
        return Mock()

    monkeypatch.setattr(guard, "create_engine", engine)
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    guard.execute(config, request, {}, Mock(), b4_transport=pin)
    context.load_verify_locations.assert_called_once_with(cadata=ca.decode())
    guard.docker_postgres_identity.assert_called_once_with(container_id=pin.container_id, local=True,
                                                         exact=(pin.image_id, pin.network, pin.network_id))
    assert guard._execute_transaction.call_args.args[3] is pin
