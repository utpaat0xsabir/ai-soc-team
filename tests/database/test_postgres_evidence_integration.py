"""Opt-in integration with guarded ai_soc_test and an actual restricted login."""

from contextlib import ExitStack
from datetime import datetime, timezone
from ipaddress import IPv4Address
import os
import re
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import Session

from app.analysts.evidence_adapter import EvidenceRejected
from app.analysts.postgres_evidence import PostgresEvidenceRepository
from app.database.migration_guard import BASELINE, LOCK_KEY
from app.database.models import EvidenceRecord, Tenant
from app.database.test_target import docker_postgres_identity
from app.db import engine
from app.evidence.hashing import calculate_evidence_hash
from tests.conftest import _configured_test_url


_RUNNER = "ai_soc_test_runner"
_OBSERVER_URL = "AI_SOC_E2_OBSERVER_DATABASE_URL"
_OBSERVER_LOGIN = "AI_SOC_E2_OBSERVER_LOGIN"
_CONTAINER_PIN = "AI_SOC_E2_TEST_CONTAINER_ID"

_IDENTITY = text("""
    SELECT current_database(), session_user, current_user,
           current_setting('server_version_num')::integer / 10000,
           inet_server_addr(), inet_client_addr(), inet_server_port(),
           r.rolcanlogin AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
                                 OR r.rolcreatedb OR r.rolreplication),
           current_setting('transaction_read_only')
    FROM pg_catalog.pg_roles r WHERE r.rolname = session_user
""")

_OBSERVER_HAS_ELEVATED_PATH = text("""
    SELECT
        EXISTS (
            SELECT FROM pg_catalog.pg_roles r
            WHERE r.rolname <> session_user
              AND (pg_has_role(r.oid, 'SET') OR pg_has_role(r.oid, 'USAGE'))
        )
        OR EXISTS (
            SELECT FROM pg_catalog.pg_shdepend d
            WHERE d.refclassid = 'pg_catalog.pg_authid'::regclass AND d.deptype = 'o'
              AND d.refobjid = session_user::regrole
        )
        OR has_database_privilege(current_database(), 'CREATE')
        OR EXISTS (
            SELECT FROM pg_catalog.pg_namespace n WHERE has_schema_privilege(n.oid, 'CREATE')
        )
        OR EXISTS (
            SELECT FROM pg_catalog.pg_proc p WHERE p.prosecdef
              AND has_schema_privilege(p.pronamespace, 'USAGE')
              AND has_function_privilege(p.oid, 'EXECUTE')
        )
""")


def _approved_configuration() -> tuple[URL, str]:
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("requires explicit DATABASE_URL for ai_soc_test_runner on ai_soc_test")
    target = _configured_test_url(engine.url)
    if target.username != _RUNNER or not target.password:
        pytest.fail("requires explicit credentials for the actual ai_soc_test_runner login", pytrace=False)
    if any(key.startswith("PG") or key in {"AI_SOC_ADVISORY_RUN_ID", "DOCKER_HOST", "DOCKER_CONTEXT"}
           for key in os.environ):
        pytest.fail("ambient PostgreSQL, Docker, or advisory settings are not allowed", pytrace=False)

    raw = os.environ.get(_OBSERVER_URL)
    observer_login = os.environ.get(_OBSERVER_LOGIN)
    if not raw or not observer_login:
        pytest.skip("requires explicit observer URL and approved observer login")
    try:
        observer = make_url(raw)
    except (ArgumentError, ValueError):
        pytest.fail("invalid observer URL", pytrace=False)
    if (
        observer.drivername != "postgresql+psycopg"
        or (observer.host, observer.port, observer.database) != ("127.0.0.1", 5432, "ai_soc_test")
        or observer.username != observer_login
        or observer_login in {_RUNNER, "ai_soc", "postgres", "ai_soc_test_owner", "ai_soc_test_migrator"}
        or not observer.password or observer.query or "?" in raw
    ):
        pytest.fail("observer URL must select the approved separate login on ai_soc_test", pytrace=False)

    pin = os.environ.get(_CONTAINER_PIN, "")
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        pytest.fail("requires the full approved ai_soc_test Docker container ID", pytrace=False)
    return observer, pin


def _pinned_addresses(container_id):
    try:
        return docker_postgres_identity(container_id=container_id, local=True)
    except ValueError:
        pytest.fail("approved ai_soc_test Docker container mismatch", pytrace=False)


def _verify_identity(connection, login, addresses, *, read_only):
    database, authenticated, current, major, server, client, port, restricted, mode = (
        connection.execute(_IDENTITY).one()
    )
    try:
        pair = IPv4Address(str(server)), IPv4Address(str(client))
    except ValueError:
        pytest.fail("invalid ai_soc_test connected endpoint", pytrace=False)
    if (
        (database, authenticated, current, major, port) != ("ai_soc_test", login, login, 16, 5432)
        or pair not in addresses or restricted is not True or mode != read_only
    ):
        pytest.fail("restricted PostgreSQL session identity or target mismatch", pytrace=False)


def _verify_revision(observer: URL, addresses) -> None:
    observer_engine = create_engine(
        observer, poolclass=NullPool, hide_parameters=True,
        connect_args={"hostaddr": "127.0.0.1", "connect_timeout": 5},
    )
    try:
        with observer_engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(text("SET LOCAL statement_timeout = '5s'"))
                _verify_identity(connection, observer.username, addresses, read_only="on")
                if connection.execute(_OBSERVER_HAS_ELEVATED_PATH).scalar_one() is not False:
                    pytest.fail("observer has ownership, creation, or elevated role access", pytrace=False)
                revision = connection.execute(text(
                    "SELECT version_num FROM public.alembic_version"
                )).scalars().all()
                if revision != [BASELINE]:
                    pytest.fail("unexpected ai_soc_test Alembic revision", pytrace=False)
            finally:
                transaction.rollback()
    finally:
        observer_engine.dispose()


@pytest.fixture
def restricted_session():
    observer, container_id = _approved_configuration()
    addresses = _pinned_addresses(container_id)
    with ExitStack() as resources:
        try:
            # The existing autouse guard also checks the runner's engine and endpoint.
            connection = resources.enter_context(engine.connect())
            transaction = connection.begin()
            resources.callback(transaction.rollback)
            connection.execute(text("SET LOCAL statement_timeout = '5s'"))
            _verify_identity(connection, _RUNNER, addresses, read_only="off")
            # This coordinates guarded and legacy migrations, not direct administrator DDL.
            if connection.execute(
                text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": LOCK_KEY},
            ).scalar_one() is not True:
                pytest.fail("ai_soc_test migration advisory lock unavailable", pytrace=False)
            _verify_revision(observer, addresses)
            if _pinned_addresses(container_id) != addresses:
                pytest.fail("ai_soc_test Docker endpoint changed during preflight", pytrace=False)
        except SQLAlchemyError:
            pytest.fail("restricted runner or observer database preflight failed", pytrace=False)

        with Session(bind=connection, autoflush=True, join_transaction_mode="rollback_only") as session:
            yield session


def test_real_restricted_lookup_and_no_autoflush(restricted_session):
    first = Tenant(name="E2 test tenant", slug=f"e2-{uuid4().hex}")
    other = Tenant(name="E2 other tenant", slug=f"e2-{uuid4().hex}")
    restricted_session.add_all([first, other])
    restricted_session.flush()
    fields = dict(
        evidence_type="observation", source_type="wazuh", source_reference="e2:test-observation",
        collector_name="e2-test", collector_version="1.0", trust_level="source_verified",
        event_time=datetime.now(timezone.utc), payload={"example": True},
    )
    entry = EvidenceRecord(
        **fields, tenant_id=first.id, content_sha256=calculate_evidence_hash(**fields)
    )
    restricted_session.add(entry)
    restricted_session.flush()

    pending = Tenant(name="E2 pending", slug=f"e2-{uuid4().hex}")
    restricted_session.add(pending)
    repository = PostgresEvidenceRepository(restricted_session)
    bundle = repository.load_stored_bundle(first.id, (entry.id,))
    assert bundle[0].content_sha256 == entry.content_sha256
    assert bundle[0].tenant_id == first.id
    assert not hasattr(bundle[0], "classification")
    assert pending.id is None

    for tenant_id, evidence_id in ((other.id, entry.id), (first.id, uuid4())):
        with pytest.raises(EvidenceRejected, match="EVIDENCE_NOT_FOUND"):
            repository.load_stored_bundle(tenant_id, (evidence_id,))


class TestObserverPreflight:
    """Offline fixture tests. No real database engine is connected here."""

    @pytest.fixture
    def fake_preflight(self, monkeypatch):
        runner_url = "postgresql+psycopg://ai_soc_test_runner:fixture@127.0.0.1:5432/ai_soc_test"
        observer_url = "postgresql+psycopg://e2_observer:fixture@127.0.0.1:5432/ai_soc_test"
        for key in tuple(os.environ):
            if key.startswith("PG") or key in {"AI_SOC_ADVISORY_RUN_ID", "DOCKER_HOST", "DOCKER_CONTEXT"}:
                monkeypatch.delenv(key)
        monkeypatch.setenv("DATABASE_URL", runner_url)
        monkeypatch.setenv(_OBSERVER_URL, observer_url)
        monkeypatch.setenv(_OBSERVER_LOGIN, "e2_observer")
        monkeypatch.setenv(_CONTAINER_PIN, "a" * 64)

        trace = []
        pair = (IPv4Address("192.0.2.2"), IPv4Address("192.0.2.1"))
        state = SimpleNamespace(
            runner_identity=("ai_soc_test", _RUNNER, _RUNNER, 16, *pair, 5432, True, "off"),
            observer_identity=("ai_soc_test", "e2_observer", "e2_observer", 16, *pair, 5432, True, "on"),
            elevated=False, lock=True, revision=[BASELINE], trace=trace,
        )
        pin = Mock(return_value=frozenset({pair}))
        monkeypatch.setitem(globals(), "docker_postgres_identity", pin)

        def fake_engine(label, url):
            transaction = Mock()
            transaction.rollback.side_effect = lambda: trace.append((label, "rollback"))
            connection = Mock()
            connection.begin.return_value = transaction

            def execute(statement, parameters=None):
                sql = str(statement)
                if statement is _IDENTITY:
                    trace.append((label, "identity"))
                    return Mock(**{"one.return_value": getattr(state, f"{label}_identity")})
                if statement is _OBSERVER_HAS_ELEVATED_PATH:
                    assert label == "observer"
                    return Mock(**{"scalar_one.return_value": state.elevated})
                if "pg_try_advisory_xact_lock" in sql:
                    assert label == "runner" and parameters == {"key": LOCK_KEY}
                    trace.append((label, "lock"))
                    return Mock(**{"scalar_one.return_value": state.lock})
                if "alembic_version" in sql:
                    assert label == "observer"
                    trace.append((label, "revision"))
                    return Mock(**{"scalars.return_value.all.return_value": state.revision})
                assert sql.startswith(("SET LOCAL", "SET TRANSACTION"))
                trace.append((label, sql))
                return Mock()

            connection.execute.side_effect = execute
            db_engine = Mock(url=make_url(url))
            manager = MagicMock()
            manager.__enter__.return_value = connection
            manager.__exit__.side_effect = lambda *args: trace.append((label, "close"))
            db_engine.connect.return_value = manager
            db_engine.dispose.side_effect = lambda: trace.append((label, "dispose"))
            return db_engine, connection

        state.runner_engine, state.runner_connection = fake_engine("runner", runner_url)
        state.observer_engine, state.observer_connection = fake_engine("observer", observer_url)
        state.create = Mock(return_value=state.observer_engine)
        state.pin = pin
        state.session = MagicMock()
        monkeypatch.setitem(globals(), "engine", state.runner_engine)
        monkeypatch.setitem(globals(), "create_engine", state.create)
        monkeypatch.setitem(globals(), "Session", state.session)
        return state

    @pytest.mark.parametrize(("key", "reason"), [
        ("DATABASE_URL", "explicit DATABASE_URL"),
        (_OBSERVER_URL, "explicit observer"),
        (_OBSERVER_LOGIN, "explicit observer"),
    ])
    def test_requires_separate_explicit_configuration(self, monkeypatch, fake_preflight, key, reason):
        monkeypatch.delenv(key)
        with pytest.raises(pytest.skip.Exception, match=reason):
            next(restricted_session.__wrapped__())
        fake_preflight.runner_engine.connect.assert_not_called()
        fake_preflight.create.assert_not_called()

    @pytest.mark.parametrize("invalid", [
        "postgresql+psycopg://e2_observer:fixture@127.0.0.1:5432/ai_soc",
        "postgresql+psycopg://e2_observer:fixture@localhost:5432/ai_soc_test",
        "postgresql+psycopg://e2_observer:fixture@127.0.0.1:5432/ai_soc_test?hostaddr=192.0.2.4",
        "postgresql+psycopg://wrong:fixture@127.0.0.1:5432/ai_soc_test",
        "postgresql+psycopg://e2_observer@127.0.0.1:5432/ai_soc_test",
    ])
    def test_invalid_observer_url_fails_before_connect(self, monkeypatch, fake_preflight, invalid):
        monkeypatch.setenv(_OBSERVER_URL, invalid)
        with pytest.raises(pytest.fail.Exception, match="observer URL"):
            next(restricted_session.__wrapped__())
        fake_preflight.runner_engine.connect.assert_not_called()
        fake_preflight.create.assert_not_called()

    @pytest.mark.parametrize("login", ["ai_soc", "postgres", _RUNNER])
    def test_configured_administrator_or_runner_cannot_be_observer(self, monkeypatch, fake_preflight, login):
        monkeypatch.setenv(_OBSERVER_LOGIN, login)
        monkeypatch.setenv(_OBSERVER_URL, f"postgresql+psycopg://{login}:fixture@127.0.0.1:5432/ai_soc_test")
        with pytest.raises(pytest.fail.Exception, match="approved separate login"):
            next(restricted_session.__wrapped__())
        fake_preflight.runner_engine.connect.assert_not_called()
        fake_preflight.create.assert_not_called()

    def test_runner_database_is_checked_independently(self, monkeypatch, fake_preflight):
        wrong = fake_preflight.runner_engine.url.set(database="ai_soc")
        fake_preflight.runner_engine.url = wrong
        monkeypatch.setenv("DATABASE_URL", wrong.render_as_string(hide_password=False))
        with pytest.raises(pytest.UsageError, match="explicit ai_soc_test"):
            next(restricted_session.__wrapped__())
        fake_preflight.runner_engine.connect.assert_not_called()
        fake_preflight.create.assert_not_called()

    def test_runner_cannot_fall_back_to_administrator(self, monkeypatch, fake_preflight):
        wrong = fake_preflight.runner_engine.url.set(username="ai_soc")
        fake_preflight.runner_engine.url = wrong
        monkeypatch.setenv("DATABASE_URL", wrong.render_as_string(hide_password=False))
        with pytest.raises(pytest.fail.Exception, match="actual ai_soc_test_runner login"):
            next(restricted_session.__wrapped__())
        fake_preflight.runner_engine.connect.assert_not_called()
        fake_preflight.create.assert_not_called()

    def test_observer_connect_failure_disposes_engine_without_fallback(self, fake_preflight):
        fake_preflight.observer_engine.connect.side_effect = SQLAlchemyError("synthetic driver details")
        with pytest.raises(pytest.fail.Exception, match="database preflight failed") as failure:
            next(restricted_session.__wrapped__())
        assert "synthetic driver details" not in str(failure.value)
        fake_preflight.create.assert_called_once()
        fake_preflight.runner_engine.connect.assert_called_once()
        fake_preflight.session.assert_not_called()
        assert fake_preflight.trace[-3:] == [
            ("observer", "dispose"), ("runner", "rollback"), ("runner", "close"),
        ]

    def test_docker_pin_mismatch_fails_before_connect(self, fake_preflight):
        fake_preflight.pin.side_effect = ValueError("synthetic mismatch")
        with pytest.raises(pytest.fail.Exception, match="Docker container mismatch"):
            next(restricted_session.__wrapped__())
        fake_preflight.pin.assert_called_once_with(container_id="a" * 64, local=True)
        fake_preflight.runner_engine.connect.assert_not_called()
        fake_preflight.create.assert_not_called()

    @pytest.mark.parametrize(("label", "index", "value"), [
        ("runner", 0, "ai_soc"), ("runner", 3, 15),
        ("observer", 1, "wrong"), ("observer", 2, "switched"),
        ("observer", 4, "198.51.100.2"), ("observer", 5, "198.51.100.1"),
        ("observer", 6, 5434), ("observer", 7, False), ("observer", 8, "off"),
    ])
    def test_connected_mismatch_aborts_before_fixture_writes(self, fake_preflight, label, index, value):
        field = f"{label}_identity"
        identity = list(getattr(fake_preflight, field))
        identity[index] = value
        setattr(fake_preflight, field, tuple(identity))

        with pytest.raises(pytest.fail.Exception, match="session identity or target mismatch"):
            next(restricted_session.__wrapped__())
        fake_preflight.session.assert_not_called()
        assert ("observer", "revision") not in fake_preflight.trace
        assert fake_preflight.trace[-2:] == [("runner", "rollback"), ("runner", "close")]
        if label == "observer":
            assert ("observer", "dispose") in fake_preflight.trace
        else:
            fake_preflight.create.assert_not_called()

    @pytest.mark.parametrize(("change", "value", "reason"), [
        ("lock", False, "migration advisory lock unavailable"),
        ("elevated", True, "elevated role access"),
        ("revision", [], "unexpected ai_soc_test Alembic revision"),
        ("revision", ["wrong"], "unexpected ai_soc_test Alembic revision"),
        ("revision", [BASELINE, BASELINE], "unexpected ai_soc_test Alembic revision"),
    ])
    def test_lock_role_and_revision_failures_roll_back(self, fake_preflight, change, value, reason):
        setattr(fake_preflight, change, value)
        with pytest.raises(pytest.fail.Exception, match=reason):
            next(restricted_session.__wrapped__())
        fake_preflight.session.assert_not_called()
        assert fake_preflight.trace[-2:] == [("runner", "rollback"), ("runner", "close")]
        if change == "lock":
            fake_preflight.create.assert_not_called()
        else:
            assert fake_preflight.trace[-5:-2] == [
                ("observer", "rollback"), ("observer", "close"), ("observer", "dispose"),
            ]
        if change == "elevated":
            assert ("observer", "revision") not in fake_preflight.trace

    def test_endpoint_drift_after_observer_blocks_fixture_writes(self, fake_preflight):
        fake_preflight.pin.side_effect = [fake_preflight.pin.return_value, frozenset()]
        with pytest.raises(pytest.fail.Exception, match="Docker endpoint changed"):
            next(restricted_session.__wrapped__())
        fake_preflight.session.assert_not_called()
        assert fake_preflight.trace[-5:] == [
            ("observer", "rollback"), ("observer", "close"), ("observer", "dispose"),
            ("runner", "rollback"), ("runner", "close"),
        ]

    @pytest.mark.parametrize("test_failure", [False, True])
    def test_observer_closes_and_runner_holds_lock_until_fixture_rollback(self, fake_preflight, test_failure):
        fixture = restricted_session.__wrapped__()
        session = next(fixture)
        assert session is fake_preflight.session.return_value.__enter__.return_value
        fake_preflight.session.assert_called_once_with(
            bind=fake_preflight.runner_connection, autoflush=True, join_transaction_mode="rollback_only",
        )
        assert fake_preflight.create.call_args.args[0].username == "e2_observer"
        assert fake_preflight.create.call_args.kwargs["poolclass"] is NullPool
        assert fake_preflight.trace.index(("runner", "lock")) < fake_preflight.trace.index(("observer", "identity"))
        assert fake_preflight.trace.index(("observer", "SET TRANSACTION READ ONLY")) < (
            fake_preflight.trace.index(("observer", "revision"))
        )
        assert fake_preflight.trace[-3:] == [
            ("observer", "rollback"), ("observer", "close"), ("observer", "dispose"),
        ]
        assert ("runner", "rollback") not in fake_preflight.trace
        if test_failure:
            with pytest.raises(RuntimeError, match="synthetic test failure"):
                fixture.throw(RuntimeError("synthetic test failure"))
        else:
            with pytest.raises(StopIteration):
                next(fixture)
        assert fake_preflight.trace[-2:] == [("runner", "rollback"), ("runner", "close")]
        assert fake_preflight.pin.call_count == 2
