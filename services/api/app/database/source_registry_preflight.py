"""Restricted B4 predecessor preflight. The caller supplies independently pinned inputs."""

from contextlib import ExitStack
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from ipaddress import IPv4Address
from itertools import islice
import os
from pathlib import Path
import re
import signal
import ssl
from tempfile import TemporaryDirectory
from threading import current_thread, main_thread
from time import monotonic
from types import SimpleNamespace

import psycopg
from psycopg import IsolationLevel
from psycopg.pq import TransactionStatus
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import dialect
from sqlalchemy.engine import make_url

from app.database import migration_guard as guard
from app.database import source_registry_migration_plan as plan
from app.database import source_registry_observer_adapter as observer
from app.database.source_registry_artifact import REPORT, manifest_bytes
from app.database.test_target import docker_postgres_identity


_HEX = re.compile(r"[0-9a-f]{64}")
_SCOPE = "b4-predecessor-read-only-v2"
_DIALECT = dialect(paramstyle="pyformat")

_IDENTITY = text("""
SELECT pg_catalog.current_database(), session_user, current_user,
       pg_catalog.inet_server_addr(), pg_catalog.inet_client_addr(), pg_catalog.inet_server_port(),
       pg_catalog.current_setting('server_version_num')::integer,
       pg_catalog.current_setting('transaction_read_only'),
       pg_catalog.current_setting('transaction_isolation'),
       pg_catalog.current_setting('session_replication_role'),
       pg_catalog.current_schemas(true),
       (SELECT setting::integer FROM pg_catalog.pg_settings WHERE name = 'statement_timeout' AND unit = 'ms'),
       (SELECT setting::integer FROM pg_catalog.pg_settings WHERE name = 'lock_timeout' AND unit = 'ms'),
       (SELECT setting::integer FROM pg_catalog.pg_settings
        WHERE name = 'idle_in_transaction_session_timeout' AND unit = 'ms'),
       pg_catalog.current_setting('application_name'), pg_catalog.pg_backend_pid(),
       pg_catalog.pg_postmaster_start_time(),
       (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())
""")
_BOUNDARY = text("""
SELECT NOT pg_catalog.has_database_privilege(current_user, 'ai_soc', 'CONNECT'),
       pg_catalog.has_database_privilege(:owner, current_database(), 'TEMP'),
       NOT pg_catalog.has_parameter_privilege(current_user, 'session_replication_role', 'SET'),
       NOT EXISTS (
           SELECT FROM pg_catalog.pg_roles r
           WHERE NOT r.rolsuper AND r.rolname <> :owner
             AND pg_catalog.has_schema_privilege(r.oid, 'public', 'CREATE')
       ) AND NOT EXISTS (
           SELECT FROM pg_catalog.pg_proc p
           WHERE p.pronamespace = 'public'::pg_catalog.regnamespace AND EXISTS (
               SELECT FROM pg_catalog.pg_proc builtin
               WHERE builtin.pronamespace = 'pg_catalog'::pg_catalog.regnamespace
                 AND builtin.proname = p.proname
           )
       ) AND NOT EXISTS (
           SELECT FROM pg_catalog.pg_operator WHERE oprnamespace = 'public'::pg_catalog.regnamespace
       ) AND NOT EXISTS (
           SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
             AND p.prorettype <> 'pg_catalog.trigger'::pg_catalog.regtype
             AND pg_catalog.has_schema_privilege(n.oid, 'USAGE')
             AND pg_catalog.has_function_privilege(p.oid, 'EXECUTE')
       )
""")

_SECURITY_STATE = text("""
SELECT encode(sha256(convert_to(jsonb_build_array(
    (SELECT jsonb_agg(ROW(oid, rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb,
        rolcanlogin, rolreplication, rolbypassrls) ORDER BY oid) FROM pg_roles),
    (SELECT jsonb_agg(to_jsonb(m) ORDER BY oid) FROM pg_auth_members m),
    (SELECT jsonb_agg(ROW(oid, datdba, datacl, datallowconn) ORDER BY oid)
     FROM pg_database WHERE datname IN (current_database(), 'ai_soc')),
    (SELECT jsonb_agg(ROW(oid, nspowner, nspacl) ORDER BY oid) FROM pg_namespace),
    (SELECT jsonb_agg(ROW(oid, relowner, relacl, relrowsecurity, relforcerowsecurity) ORDER BY oid)
     FROM pg_class),
    (SELECT jsonb_agg(ROW(attrelid, attnum, attacl) ORDER BY attrelid, attnum)
     FROM pg_attribute WHERE attacl IS NOT NULL),
    (SELECT jsonb_agg(ROW(oid, proowner, proacl, prosecdef) ORDER BY oid) FROM pg_proc),
    (SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_default_acl a),
    (SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_parameter_acl a)
)::text, 'UTF8')), 'hex')
""")

# Exact query text digests from verify_roles, verify_legacy_audit and
# verify_default_privileges. Review SQL and repin together on any change.
_ROLE_READS = """
2e85668c7e7bf9ff81a92b06c261b1e3d0a014a4aacc86ff9513adca0fb0e15f
0dc88e373d89069a0f587dc985f7a8a5fd36e6d31336678e012e152732c528e6
b58921b86dba8a39c051fea34d148a25fd79bbec66113d6f9b15a00a45277ee2
ea5b45b087fc24267f8f652c4037df58f633fb96b699f562eedb7a43f679f7e7
b2e737f417c51143e3486a4449832a39bbaf1531d9059eaede9d2df88f1414ea
326c2e6d32a24589879394a5d598244dfdadebbe17f266ea3549aec77b63791a
1abffc1a964c1b117197884531da244b12891399127cf9fe8ef2143bef5ebfe5
18b4f5f8f3dbfc2ad6eab337e6c0409b7e740d446cb25524244612082b1fe9a2
09f927ad8d304b6ef9add8ef633b521dc04b5a1f7b8c345c58ff25aa34e644e8
dc57cb6d94bd0bce644b4325249718196bd6ce11a50cb2e331cf77e5f904b064
0b2f7fbda2c2be37220f2e3921ad0ff1e60503e8ed84979cfe1b45e7a2eeca27
0d99e4695e1990ef8970a198e7c51c605c20b1661d5def2fe1020ecd61929cc1
""".split()

_ROLE_BINDS = dict(zip(_ROLE_READS, (
    (), ("login", "owner"), (), (), ("login", "owner"), ("login", "owner"),
    ("names",), (), (), (), ("owner",), ("owner",),
), strict=True))
_BIND_VALUES = {"login": guard.LOGIN, "owner": guard.OWNER,
                "names": (*guard.APPLICATION_TABLES, "alembic_version")}
_PROTOCOL = ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", "DECLARE CURSOR WITHOUT HOLD",
             "DESCRIBE PORTAL", "FETCH bounded rows", "CLOSE CURSOR", "ROLLBACK", "CLOSE CONNECTION")



@dataclass(frozen=True)
class DockerPin:
    container_id: str
    image_id: str
    network: str
    network_id: str
    address_pair: tuple[IPv4Address, IPv4Address]


@dataclass(frozen=True)
class Budgets:
    connect_seconds: int
    statement_ms: int
    lock_ms: int
    max_rows: int
    max_sessions: int
    deadline_seconds: int
    recovery_seconds: int


@dataclass(frozen=True)
class Approval:
    scope: str
    decision_id: str
    independent_reviewer: str
    valid_from: datetime
    expires_at: datetime
    observed_target: DockerPin
    approved_target: DockerPin
    database: str
    endpoint: tuple[str, int]
    tls_server_identity: str
    tls_ca_sha256: str
    freeze_sha256: str
    migrator_login: str
    owner_role: str
    observer_login: str
    migrator_secret_ref: str
    observer_secret_ref: str
    candidate_manifest_sha256: str
    approved_manifest_sha256: str
    prior_manifest_sha256: str
    application_isolation_sha256: str
    observer_inventory_sha256: str
    supplemental_inventory_sha256: str
    predecessor_queries: tuple[str, ...]
    budgets: Budgets


@dataclass(frozen=True)
class Report:
    status: str
    stage: str
    code: str
    versions: tuple[int, ...] = ()
    predecessor: str | None = None
    evidence_sha256: str | None = None
    target_recheck: str = "NOT_ATTEMPTED"
    run_id: str | None = None
    backend_pids: tuple[int, ...] = ()
    approval_sha256: str | None = None


class _Stop(Exception):
    pass


def _sha(data):
    return sha256(data).hexdigest()


def approval_sha256(approval: Approval) -> str:
    return observer._digest(asdict(approval))


def supplemental_inventory_sha256() -> str:
    return observer._digest([str(_IDENTITY), str(_BOUNDARY), str(_SECURITY_STATE),
                             _ROLE_BINDS, _BIND_VALUES, _PROTOCOL])


def _validate(packet, trusted_pin, root, isolation, ca, freeze):
    now = datetime.now(timezone.utc)
    if (type(packet) is not Approval or type(trusted_pin) is not str or not _HEX.fullmatch(trusted_pin)
            or not compare_digest(approval_sha256(packet), trusted_pin)
            or packet.scope != _SCOPE or not packet.decision_id.strip()
            or not packet.independent_reviewer.strip()
            or not packet.valid_from <= now < packet.expires_at):
        raise _Stop("APPROVAL_REQUIRED")
    target = packet.approved_target
    if (type(target) is not DockerPin or packet.observed_target != target
            or not _HEX.fullmatch(target.container_id)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", target.image_id)
            or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", target.network)
            or not _HEX.fullmatch(target.network_id)
            or type(target.address_pair) is not tuple or len(target.address_pair) != 2
            or any(type(ip) is not IPv4Address or ip.is_loopback or ip.is_unspecified
                   for ip in target.address_pair) or target.address_pair[0] == target.address_pair[1]
            or (packet.database, packet.endpoint, packet.migrator_login, packet.owner_role)
            != (guard.TARGET, ("127.0.0.1", 5432), guard.LOGIN, guard.OWNER)
            or packet.tls_server_identity != packet.endpoint[0]):
        raise _Stop("TARGET_NOT_APPROVED")
    if (not observer.contract._LOGIN.fullmatch(packet.observer_login)
            or packet.observer_login.startswith("pg_")
            or packet.observer_login in {guard.LOGIN, guard.OWNER, "ai_soc", "postgres", "ai_soc_test_runner"}
            or not packet.migrator_secret_ref.strip() or not packet.observer_secret_ref.strip()
            or packet.migrator_secret_ref == packet.observer_secret_ref):
        raise _Stop("IDENTITIES_NOT_APPROVED")
    b = packet.budgets
    if (type(b) is not Budgets or any(type(n) is not int or n <= 0 for n in asdict(b).values())
            or b.max_sessions != 2 or b.connect_seconds < 2 or b.connect_seconds >= b.deadline_seconds
            or not b.lock_ms <= b.statement_ms < 1000 * b.deadline_seconds
            or b.deadline_seconds > 3600 or b.recovery_seconds > 30 or b.max_rows > 100_000):
        raise _Stop("BUDGET_NOT_APPROVED")
    queries = observer.READ_QUERIES
    if (packet.predecessor_queries != tuple(n for n, q in queries.items() if not q.successor_only)
            or packet.observer_inventory_sha256 != observer.QUERY_INVENTORY_SHA256
            or packet.observer_inventory_sha256 != observer._digest({n: asdict(q) for n, q in queries.items()})
            or packet.supplemental_inventory_sha256 != supplemental_inventory_sha256()):
        raise _Stop("QUERY_INVENTORY_MISMATCH")
    if (type(isolation) is not bytes or not isolation
            or _sha(isolation) != packet.application_isolation_sha256):
        raise _Stop("ISOLATION_MISMATCH")
    if type(ca) is not bytes or not ca or len(ca) > 256_000 or _sha(ca) != packet.tls_ca_sha256:
        raise _Stop("TLS_CA_MISMATCH")
    if type(freeze) is not bytes or not freeze or _sha(freeze) != packet.freeze_sha256:
        raise _Stop("FREEZE_EVIDENCE_MISMATCH")
    if (_sha(manifest_bytes(root)) != packet.candidate_manifest_sha256
            or packet.approved_manifest_sha256 != packet.candidate_manifest_sha256
            or _sha((root / REPORT).read_bytes()) != packet.prior_manifest_sha256):
        raise _Stop("MANIFEST_MISMATCH")


def _url(raw, login):
    if type(raw) is not str:
        raise _Stop("CREDENTIAL_TARGET_MISMATCH")
    url = make_url(raw)
    if ((url.drivername, url.username, url.database, url.host, url.port)
            != ("postgresql+psycopg", login, guard.TARGET, "127.0.0.1", 5432)
            or not url.password or url.query or "?" in raw):
        raise _Stop("CREDENTIAL_TARGET_MISMATCH")
    return url


def _docker(pin):
    try:
        pairs = docker_postgres_identity(container_id=pin.container_id, local=True,
                                         exact=(pin.image_id, pin.network, pin.network_id))
    except ValueError:
        raise _Stop("DOCKER_IDENTITY_MISMATCH") from None
    if pairs != frozenset({pin.address_pair}):
        raise _Stop("DOCKER_IDENTITY_MISMATCH")


class _Rows:
    def __init__(self, rows):
        self._rows = iter(rows)

    def __iter__(self):
        return self._rows

    def fetchmany(self, size):
        return list(islice(self._rows, size))

    def all(self):
        return list(self._rows)

    def one(self):
        row, = self.all()
        return row

    def scalar_one(self):
        return self.one()[0]

    def scalar_one_or_none(self):
        rows = self.all()
        return None if not rows else _Rows(rows).scalar_one()

    def close(self):
        self._rows = iter(())


class _ReadConnection:
    """Expose the observer's narrow protocol without a raw connection handle."""

    dialect = SimpleNamespace(name="postgresql", driver="psycopg")
    invalidated = False

    def __init__(self, driver, queries, max_rows, *, migrator):
        self._driver = driver
        self._max_rows = max_rows
        self._migrator = migrator
        self._queries = {observer.READ_QUERIES[n].sql: observer.READ_QUERIES[n] for n in queries}
        self.connection = SimpleNamespace(driver_connection=SimpleNamespace(autocommit=driver.autocommit))

    @property
    def closed(self):
        return self._driver.closed

    @property
    def is_active(self):
        return self._driver.info.transaction_status == TransactionStatus.INTRANS

    def get_transaction(self):
        return self if self.is_active else None

    def get_nested_transaction(self):
        return None

    def execute(self, statement, parameters=None):
        if not self.is_active:
            raise _Stop("TRANSACTION_LOST")
        sql = str(statement)
        params = {} if parameters is None else parameters
        if type(params) is not dict:
            raise _Stop("UNAPPROVED_QUERY")
        query = self._queries.get(sql)
        if query is not None:
            expected = {k: list(v) if type(v) is tuple else v for k, v in query.binds}
            allowed = params == expected
        else:
            role_args = _ROLE_BINDS.get(_sha(sql.encode()))
            allowed = (sql in {str(_IDENTITY), str(_SECURITY_STATE)} and not params
                       or sql == str(_BOUNDARY) and params == {"owner": guard.OWNER}
                       or self._migrator and role_args is not None and params == {
                           key: list(_BIND_VALUES[key]) if key == "names" else _BIND_VALUES[key]
                           for key in role_args
                       })
        if not allowed:
            raise _Stop("UNAPPROVED_QUERY")
        maximum = self._max_rows
        if query is not None and query.maximum is not None:
            maximum = min(maximum, query.maximum)
        compiled = text(sql).compile(dialect=_DIALECT)
        with self._driver.cursor(name="b4_observation") as cursor:
            cursor.execute(str(compiled), params)
            rows = cursor.fetchmany(maximum + 1)
        if len(rows) > maximum:
            raise _Stop("QUERY_ROW_LIMIT")
        return _Rows(rows)


def _identity(row, login, pin, budgets, run_id):
    (database, session, current, server, client, port, version, mode, isolation, replica,
     path, stmt, lock, idle, app, pid, started, database_oid) = row
    if ((database, session, current, port) != (guard.TARGET, login, login, 5432)
            or tuple(map(IPv4Address, (server, client))) != pin.address_pair):
        raise _Stop("SESSION_IDENTITY_MISMATCH")
    if type(version) is not int or version // 10000 != 16:
        raise _Stop("POSTGRES_VERSION_MISMATCH")
    if (mode, isolation, replica, tuple(path)) != ("on", "repeatable read", "origin", ("pg_catalog",)):
        raise _Stop("TRANSACTION_SETTINGS_MISMATCH")
    if (stmt, lock, idle) != (budgets.statement_ms, budgets.lock_ms, budgets.statement_ms):
        raise _Stop("TIMEOUT_SETTINGS_MISMATCH")
    if type(started) is not datetime or started.utcoffset() is None or type(database_oid) is not int or database_oid <= 0:
        raise _Stop("SESSION_IDENTITY_MISMATCH")
    if app != run_id or type(pid) is not int or pid <= 0:
        raise _Stop("SESSION_IDENTITY_MISMATCH")
    return (version, started, database_oid), pid


def _session(url, packet, evidence, *, migrator, root, ca_path, run_id, expected=None, admitted_instance=None):
    b = packet.budgets
    driver = psycopg.connect(
        host=packet.tls_server_identity, hostaddr=url.host, port=url.port, dbname=url.database,
        user=url.username, password=url.password, passfile="/dev/null",
        connect_timeout=b.connect_seconds, sslmode="verify-full", sslrootcert=str(ca_path),
        sslcertmode="disable", gssencmode="disable", channel_binding="require", application_name=run_id,
        options=f"-c search_path=pg_catalog -c statement_timeout={b.statement_ms}"
                f" -c lock_timeout={b.lock_ms} -c idle_in_transaction_session_timeout={b.statement_ms}"
                " -c default_transaction_read_only=on",
    )
    try:
        driver.read_only = True
        driver.isolation_level = IsolationLevel.REPEATABLE_READ
        # Psycopg starts the configured transaction before this first read.
        with driver.cursor() as cursor:
            cursor.execute(str(_IDENTITY), prepare=True)
            initial = cursor.fetchone()
        allowed = () if migrator else packet.predecessor_queries
        connection = _ReadConnection(driver, allowed, b.max_rows, migrator=migrator)
        server_identity, pid = _identity(initial, url.username, packet.approved_target, b, run_id)
        if admitted_instance is not None and server_identity != admitted_instance:
            raise _Stop("SESSION_IDENTITY_MISMATCH")
        if expected is not None and server_identity != expected[0]:
            raise _Stop("INCONSISTENT_OBSERVATIONS")
        if not connection.is_active:
            raise _Stop("TRANSACTION_LOST")
        if connection.execute(_BOUNDARY, {"owner": guard.OWNER}).one() != (True, True, True, True):
            raise _Stop("DATABASE_PRIVILEGE_BOUNDARY")
        security = connection.execute(_SECURITY_STATE).scalar_one()
        if type(security) is not str or not _HEX.fullmatch(security):
            raise _Stop("SECURITY_STATE_UNVERIFIED")
        if expected is not None and (security != expected[1] or pid == expected[2]):
            raise _Stop("INCONSISTENT_OBSERVATIONS")
        if migrator:
            guard.verify_roles(connection)
            if not plan.verify_default_privileges(connection, owner=guard.OWNER):
                raise _Stop("DEFAULT_PRIVILEGES_MISMATCH")
            return (server_identity, security, pid), None
        approval = observer.Approval(evidence.target, packet.approved_manifest_sha256,
                                     packet.application_isolation_sha256, b.statement_ms, b.max_rows)
        captured = observer.capture(connection, root=root, approval=approval,
                                    container=evidence, successor=False)
        if isinstance(captured, observer.Rejection):
            raise _Stop(captured.code)
        accepted = observer.accept_predecessor(captured)
        if not isinstance(accepted, observer.Accepted):
            raise _Stop(accepted.code)
        final = _identity(connection.execute(_IDENTITY).one(), url.username, packet.approved_target, b, run_id)
        snapshot = accepted.capture.snapshot
        if (final != (server_identity, pid)
                or (snapshot.backend_pid, snapshot.server_started, snapshot.database_oid)
                != (pid, *server_identity[1:])):
            raise _Stop("SESSION_IDENTITY_MISMATCH")
        return (server_identity, security, pid), accepted.capture.evidence_sha256
    finally:
        try:
            driver.rollback()
            if driver.info.transaction_status != TransactionStatus.IDLE:
                raise ValueError
        except Exception:
            raise _Stop("ROLLBACK_FAILED") from None
        finally:
            try:
                driver.close()
                if not driver.closed:
                    raise ValueError
            except Exception:
                raise _Stop("CLOSE_FAILED") from None


def _deadline(*_):
    raise _Stop("PREFLIGHT_DEADLINE")


def run(packet: Approval, *, trusted_approval_sha256: str, root: Path,
        application_isolation: bytes, ca: bytes, freeze: bytes, run_id: str,
        credentials: dict[str, str], admission=None) -> Report:
    """Run in a dedicated main-thread process with an independently supplied approval pin."""
    stage = "approval"
    recheck = "NOT_ATTEMPTED"
    resources = ExitStack()
    alarm = False
    previous = None
    try:
        if (type(packet) is not Approval or type(packet.budgets) is not Budgets
                or type(packet.budgets.deadline_seconds) is not int
                or not 0 < packet.budgets.deadline_seconds <= 3600):
            raise _Stop("APPROVAL_REQUIRED")
        if current_thread() is not main_thread() or signal.getitimer(signal.ITIMER_REAL) != (0, 0):
            raise _Stop("DEADLINE_UNAVAILABLE")
        previous = signal.signal(signal.SIGALRM, _deadline)
        alarm = True
        deadline = monotonic() + packet.budgets.deadline_seconds
        alarm_seconds = packet.budgets.deadline_seconds
        if admission is not None:
            deadline = min(deadline, admission.stop_by)
            alarm_seconds = deadline - monotonic()
            if alarm_seconds <= 0:
                raise _Stop("PREFLIGHT_DEADLINE")
        signal.setitimer(signal.ITIMER_REAL, alarm_seconds)
        if any(k.startswith(("PG", "DOCKER_", "GIT_")) for k in os.environ):
            raise _Stop("AMBIENT_CONFIGURATION")
        _validate(packet, trusted_approval_sha256, root, application_isolation, ca, freeze)
        if type(run_id) is not str or not re.fullmatch(r"b4-[0-9a-f]{32}", run_id):
            raise _Stop("RUN_ID_REQUIRED")
        stage = "tls"
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca.decode("ascii"))
        except (UnicodeError, ssl.SSLError):
            raise _Stop("TLS_CA_INVALID") from None
        ca_path = Path(resources.enter_context(TemporaryDirectory(prefix="b4-ca-", dir="/tmp"))) / "approved.pem"
        ca_path.write_bytes(ca)
        stage = "credentials"
        migrator = _url(credentials[packet.migrator_secret_ref], packet.migrator_login)
        independent = _url(credentials[packet.observer_secret_ref], packet.observer_login)
        stage = "target"
        pin = packet.approved_target
        target = observer.contract.Target(pin.container_id, pin.address_pair, packet.observer_login)
        _docker(pin)
        evidence = observer.ContainerEvidence(target)
        if datetime.now(timezone.utc) >= packet.expires_at:
            raise _Stop("APPROVAL_EXPIRED")
        stage = "migrator"
        try:
            first, _ = _session(migrator, packet, evidence, migrator=True, root=root,
                                ca_path=ca_path, run_id=run_id,
                                admitted_instance=admission.instance if admission else None)
            stage = "observer_target"
            _docker(pin)
            stage = "observer"
            if datetime.now(timezone.utc) >= packet.expires_at:
                raise _Stop("APPROVAL_EXPIRED")
            second, digest = _session(independent, packet, evidence, migrator=False, root=root,
                                      ca_path=ca_path, run_id=run_id, expected=first,
                                      admitted_instance=admission.instance if admission else None)
        finally:
            recheck = "DEADLINE_EXPIRED"
            if monotonic() < deadline:
                try:
                    _docker(pin)
                    recheck = "MATCH"
                except Exception:
                    recheck = "FAILED"
        stage = "final_target"
        if recheck != "MATCH":
            raise _Stop("DOCKER_RECHECK_UNVERIFIED")
        _validate(packet, trusted_approval_sha256, root, application_isolation, ca, freeze)
        if not _HEX.fullmatch(digest):
            raise _Stop("INCONSISTENT_OBSERVATIONS")
        if monotonic() >= deadline:
            raise _Stop("PREFLIGHT_DEADLINE")
        if datetime.now(timezone.utc) >= packet.expires_at:
            raise _Stop("APPROVAL_EXPIRED")
        resources.close()
        return Report("PASS", "complete", "VERIFIED", (first[0][0], second[0][0]), guard.BASELINE,
                      digest, recheck, run_id, (first[2], second[2]), trusted_approval_sha256)
    except _Stop as exc:
        return Report("FAIL", stage, str(exc), target_recheck=recheck)
    except guard.Denied:
        return Report("FAIL", stage, "MIGRATOR_SECURITY_MISMATCH", target_recheck=recheck)
    except (psycopg.errors.QueryCanceled, psycopg.errors.LockNotAvailable):
        return Report("FAIL", stage, "QUERY_TIMEOUT", target_recheck=recheck)
    except Exception:
        return Report("FAIL", stage, "PREFLIGHT_FAILED", target_recheck=recheck)
    finally:
        try:
            resources.close()
        except Exception:
            pass
        if alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
