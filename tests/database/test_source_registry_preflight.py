"""Offline caller tests. All connections and Docker observations are injected fakes."""
import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from hashlib import sha256
import inspect
import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from app.database import source_registry_preflight as preflight

from tests.database.test_source_registry_observer_adapter import BEFORE, OK_ROLES, STAMP, transcript
from tests.database.test_source_registry_observer import TARGET, snapshots  # noqa: F401


def compile_sql(sql):
    return str(preflight.text(str(sql)).compile(dialect=preflight._DIALECT))


class Cursor:
    def __init__(self, driver, name):
        self.driver = driver
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, params=None, *, prepare=None):
        if self.name is None:
            assert prepare is True
            assert self.driver.read_only is True
            assert self.driver.isolation_level == preflight.IsolationLevel.REPEATABLE_READ
        self.driver.calls.append(sql)
        result = self.driver.rows[sql]
        if isinstance(result, Exception):
            raise result
        self.rows = result

    def fetchone(self):
        return self.rows[0]

    def fetchmany(self, limit):
        self.driver.fetches.append(limit)
        return self.rows[:limit]


class Driver:
    autocommit = False

    def __init__(self, rows):
        self.rows = rows
        self.info = SimpleNamespace(transaction_status=preflight.TransactionStatus.INTRANS)
        self.calls = []
        self.fetches = []
        self.cleanup = []
        self.closed = False
        self.rollback_error = False
        self.rollback_stalls = False
        self.close_error = False

    def cursor(self, name=None):
        return Cursor(self, name)

    def rollback(self):
        self.cleanup.append("rollback")
        if self.rollback_error:
            raise RuntimeError("secret-value")
        if not self.rollback_stalls:
            self.info.transaction_status = preflight.TransactionStatus.IDLE

    def close(self):
        self.cleanup.append("close")
        if self.close_error:
            raise RuntimeError("secret-value")
        self.closed = True


def guard_sql():
    tree = ast.parse(inspect.getsource(preflight.guard.verify_roles))
    statements = [ast.literal_eval(n.args[0]) for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "text"]
    return sorted(statements, key=lambda sql: next(
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value == sql
    ))


@pytest.fixture
def scenario(monkeypatch, tmp_path, snapshots):
    g, p, o = preflight.guard, preflight.plan, preflight.observer
    now = datetime.now(timezone.utc)
    pin = preflight.DockerPin(TARGET.container_id, "sha256:" + "b" * 64, "bridge", "c" * 64, TARGET.address_pair)
    manifest, previous, isolation = b"current", b"prior", b"independent evidence"
    ca, freeze = b"synthetic CA", b"independent freeze"
    class CAContext:
        def load_verify_locations(self, *, cadata):
            assert cadata == ca.decode("ascii")
    monkeypatch.setattr(preflight.ssl, "SSLContext", lambda _: CAContext())
    run_id = "b4-" + "d" * 32
    for module in (preflight, o):
        monkeypatch.setattr(module, "manifest_bytes", lambda _: manifest)
    prior = tmp_path / preflight.REPORT
    prior.parent.mkdir(parents=True)
    prior.write_bytes(previous)
    packet = preflight.Approval(
        preflight._SCOPE, "test-approval", "independent reviewer",
        now - timedelta(minutes=1), now + timedelta(minutes=1), pin, pin,
        "ai_soc_test", ("127.0.0.1", 5432), "127.0.0.1", sha256(ca).hexdigest(),
        sha256(freeze).hexdigest(), g.LOGIN, g.OWNER, TARGET.login,
        "migrator-ref", "observer-ref", sha256(manifest).hexdigest(), sha256(manifest).hexdigest(),
        sha256(previous).hexdigest(), sha256(isolation).hexdigest(), o.QUERY_INVENTORY_SHA256,
        preflight.supplemental_inventory_sha256(),
        tuple(n for n, q in o.READ_QUERIES.items() if not q.successor_only),
        preflight.Budgets(5, 5000, 1000, 1000, 2, 60, 5),
    )
    inputs = dict(trusted_approval_sha256=preflight.approval_sha256(packet), root=tmp_path,
                  application_isolation=isolation, ca=ca, freeze=freeze, run_id=run_id, credentials={
                      ref: f"postgresql+psycopg://{login}:secret-value@127.0.0.1:5432/ai_soc_test"
                      for ref, login in ((packet.migrator_secret_ref, g.LOGIN), (packet.observer_secret_ref, TARGET.login))
                  })
    identity = lambda login: ("ai_soc_test", login, login, *pin.address_pair, 5432, 160006,
                              "on", "repeatable read", "origin", ["pg_catalog"], 5000, 1000, 5000, run_id,
                              20 if login == TARGET.login else 21, STAMP, 11)
    historical = transcript(snapshots[0], start=BEFORE)
    sql = guard_sql()
    guard_rows = [
        [(True,)],
        [(g.LOGIN, [True, False, False, False, False, False, False]), (g.OWNER, [False] * 7)],
        [OK_ROLES], [(g.OWNER, "pg_database_owner")], [(False, False, True, True)], [(False,)],
        [(name, g.OWNER) for name in (*g.APPLICATION_TABLES, "alembic_version")], [(g.OWNER,)],
    ]
    migrator = {compile_sql(s): rows for s, rows in zip(sql, guard_rows, strict=True)}
    migrator.update({compile_sql(s): rows for s, rows in (
        (p._LEGACY_AUDIT_ROUTINE, historical["audit_routine"]),
        (p._LEGACY_AUDIT_TRIGGERS, historical["audit_triggers"]),
        (p._AUDIT_MUTATION_ROLES, ()), (p._DEFAULT_ACL_CHECK, ((True,),)),
    )})
    independently_observed = {compile_sql(o.READ_QUERIES[n].sql): rows for n, rows in historical.items()}
    drivers = {}
    for login, rows in ((g.LOGIN, migrator), (TARGET.login, independently_observed)):
        rows[str(preflight._IDENTITY)] = [identity(login)]
        rows[compile_sql(preflight._IDENTITY)] = [identity(login)]
        rows[compile_sql(preflight._BOUNDARY)] = [(True, True, True, True)]
        rows[compile_sql(preflight._SECURITY_STATE)] = [("c" * 64,)]
        drivers[login] = Driver(rows)
    opened = []
    docker_calls = []

    def connect(**kwargs):
        assert kwargs["host"] == kwargs["hostaddr"] == "127.0.0.1"
        assert (kwargs["port"], kwargs["dbname"], kwargs["connect_timeout"]) == (5432, "ai_soc_test", 5)
        assert (kwargs["sslmode"], kwargs["sslcertmode"], kwargs["gssencmode"]) == ("verify-full", "disable", "disable")
        assert kwargs["application_name"] == run_id and kwargs["channel_binding"] == "require"
        assert kwargs["passfile"] == "/dev/null" and Path(kwargs["sslrootcert"]).read_bytes() == ca
        assert kwargs["options"] == ("-c search_path=pg_catalog -c statement_timeout=5000"
                                    " -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000"
                                    " -c default_transaction_read_only=on")
        assert all(d.closed for d in opened)
        driver = drivers[kwargs["user"]]
        opened.append(driver)
        return driver

    def inspect_docker(**kwargs):
        docker_calls.append(kwargs)
        assert kwargs == dict(container_id=pin.container_id, local=True,
                              exact=(pin.image_id, pin.network, pin.network_id))
        return frozenset({pin.address_pair})

    monkeypatch.setattr(preflight.psycopg, "connect", connect)
    monkeypatch.setattr(preflight, "docker_postgres_identity", inspect_docker)
    return SimpleNamespace(packet=packet, inputs=inputs, drivers=drivers, opened=opened,
                           docker_calls=docker_calls, sql=sql)


def test_two_restricted_sessions_and_real_observer_capture(scenario):
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.status == "PASS", report
    assert report.predecessor == "d93c6e4fb132"
    assert len(report.evidence_sha256) == 64
    assert report.approval_sha256 == scenario.inputs["trusted_approval_sha256"]
    assert len(scenario.opened) == 2 and len(scenario.docker_calls) == 3
    assert all(driver.cleanup == ["rollback", "close"] for driver in scenario.opened)
    assert "secret-value" not in repr(report)
    assert "not in reports" not in repr(report)
    assert all("SELECT" in sql for d in scenario.opened for sql in d.calls)


@pytest.mark.parametrize("field,value,code", [
    ("decision_id", "forged", "APPROVAL_REQUIRED"),
    ("approved_manifest_sha256", "f" * 64, "MANIFEST_MISMATCH"),
    ("application_isolation_sha256", "f" * 64, "ISOLATION_MISMATCH"),
    ("predecessor_queries", (), "QUERY_INVENTORY_MISMATCH"),
    ("observer_inventory_sha256", "f" * 64, "QUERY_INVENTORY_MISMATCH"),
    ("supplemental_inventory_sha256", "f" * 64, "QUERY_INVENTORY_MISMATCH"),
    ("endpoint", ("127.0.0.1", 6432), "TARGET_NOT_APPROVED"),
    ("observer_login", "postgres", "IDENTITIES_NOT_APPROVED"),
])
def test_rejects_bad_approval_before_docker(scenario, field, value, code):
    packet = replace(scenario.packet, **{field: value})
    if field != "decision_id":
        scenario.inputs["trusted_approval_sha256"] = preflight.approval_sha256(packet)
    assert preflight.run(packet, **scenario.inputs).code == code
    assert not scenario.opened and not scenario.docker_calls


def test_missing_and_expired_approval(scenario):
    assert preflight.run(None, **scenario.inputs).code == "APPROVAL_REQUIRED"
    packet = replace(scenario.packet, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    scenario.inputs["trusted_approval_sha256"] = preflight.approval_sha256(packet)
    assert preflight.run(packet, **scenario.inputs).code == "APPROVAL_REQUIRED"
    assert not scenario.opened


@pytest.mark.parametrize("field,value,code", [
    (0, "ai_soc", "SESSION_IDENTITY_MISMATCH"),
    (2, "postgres", "SESSION_IDENTITY_MISMATCH"),
    (6, 170000, "POSTGRES_VERSION_MISMATCH"),
    (7, "off", "TRANSACTION_SETTINGS_MISMATCH"),
    (8, "read committed", "TRANSACTION_SETTINGS_MISMATCH"),
    (9, "replica", "TRANSACTION_SETTINGS_MISMATCH"),
    (10, ["public"], "TRANSACTION_SETTINGS_MISMATCH"),
    (11, 0, "TIMEOUT_SETTINGS_MISMATCH"),
    (12, 0, "TIMEOUT_SETTINGS_MISMATCH"),
])
def test_wrong_session_stops_before_catalogs(scenario, field, value, code):
    driver = scenario.drivers[preflight.guard.LOGIN]
    sql = str(preflight._IDENTITY)
    row = list(driver.rows[sql][0])
    row[field] = value
    driver.rows[sql] = [tuple(row)]
    assert preflight.run(scenario.packet, **scenario.inputs).code == code
    assert driver.calls == [sql] and driver.cleanup == ["rollback", "close"]
    assert len(scenario.opened) == 1


@pytest.mark.parametrize("index,rows", [
    (2, [((1, 2, 3, 4), OK_ROLES[1], (), (), (3,))]),
    (4, [(False, False, False, True)]),
    (5, [(True,)]),
])
def test_migrator_role_and_privilege_checks(scenario, index, rows):
    driver = scenario.drivers[preflight.guard.LOGIN]
    driver.rows[compile_sql(scenario.sql[index])] = rows
    assert preflight.run(scenario.packet, **scenario.inputs).code == "MIGRATOR_SECURITY_MISMATCH"
    assert driver.cleanup == ["rollback", "close"]


@pytest.mark.parametrize("query,code", [
    ("history_visibility", "INCOMPLETE_VISIBILITY"),
    ("cross_tenant", "INCOMPLETE_VISIBILITY"),
    ("budget", "QUERY_ROW_LIMIT"),
    ("revision", "REVISION_MISMATCH"),
])
def test_real_observer_failures(scenario, query, code):
    driver = scenario.drivers[TARGET.login]
    sql = lambda name: compile_sql(preflight.observer.READ_QUERIES[name].sql)
    if query == "cross_tenant":
        row = list(driver.rows[sql("evidence")][0])
        row[1] = UUID(int=999)
        driver.rows[sql("evidence")] = [tuple(row)]
    elif query == "budget":
        driver.rows[sql("evidence")] *= 1001
    else:
        driver.rows[sql(query)] = [("wrong",)] if query == "revision" else []
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.code == code
    assert len(scenario.docker_calls) == 3
    assert all(d.cleanup == ["rollback", "close"] for d in scenario.opened)


@pytest.mark.parametrize("fault,code", [
    ("query", "PREFLIGHT_FAILED"), ("rollback", "ROLLBACK_FAILED"), ("close", "CLOSE_FAILED"),
])
def test_cleanup_and_redaction(scenario, fault, code):
    driver = scenario.drivers[preflight.guard.LOGIN]
    if fault == "query":
        driver.rows[compile_sql(preflight._BOUNDARY)] = RuntimeError("secret-value")
    else:
        setattr(driver, fault + "_error", True)
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.code == code and "secret-value" not in repr(report)
    assert driver.cleanup == ["rollback", "close"]
    assert report.target_recheck == "MATCH"


@pytest.mark.parametrize("failure_at", [1, 2, 3])
def test_container_drift_at_every_boundary(scenario, monkeypatch, failure_at):
    original = preflight.docker_postgres_identity

    def inspect(**kwargs):
        result = original(**kwargs)
        return frozenset() if len(scenario.docker_calls) == failure_at else result

    monkeypatch.setattr(preflight, "docker_postgres_identity", inspect)
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.code == ("DOCKER_RECHECK_UNVERIFIED" if failure_at == 3 else "DOCKER_IDENTITY_MISMATCH")
    assert report.target_recheck == ("NOT_ATTEMPTED" if failure_at == 1 else "MATCH" if failure_at == 2 else "FAILED")
    assert len(scenario.opened) == failure_at - 1
    assert all(d.closed for d in scenario.opened)


@pytest.mark.parametrize("mismatch", ["container", "image", "endpoint", "multiple", "network_id"])
def test_projected_docker_metadata_is_exact(monkeypatch, mismatch):
    from app.database import test_target

    container, image, network_id = "a" * 64, "sha256:" + "b" * 64, "c" * 64
    networks = {"bridge": {"NetworkID": network_id, "IPAddress": "192.0.2.1", "Gateway": "192.0.2.2"}}
    ports = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]}
    fields = [container, "/ai-soc-postgres", "postgres:16", "running", ports, networks, image]
    if mismatch == "container":
        fields[0] = "d" * 64
    if mismatch == "image":
        fields[-1] = "sha256:" + "d" * 64
    if mismatch == "endpoint":
        ports["5432/tcp"][0]["HostIp"] = "0.0.0.0"
    if mismatch == "multiple":
        networks["second"] = networks["bridge"]
    if mismatch == "network_id":
        networks["bridge"]["NetworkID"] = "d" * 64
    output = "|".join(json.dumps(x) if isinstance(x, dict) else x for x in fields)
    monkeypatch.setattr(test_target.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=output))
    with pytest.raises(ValueError, match="cannot verify"):
        test_target.docker_postgres_identity(container_id=container, local=True,
                                             exact=(image, "bridge", network_id))


def test_unapproved_sql_never_reaches_driver(scenario):
    driver = scenario.drivers[TARGET.login]
    reader = preflight._ReadConnection(driver, scenario.packet.predecessor_queries, 1000, migrator=False)
    for sql in ("SELECT 1", "SELECT 1; SELECT 2", "CALL unsafe()", "SET ROLE postgres", "COPY x TO PROGRAM 'x'"):
        with pytest.raises(preflight._Stop, match="UNAPPROVED_QUERY"):
            reader.execute(preflight.text(sql))
    assert not driver.calls


def test_unapproved_credential_target_and_ambient_settings(scenario, monkeypatch):
    credentials = scenario.inputs["credentials"]
    key = scenario.packet.migrator_secret_ref
    old = credentials[key]
    credentials[key] = old.replace("/ai_soc_test", "/ai_soc")
    assert preflight.run(scenario.packet, **scenario.inputs).code == "CREDENTIAL_TARGET_MISMATCH"
    credentials[key] = old
    monkeypatch.setenv("PGSERVICE", "override")
    assert preflight.run(scenario.packet, **scenario.inputs).code == "AMBIENT_CONFIGURATION"
    assert not scenario.opened and not scenario.docker_calls


def test_server_restart_between_sessions_rejected(scenario):
    driver = scenario.drivers[TARGET.login]
    src = str(preflight._IDENTITY)
    row = driver.rows[src][0]
    changed = (*row[:-2], row[-2] + timedelta(seconds=1), row[-1])
    driver.rows[src] = driver.rows[compile_sql(preflight._IDENTITY)] = [changed]
    assert preflight.run(scenario.packet, **scenario.inputs).code == "INCONSISTENT_OBSERVATIONS"
    assert driver.calls == [src]


def test_final_deadline_check_catches_late_work(scenario, monkeypatch):
    clock = iter([0, 30, 61])
    monkeypatch.setattr(preflight, "monotonic", lambda: next(clock))
    assert preflight.run(scenario.packet, **scenario.inputs).code == "PREFLIGHT_DEADLINE"


def test_ambient_git_is_rejected_before_manifest_process(scenario, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "unapproved")
    monkeypatch.setattr(preflight, "manifest_bytes", lambda _: pytest.fail("unsafe git launch"))
    assert preflight.run(scenario.packet, **scenario.inputs).code == "AMBIENT_CONFIGURATION"
    assert not scenario.opened


def test_credentials_missing_fails_without_disclosure(scenario):
    scenario.inputs["credentials"] = {}
    result = preflight.run(scenario.packet, **scenario.inputs)
    assert result.status == "FAIL" and result.stage == "credentials"
    assert "migrator-ref" not in repr(result)
    assert not scenario.opened and not scenario.docker_calls


def test_unconfirmed_rollback_is_rejected(scenario):
    driver = scenario.drivers[preflight.guard.LOGIN]
    driver.rollback_stalls = True
    assert preflight.run(scenario.packet, **scenario.inputs).code == "ROLLBACK_FAILED"
    assert driver.cleanup == ["rollback", "close"]


def test_driver_query_timeout_is_sanitized(scenario):
    driver = scenario.drivers[preflight.guard.LOGIN]
    driver.rows[compile_sql(preflight._BOUNDARY)] = preflight.psycopg.errors.QueryCanceled("secret-value")
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.code == "QUERY_TIMEOUT" and "secret-value" not in repr(report)
    assert driver.cleanup == ["rollback", "close"]


@pytest.mark.parametrize("field,bad,code", [
    ("ca", b"wrong CA artifact", "TLS_CA_MISMATCH"),
    ("freeze", b"", "FREEZE_EVIDENCE_MISMATCH"),
])
def test_ca_and_freeze_are_bound_before_opening(scenario, field, bad, code):
    scenario.inputs[field] = bad
    assert preflight.run(scenario.packet, **scenario.inputs).code == code
    assert not scenario.opened and not scenario.docker_calls


def test_invalid_approved_ca_is_rejected(scenario, monkeypatch):
    def bad_ca(**_):
        raise preflight.ssl.SSLError("secret-value")
    monkeypatch.setattr(preflight.ssl, "SSLContext", lambda _: SimpleNamespace(load_verify_locations=bad_ca))
    assert preflight.run(scenario.packet, **scenario.inputs).code == "TLS_CA_INVALID"
    assert not scenario.opened


@pytest.mark.parametrize("error", ["certificate expired", "hostname mismatch", "unknown CA", "authentication failure"])
def test_tls_and_authentication_failures_never_retry_and_recheck(scenario, monkeypatch, error):
    calls = []

    def reject(**kwargs):
        calls.append(kwargs["sslmode"])
        raise preflight.psycopg.OperationalError(error + " secret-value")

    monkeypatch.setattr(preflight.psycopg, "connect", reject)
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert calls == ["verify-full"]
    assert report.status == "FAIL" and report.target_recheck == "MATCH"
    assert error not in repr(report) and "secret-value" not in repr(report)
    assert len(scenario.docker_calls) == 2


def test_security_drift_rejected_before_observer_history(scenario):
    driver = scenario.drivers[TARGET.login]
    driver.rows[compile_sql(preflight._SECURITY_STATE)] = [("e" * 64,)]
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.code == "INCONSISTENT_OBSERVATIONS"
    assert compile_sql(preflight.observer.READ_QUERIES["revision"].sql) not in driver.calls


def test_changed_role_bind_is_rejected(scenario):
    driver = scenario.drivers[preflight.guard.LOGIN]
    reader = preflight._ReadConnection(driver, (), 1000, migrator=True)
    with pytest.raises(preflight._Stop, match="UNAPPROVED_QUERY"):
        reader.execute(preflight.text(scenario.sql[1]), {"login": "postgres", "owner": preflight.guard.OWNER})
    assert not driver.calls


def test_cleanup_failure_and_recheck_failure_are_reported_separately(scenario, monkeypatch):
    first = preflight.docker_postgres_identity
    driver = scenario.drivers[preflight.guard.LOGIN]
    driver.rollback_error = True

    def inspect(**kwargs):
        result = first(**kwargs)
        return frozenset() if len(scenario.docker_calls) == 2 else result

    monkeypatch.setattr(preflight, "docker_postgres_identity", inspect)
    report = preflight.run(scenario.packet, **scenario.inputs)
    assert report.code == "ROLLBACK_FAILED" and report.target_recheck == "FAILED"


@pytest.mark.parametrize("fault", ["parent", "child", "missing", "self", "duplicate", "fk"])
def test_complete_lineage_and_fk_catalog(scenario, fault):
    driver = scenario.drivers[TARGET.login]
    sql = lambda name: compile_sql(preflight.observer.READ_QUERIES[name].sql)
    original = driver.rows[sql("evidence")][0]
    identity, tenant = original[:2]
    second_tenant, sibling, foreign = UUID(int=900), UUID(int=901), UUID(int=902)
    driver.rows[sql("tenants")] += ((second_tenant,),)
    driver.rows[sql("evidence")] += ((sibling, tenant, *original[2:]), (foreign, second_tenant, *original[2:]))
    edge = (tenant, identity, sibling, "derived_from", STAMP)
    if fault == "parent":
        edge = (tenant, foreign, *edge[2:])
    elif fault == "child":
        edge = (*edge[:2], foreign, *edge[3:])
    elif fault == "missing":
        edge = (*edge[:2], UUID(int=903), *edge[3:])
    elif fault == "self":
        edge = (*edge[:2], identity, *edge[3:])
    elif fault == "fk":
        rows = driver.rows[sql("lineage_keys")]
        driver.rows[sql("lineage_keys")] = ((rows[0][0], False), rows[1])
    driver.rows[sql("lineage")] = (edge, edge) if fault == "duplicate" else (edge,)
    expected = "PREDECESSOR_CATALOG_MISMATCH" if fault == "fk" else "EVIDENCE_BASELINE_MISMATCH"
    assert preflight.run(scenario.packet, **scenario.inputs).code == expected


def test_public_shadow_schema_in_effective_path_is_rejected(scenario):
    driver = scenario.drivers[preflight.guard.LOGIN]
    sql = str(preflight._IDENTITY)
    row = list(driver.rows[sql][0])
    row[10] = ["pg_catalog", "public"]
    driver.rows[sql] = [tuple(row)]
    assert preflight.run(scenario.packet, **scenario.inputs).code == "TRANSACTION_SETTINGS_MISMATCH"
    assert driver.calls == [sql]


def test_ambient_tls_downgrade_rejected(scenario, monkeypatch):
    monkeypatch.setenv("PGSSLMODE", "disable")
    assert preflight.run(scenario.packet, **scenario.inputs).code == "AMBIENT_CONFIGURATION"
    assert not scenario.opened and not scenario.docker_calls
