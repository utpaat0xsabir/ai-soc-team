"""Synthetic driver transcripts for the restricted B4 adapter."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from sqlalchemy.exc import OperationalError, TimeoutError

from app.audit.integrity import GENESIS_HASH, calculate_audit_hash
from app.database import source_registry_observer_adapter as adapter
from app.database.source_registry_artifact import FILES, REPORT, manifest_bytes
from app.evidence.hashing import calculate_evidence_hash
from tests.database.test_source_registry_observer import OWNER, TARGET, TENANT, snapshots


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
BEFORE = STAMP + timedelta(hours=1)
AFTER = BEFORE + timedelta(minutes=1)
NOW = AFTER + timedelta(seconds=5)
MANIFEST = b"synthetic approved manifest"
CONTAINER = adapter.ContainerEvidence(TARGET)
OK_ROLES = ((1, 2, 3, 4), (OWNER, adapter.guard.LOGIN, "postgres", TARGET.login),
            ((2, 1, 3),), ((False, False, True),), (3,))
RELATIONS = ("tenants", "evidence_records", "evidence_lineage", "audit_logs")


class Result:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.closed = False

    def fetchmany(self, size):
        # Deliberately return short batches to require a complete drain.
        row = next(self.rows, None)
        return [] if row is None else [row]

    def close(self):
        self.closed = True


class Connection:
    closed = False
    invalidated = False
    dialect = SimpleNamespace(name="postgresql", driver="psycopg")

    def __init__(self, rows):
        self.rows = rows
        self.calls = []
        self.results = []
        self.transaction = SimpleNamespace(is_active=True)
        self.connection = SimpleNamespace(driver_connection=SimpleNamespace(autocommit=False))

    def get_transaction(self):
        return self.transaction

    def get_nested_transaction(self):
        return None

    def execute(self, sql, params):
        name = next(name for name, query in adapter.READ_QUERIES.items()
                    if query.sql == str(sql) and params == {
                        key: list(value) if type(value) is tuple else value for key, value in query.binds
                    })
        self.calls.append(name)
        rows = self.rows[name]
        if isinstance(rows, Exception):
            raise rows
        if callable(rows):
            rows = rows()
        result = Result(rows)
        self.results.append(result)
        return result


def transcript(observation, *, start):
    identity = observation.identity
    evidence = dict(evidence_type="observation", source_type="wazuh", source_reference="fixture",
                    collector_name="fixture", collector_version="1", trust_level="unverified",
                    payload={"example": "not in reports"}, event_time=STAMP)
    event = dict(tenant_id=TENANT.tenant_id, sequence_number=1, previous_hash=GENESIS_HASH,
                 actor_type="system", actor_id=None, action="fixture", resource_type="evidence",
                 resource_id=None, details={}, created_at=STAMP)
    return dict(
        observation.catalog.results,
        identity=((identity.database, identity.version_num, identity.session_user, identity.current_user,
                   identity.server, identity.client, identity.port, True, True, True, True, False, OWNER, True),),
        snapshot=((11, 20, start, STAMP, "12:15:13", 5000),),
        privileges=(((True, False, False, False, False, False, False), True, True, True, False, OWNER),),
        roles=(OK_ROLES,),
        revision_relation=((True,),),
        revision=((observation.revisions[0],),),
        history_relations=tuple((name, True) for name in RELATIONS),
        history_visibility=tuple((name, True, True) for name in RELATIONS),
        tenants=((TENANT.tenant_id,),),
        evidence=((TENANT.evidence[0].evidence_id, TENANT.tenant_id, *evidence.values(),
                   calculate_evidence_hash(**evidence), STAMP, STAMP, "1.0"),),
        lineage=(),
        audit=((TENANT.evidence[0].evidence_id, TENANT.tenant_id, 1, GENESIS_HASH, calculate_audit_hash(**event),
                "system", None, "fixture", "evidence", None, {}, STAMP),),
    )


@pytest.fixture
def workflow(monkeypatch, snapshots):
    before, after, reference = snapshots
    monkeypatch.setattr(adapter, "manifest_bytes", lambda _: MANIFEST)
    approval = adapter.Approval(TARGET, sha256(MANIFEST).hexdigest(), "1" * 64, 5000, 1000,
                                adapter.expression_reference_sha256(reference))
    return SimpleNamespace(before=transcript(before, start=BEFORE), after=transcript(after, start=AFTER),
                           approval=approval, reference=reference)


def collect(workflow, successor=False, *, connection=None, container=CONTAINER):
    if connection is None:
        connection = Connection(workflow.after if successor else workflow.before)
    return adapter.capture(connection, root=Path("."), approval=workflow.approval,
                           container=container, successor=successor)


def receipt(value):
    return adapter.EmptinessAttestation("ai_soc_test", TARGET.container_id, (*map(str, TARGET.address_pair), 5432),
                                       adapter.plan.STAGED_REVISION, value.snapshot, "approved-reviewer", AFTER,
                                       adapter._SCOPE, tuple((table, 0) for table in adapter._TABLES),
                                       value.evidence_sha256, "approved-freshness")


def accepted_digest(value):
    return adapter.AttestationApproval(adapter.attestation_sha256(value), value.attestor,
                                       value.policy_id, timedelta(seconds=5))


def finish(workflow, before, after, value=None, approval=None, *, reference=True):
    return adapter.accept_successor(
        before, after, reference=workflow.reference if reference else None,
        attestation=value, attestation_approval=approval, now=NOW,
    )


def test_complete_workflow_uses_only_injected_transaction(workflow):
    connection = Connection(workflow.before)
    before = collect(workflow, connection=connection)
    after = collect(workflow, True)
    assert isinstance(adapter.accept_predecessor(before), adapter.Accepted)
    assert after.observation.authority.registry_empty is None
    value = receipt(after)
    result = finish(workflow, before, after, value, accepted_digest(value))
    assert isinstance(result, adapter.Accepted)
    assert result.attestation_sha256 == adapter.attestation_sha256(value)
    assert connection.transaction.is_active and all(result.closed for result in connection.results)
    assert connection.calls[:4] == ["identity", "snapshot", "privileges", "roles"]
    assert "not in reports" not in repr(result)


@pytest.mark.parametrize(("field", "value"), [
    ("closed", True), ("invalidated", True), ("transaction", None),
    ("connection", SimpleNamespace(driver_connection=SimpleNamespace(autocommit=True))),
])
def test_requires_existing_live_transaction(workflow, field, value):
    connection = Connection(workflow.before)
    setattr(connection, field, value)
    assert collect(workflow, connection=connection).code == "CONNECTION_NOT_INDEPENDENTLY_AUTHENTICATED"
    assert not connection.calls


@pytest.mark.parametrize(("index", "value", "code"), [
    (0, "ai_soc", "WRONG_DATABASE"), (1, 170000, "WRONG_POSTGRES_VERSION"),
    (2, "other", "WRONG_OBSERVER_LOGIN"), (3, OWNER, "WRONG_OBSERVER_LOGIN"),
    (4, "192.0.2.9", "WRONG_SERVER"), (5, "192.0.2.9", "WRONG_SERVER"),
    (7, False, "TRANSACTION_NOT_READ_ONLY"), (8, False, "INCONSISTENT_SNAPSHOT"),
    (9, False, "PRIVILEGED_OBSERVER"), (10, False, "PRIVILEGED_OBSERVER"),
    (11, True, "PRIVILEGED_OBSERVER"),
])
def test_rejects_identity_before_history(workflow, index, value, code):
    row = list(workflow.before["identity"][0])
    row[index] = value
    workflow.before["identity"] = (row,)
    connection = Connection(workflow.before)
    assert collect(workflow, connection=connection).code == code
    assert connection.calls == ["identity"]


@pytest.mark.parametrize("edges", [
    (((4, 1, 3), (False, False, True)),),
    (((4, 3, 3), (False, False, True)), ((3, 1, 3), (False, False, True))),
    (((4, 1, 3), (True, False, False)),),
    (((4, 2, 3), (False, False, True)),),
])
def test_rejects_direct_transitive_and_admin_paths(workflow, edges):
    oids, names, grants, options, unrestricted = OK_ROLES
    workflow.before["roles"] = ((oids, names, (*grants, *(edge[0] for edge in edges)),
                                (*options, *(edge[1] for edge in edges)), unrestricted),)
    assert collect(workflow).code == "ROLE_REACHABILITY_UNVERIFIED"


def test_requires_independent_container_evidence(workflow, monkeypatch):
    assert collect(workflow, container=None).code == "MISSING_CONTAINER_PIN"
    other = adapter.ContainerEvidence(replace(TARGET, container_id="f" * 64))
    assert collect(workflow, container=other).code == "WRONG_CONTAINER"
    expected = frozenset({TARGET.address_pair})
    monkeypatch.setattr(adapter, "docker_postgres_identity", lambda **kwargs: expected)
    assert adapter.verify_container(TARGET) == CONTAINER


@pytest.mark.parametrize("sql", [
    "SELECT 1; SELECT 2", "CREATE TABLE t(id int)", "UPDATE t SET id = 1",
    "SET ROLE postgres", "COMMIT", "SELECT pg_catalog.pg_advisory_lock(1)",
    "SELECT nextval('seq')", "SELECT public.unapproved()",
])
def test_sql_inventory_drift_is_denied_before_driver(workflow, monkeypatch, sql):
    queries = dict(adapter.READ_QUERIES)
    queries["identity"] = replace(queries["identity"], sql=sql)
    monkeypatch.setattr(adapter, "READ_QUERIES", MappingProxyType(queries))
    connection = Connection(workflow.before)
    assert collect(workflow, connection=connection).code == "UNAPPROVED_QUERY"
    assert not connection.calls


def test_unknown_or_out_of_phase_query_cannot_reach_driver():
    connection = Connection({})
    for name in ("SELECT 1", "checks:source_registry.source_scopes"):
        with pytest.raises(adapter._Rejected, match="UNAPPROVED_QUERY"):
            adapter._read(connection, name, successor=False, max_rows=2)
    assert not connection.calls


@pytest.mark.parametrize(("query", "value", "code"), [
    ("identity", (), "QUERY_RESULT_SHAPE_MISMATCH"),
    ("identity", (("wrong width",),), "QUERY_RESULT_SHAPE_MISMATCH"),
    ("identity", TimeoutError("secret"), "QUERY_TIMEOUT"),
    ("identity", OperationalError("secret", {}, OSError("secret")), "QUERY_FAILED"),
    ("identity", OperationalError("secret", {}, type("Denied", (Exception,), {"sqlstate": "42501"})()),
     "INCOMPLETE_VISIBILITY"),
    ("identity", OperationalError("secret", {}, type("Canceled", (Exception,), {"sqlstate": "57014"})()),
     "QUERY_TIMEOUT"),
    ("revision_relation", ((False,),), "INCOMPLETE_VISIBILITY"),
    ("revision", (), "REVISION_MISMATCH"),
    ("revision", (("unknown",),), "REVISION_MISMATCH"),
    ("revision", (("one",), ("two",)), "MULTIPLE_REVISIONS"),
    ("history_visibility", (("audit_logs", False, True),), "INCOMPLETE_VISIBILITY"),
    ("history_relations", (("audit_logs", False),), "INCOMPLETE_VISIBILITY"),
    ("snapshot", ((11, 20, BEFORE, STAMP, "12:15:13", 0),), "UNAPPROVED_QUERY_TIMEOUT"),
])
def test_failure_classification(workflow, query, value, code):
    workflow.before[query] = value
    failure = collect(workflow)
    assert failure == adapter.Rejection(code)
    assert "secret" not in repr(failure)


def test_snapshot_and_artifact_change_fail_closed(workflow):
    initial = workflow.before["snapshot"]
    drift = ((*initial[0][:4], "99:100:", 5000),)
    reads = iter((initial, drift))
    workflow.before["snapshot"] = lambda: next(reads)
    assert collect(workflow).code == "INCONSISTENT_SNAPSHOT"
    workflow.approval = replace(workflow.approval, manifest_sha256="b" * 64)
    assert collect(workflow).code == "ARTIFACT_MISMATCH"


@pytest.mark.parametrize(("field", "value", "code"), [
    ("database", "ai_soc", "EMPTINESS_ATTESTATION_MISMATCH"),
    ("container_id", "e" * 64, "EMPTINESS_ATTESTATION_MISMATCH"),
    ("revision", adapter.plan.EXPECTED_PREDECESSOR, "EMPTINESS_ATTESTATION_MISMATCH"),
    ("endpoint", ("192.0.2.9", "192.0.2.2", 5432), "EMPTINESS_ATTESTATION_MISMATCH"),
    ("evidence_sha256", "e" * 64, "EMPTINESS_ATTESTATION_MISMATCH"),
    ("scope", "filtered_rows_only", "EMPTINESS_ATTESTATION_MISMATCH"),
    ("generated_at", NOW + timedelta(seconds=1), "EMPTINESS_ATTESTATION_FRESHNESS_UNVERIFIED"),
    ("attestor", TARGET.login, "UNAPPROVED_EMPTINESS_ATTESTATION"),
])
def test_attestation_exact_binding(workflow, field, value, code):
    before, after = collect(workflow), collect(workflow, True)
    altered = replace(receipt(after), **{field: value})
    assert finish(workflow, before, after, altered, accepted_digest(altered)).code == code


def test_independent_attestation_never_inferred_from_catalog(workflow):
    before, after = collect(workflow), collect(workflow, True)
    value = receipt(after)
    approval = accepted_digest(value)
    assert finish(workflow, before, after).code == "MISSING_EMPTINESS_ATTESTATION"
    assert finish(workflow, before, after, value, approval, reference=False).code == "INCOMPLETE_VISIBILITY"
    assert finish(workflow, before, after, value, replace(approval, sha256="f" * 64)).code == (
        "UNAPPROVED_EMPTINESS_ATTESTATION"
    )
    assert finish(workflow, before, after, value, replace(approval, max_age=timedelta(seconds=1))).code == (
        "EMPTINESS_ATTESTATION_FRESHNESS_UNVERIFIED"
    )
    assert finish(workflow, before, after, value, replace(approval, max_age=None)).code == (
        "EMPTINESS_ATTESTATION_FRESHNESS_UNVERIFIED"
    )
    for bad in (replace(value, snapshot=before.snapshot), replace(value, table_counts=value.table_counts[:-1])):
        assert finish(workflow, before, after, bad, accepted_digest(bad)).code == "EMPTINESS_ATTESTATION_MISMATCH"
    nonempty = replace(value, table_counts=((value.table_counts[0][0], 1), *value.table_counts[1:]))
    assert finish(workflow, before, after, nonempty, accepted_digest(nonempty)).code == "AUTHORITY_PRESENT"
    assert not any("SELECT" in query.sql.upper() and "FROM SOURCE_REGISTRY." in query.sql.upper()
                   for query in adapter.READ_QUERIES.values())


@pytest.mark.parametrize(("query", "alter", "code"), [
    ("tables", lambda rows: rows[:-1], "SUCCESSOR_CATALOG_MISMATCH"),
    ("indexes", lambda rows: ((*rows[0][:3], False, *rows[0][4:]), *rows[1:]), "SUCCESSOR_CATALOG_MISMATCH"),
    ("checks:source_registry.source_scopes", lambda rows: (("true",), *rows[1:]), "SUCCESSOR_CATALOG_MISMATCH"),
    ("tables", lambda rows: ((*rows[0][:3], False, *rows[0][4:]), *rows[1:]), "RLS_NOT_FORCED"),
    ("registry", lambda rows: ((OWNER, 1, 0, True, True),), "ACCEPTING_POLICY_PRESENT"),
    ("triggers", lambda rows: (rows[0], (*rows[1][:3], "D", *rows[1][4:]), *rows[2:]), "DENY_TRIGGER_MISSING"),
    ("triggers", lambda rows: rows[1:], "RESERVED_AUDIT_FENCE_MISSING"),
    ("tables", lambda rows: ((*rows[0][:-1], False), *rows[1:]), "UNEXPECTED_RUNTIME_GRANT"),
    ("routines", lambda rows: ((*rows[0][:3], True, *rows[0][4:]),), "UNEXPECTED_AUTHORITY_ROUTINE"),
    ("evidence", lambda rows: ((*rows[0][:10], "f" * 64, *rows[0][11:]),), "EVIDENCE_BASELINE_MISMATCH"),
    ("lineage", lambda rows: ((TENANT.tenant_id, TENANT.evidence[0].evidence_id,
                               TENANT.tenant_id, "derived_from", STAMP),), "EVIDENCE_BASELINE_MISMATCH"),
    ("audit", lambda rows: ((*rows[0][:2], 2, *rows[0][3:]),), "AUDIT_BASELINE_MISMATCH"),
    ("audit", lambda rows: ((*rows[0][:4], "f" * 64, *rows[0][5:]),), "AUDIT_BASELINE_MISMATCH"),
    ("audit", lambda rows: (), "AUDIT_BASELINE_MISMATCH"),
])
def test_catalog_and_history_use_existing_fail_closed_validators(workflow, query, alter, code):
    before = collect(workflow)
    workflow.after[query] = alter(workflow.after[query])
    after = collect(workflow, True)
    if query == "lineage":
        assert after == adapter.Rejection(code)
        return
    value = receipt(after)
    assert finish(workflow, before, after, value, accepted_digest(value)).code == code


def test_missing_tenant_and_application_isolation(workflow):
    before = collect(workflow)
    for query in ("tenants", "evidence", "audit"):
        workflow.after[query] = ()
    after = collect(workflow, True)
    value = receipt(after)
    assert finish(workflow, before, after, value, accepted_digest(value)).code == "EVIDENCE_BASELINE_MISMATCH"
    workflow.approval = replace(workflow.approval, application_isolation_sha256="")
    assert collect(workflow, True).code == "AUTHORITY_STATE_UNKNOWN"


def test_e2_and_b4_revision_requirements_stay_separate(workflow):
    before = collect(workflow)
    assert before.observation.revisions == (adapter.guard.BASELINE,)
    workflow.after["revision"] = ((adapter.guard.BASELINE,),)
    assert collect(workflow, True).code == "REVISION_MISMATCH"
    workflow.before["revision"] = ((adapter.plan.STAGED_REVISION,),)
    assert collect(workflow).code == "REVISION_MISMATCH"


def test_manifest_reproduces_reviewed_artifact():
    root = Path(__file__).resolve().parents[2]
    assert manifest_bytes(root) == (root / REPORT).read_bytes()
    assert len(FILES) == len(set(FILES))
    assert all(".env" not in name and REPORT != name for name in FILES)


def test_observer_import_never_creates_engine_or_connects(monkeypatch):
    import importlib.util
    import sys

    import psycopg
    import sqlalchemy

    def denied(*args, **kwargs):
        pytest.fail("unexpected import-time connection or engine")
    monkeypatch.setattr(sqlalchemy, "create_engine", denied)
    monkeypatch.setattr(psycopg, "connect", denied)
    spec = importlib.util.spec_from_file_location("b4_observer_import_probe", adapter.__file__)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    assert module.QUERY_INVENTORY_SHA256 == adapter.QUERY_INVENTORY_SHA256


def test_transaction_replacement_stops_capture(workflow):
    connection = Connection(workflow.before)
    identity_rows = workflow.before["identity"]

    def replaced():
        connection.transaction = SimpleNamespace(is_active=True)
        return identity_rows

    workflow.before["identity"] = replaced
    assert collect(workflow, connection=connection).code == "INCONSISTENT_SNAPSHOT"
    assert connection.calls == ["identity"]


@pytest.mark.parametrize("index,value", [(1, False), (2, False), (3, False), (4, True)])
def test_effective_grants_are_required_and_callable_routines_are_rejected(workflow, index, value):
    row = list(workflow.before["privileges"][0])
    row[index] = value
    workflow.before["privileges"] = (row,)
    assert collect(workflow).code == "PRIVILEGED_OBSERVER"


def test_recipe_detects_allowlisted_untracked_artifact_drift(monkeypatch):
    from app.database import source_registry_artifact as artifact

    root = Path(__file__).resolve().parents[2]
    original = artifact._read

    def changed(path, name):
        data = original(path, name)
        return data + b"\n" if name == "scripts/run_guarded_migration.py" else data

    expected = sha256(manifest_bytes(root)).hexdigest()
    monkeypatch.setattr(artifact, "_read", changed)
    assert sha256(manifest_bytes(root)).hexdigest() != expected
