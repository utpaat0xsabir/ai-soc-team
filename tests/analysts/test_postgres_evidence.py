"""Stored evidence tests use a fake PostgreSQL connection and no database."""

from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import SQLAlchemyError

from app.analysts.evidence_adapter import EvidenceRejected, StoredEvidenceAdapter
from app.analysts.orchestration import orchestrate_l1
from app.analysts.postgres_evidence import PostgresEvidenceRepository
from app.evidence.hashing import calculate_evidence_hash
from tests.analysts.test_analyst_contracts import NOW
from tests.analysts.test_analyst_inference import setup


TENANT, EVIDENCE = UUID(int=1), UUID(int=3)


def row(**changes):
    data = dict(
        evidence_id=EVIDENCE, tenant_id=TENANT, evidence_type="observation",
        source_type="wazuh", source_reference="alert:42", collector_name="test",
        collector_version="1.0", trust_level="unverified", schema_version="1.0",
        event_time=datetime(2026, 11, 11, tzinfo=timezone.utc),
        collected_at=NOW, payload={"text": "evidence canary"},
    )
    data.update(changes)
    data["content_sha256"] = calculate_evidence_hash(**{key: data[key] for key in (
        "evidence_type", "source_type", "source_reference", "collector_name",
        "collector_version", "trust_level", "event_time", "payload",
    )})
    return data


class Session:
    def __init__(self, rows=(), *, username="reader", allowed=True):
        self.rows = rows
        self.username = username
        self.allowed = allowed
        self.statements = []
        self.connections = 0

    def get_bind(self):
        return SimpleNamespace(
            dialect=postgresql.dialect(), engine=SimpleNamespace(
                url=SimpleNamespace(username=self.username),
            ),
        )

    def connection(self, *, bind_arguments):
        assert bind_arguments["bind"].engine.url.username == self.username
        self.connections += 1
        return self

    def execute(self, statement, parameters=None, *, execution_options=None):
        self.statements.append((statement, parameters))
        if len(self.statements) == 1:
            return SimpleNamespace(scalar_one=lambda: self.allowed)
        self.read_options = execution_options
        if isinstance(self.rows, Exception):
            raise self.rows
        return SimpleNamespace(mappings=lambda: SimpleNamespace(fetchmany=lambda n: self.rows[:n]))


def test_parameterized_tenant_scoped_bounded_read():
    other = UUID(int=2)
    session = Session((row(), row(evidence_id=other, event_time=None)))
    bundle = PostgresEvidenceRepository(session).load_stored_bundle(TENANT, (EVIDENCE, other))
    assert tuple(item.evidence_id for item in bundle) == (other, EVIDENCE)
    assert bundle[0].event_time is None
    assert bundle[1].content_sha256 == row()["content_sha256"]
    assert bundle[1].source_reference == "alert:42"
    assert bundle[1].trust_level == "unverified"
    assert not hasattr(bundle[1], "classification")
    role, role_params = session.statements[0]
    assert "session_user = current_user" in str(role)
    assert "rolsuper" in str(role)
    assert role_params == {"login": "reader"}
    statement = session.statements[1][0]
    schemas = session.read_options["schema_translate_map"]
    compiled = statement.compile(dialect=postgresql.dialect(), schema_translate_map=schemas,
                                 render_schema_translate=True)
    assert "WHERE public.evidence_records.tenant_id = %(" in str(compiled)
    assert "public.evidence_records.id IN" in str(compiled)
    assert "ORDER BY public.evidence_records.id" in str(compiled)
    assert "pg_catalog.octet_length" in str(compiled)
    assert "LIMIT" in str(compiled)
    assert TENANT in compiled.params.values()
    assert [other, EVIDENCE] in compiled.params.values()
    assert 2 in compiled.params.values()


@pytest.mark.parametrize("rows", [(), (row(tenant_id=UUID(int=9)),), (row(evidence_id=UUID(int=9)),)])
def test_missing_or_wrong_scope_rejected_identically(rows):
    with pytest.raises(EvidenceRejected, match="EVIDENCE_NOT_FOUND"):
        PostgresEvidenceRepository(Session(rows)).load_stored_bundle(TENANT, (EVIDENCE,))


@pytest.mark.parametrize(("change", "reason"), [
    ({"content_sha256": "0" * 64}, "HASH_MISMATCH"),
    ({"content_sha256": "not a hash"}, "INVALID_EVIDENCE"),
    ({"payload": ["evidence canary"]}, "INVALID_EVIDENCE"),
    ({"payload": {"secret canary": float("inf")}}, "INVALID_EVIDENCE"),
    ({"payload": None}, "INVALID_EVIDENCE"),
    ({"source_reference": " "}, "INVALID_EVIDENCE"),
    ({"collector_name": None}, "INVALID_EVIDENCE"),
    ({"collector_version": ""}, "INVALID_EVIDENCE"),
    ({"schema_version": "2.0"}, "INVALID_EVIDENCE"),
    ({"evidence_type": "action"}, "INVALID_EVIDENCE"),
    ({"source_type": "unknown"}, "UNSUPPORTED_SOURCE"),
    ({"trust_level": "elevated"}, "UNSUPPORTED_TRUST_LEVEL"),
    ({"collected_at": NOW.replace(tzinfo=None)}, "INVALID_EVIDENCE"),
    ({"event_time": NOW.replace(tzinfo=None)}, "INVALID_EVIDENCE"),
])
def test_invalid_stored_metadata_is_sanitized(change, reason):
    record = row()
    record.update(change)
    with pytest.raises(EvidenceRejected) as error:
        PostgresEvidenceRepository(Session((record,))).load_stored_bundle(TENANT, (EVIDENCE,))
    assert error.value.reason == reason
    assert str(error.value) == reason


@pytest.mark.parametrize("ids", [(), (EVIDENCE, EVIDENCE), (str(EVIDENCE),),
                                 (UUID(int=0),), tuple(UUID(int=i) for i in range(1, 34))])
def test_invalid_ids_do_not_open_connection(ids):
    session = Session()
    with pytest.raises(EvidenceRejected, match="INVALID_EVIDENCE_IDS"):
        PostgresEvidenceRepository(session).load_stored_bundle(TENANT, ids)
    assert not session.connections


@pytest.mark.parametrize(("username", "allowed", "reads"), [
    ("ai_soc", True, 0), ("postgres", True, 0), (None, True, 0), ("reader", False, 1),
])
def test_privileged_or_unverified_connection_cannot_read_evidence(username, allowed, reads):
    session = Session((row(),), username=username, allowed=allowed)
    with pytest.raises(EvidenceRejected, match="UNSAFE_EVIDENCE_SESSION"):
        PostgresEvidenceRepository(session).load_stored_bundle(TENANT, (EVIDENCE,))
    assert len(session.statements) == reads
    assert session.connections == reads


def test_query_failure_does_not_disclose_driver_details():
    session = Session(SQLAlchemyError("sensitive driver message"))
    with pytest.raises(EvidenceRejected) as error:
        PostgresEvidenceRepository(session).load_stored_bundle(TENANT, (EVIDENCE,))
    assert str(error.value) == "EVIDENCE_LOOKUP_FAILED"


@pytest.mark.parametrize("level", ["unverified", "source_verified", "system_verified"])
def test_valid_stored_rows_never_enter_l1(level, monkeypatch):
    args = setup("L1")
    session = Session((row(trust_level=level),))
    source = StoredEvidenceAdapter(PostgresEvidenceRepository(session))
    assert source.load_stored_bundle(args["context"], (EVIDENCE,))[0].trust_level == level
    session.statements.clear()

    def forbidden_snapshot(*args, **kwargs):
        pytest.fail("stored evidence reached snapshot construction")

    monkeypatch.setattr("app.analysts.contracts.build_snapshot", forbidden_snapshot)
    result = orchestrate_l1(
        args["context"], args["task"], source, args["configuration"], args["provider"],
        args["admission"], args["control"], captured_at=NOW, at=NOW,
    )
    assert len(session.statements) == 2
    assert result.status == "DENIED"
    assert result.reason == "INVALID_INPUT"
    assert args["provider"].calls == 0


def test_task_scope_is_checked_before_requesting_stored_rows():
    args = setup("L1")
    session = Session((row(),))
    task = args["task"].model_copy(update={"principal_id": UUID(int=99)})
    result = orchestrate_l1(
        args["context"], task, StoredEvidenceAdapter(PostgresEvidenceRepository(session)),
        args["configuration"], args["provider"], args["admission"], args["control"],
        captured_at=NOW, at=NOW,
    )
    assert result.status == "DENIED"
    assert not session.connections
    assert args["provider"].calls == 0


def test_bundle_limit_and_detachment():
    record = row(payload={"text": "x" * 7000})
    session = Session((record,))
    item = PostgresEvidenceRepository(session).load_stored_bundle(TENANT, (EVIDENCE,))[0]
    original = deepcopy(item)
    record["payload"]["text"] = "changed"
    assert item == original
    rows = tuple(row(evidence_id=UUID(int=i), payload={"text": "x" * 7500}) for i in range(1, 11))
    with pytest.raises(EvidenceRejected, match="EVIDENCE_BUNDLE_TOO_LARGE"):
        PostgresEvidenceRepository(Session(rows)).load_stored_bundle(
            TENANT, tuple(item["evidence_id"] for item in rows),
        )


def test_repository_schema_wins_over_connection_schema_mapping():
    from sqlalchemy import create_engine, event

    engine = create_engine("sqlite://")
    dispatched = []

    def stop_before_driver(connection, cursor, sql, *args):
        dispatched.append(sql)
        raise SQLAlchemyError("offline SQL interception")

    try:
        with engine.connect() as connection:
            connection.execution_options(schema_translate_map={None: "other_schema"})
            event.listen(connection, "before_cursor_execute", stop_before_driver)

            class SessionWithMappedConnection(Session):
                def execute(self, statement, parameters=None, *, execution_options=None):
                    if not self.statements:
                        return super().execute(statement, parameters)
                    return connection.execute(statement, execution_options=execution_options)

            with pytest.raises(EvidenceRejected, match="EVIDENCE_LOOKUP_FAILED"):
                PostgresEvidenceRepository(SessionWithMappedConnection()).load_stored_bundle(
                    TENANT, (EVIDENCE,),
                )
    finally:
        engine.dispose()
    assert len(dispatched) == 1
    assert "FROM public.evidence_records" in dispatched[0]
    assert "other_schema" not in dispatched[0]
