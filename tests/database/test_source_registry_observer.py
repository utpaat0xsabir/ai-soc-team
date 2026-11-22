"""Synthetic B4 snapshots. No driver, Docker, or external service is required."""
from dataclasses import replace
from ipaddress import IPv4Address
from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, PrimaryKeyConstraint
from sqlalchemy.dialects import postgresql

from app.database import source_registry_observer as observer
from app.database import source_registry_migration_plan as plan
from tests.database import test_postgres_evidence_integration as e2


OWNER = "ai_soc_test_owner"
TARGET = observer.Target("a" * 64, (IPv4Address("192.0.2.1"), IPv4Address("192.0.2.2")), "b4_observer")
IDENTITY = observer.Identity("ai_soc_test", 160006, TARGET.login, TARGET.login, *TARGET.address_pair, 5432,
                             True, True, True, True, False, OWNER, True, TARGET.container_id)
VISIBILITY = observer.Visibility(True, True, True, True)
AUTHORITY = observer.Authority(True, True, True)
TENANT = observer.TenantBaseline(
    UUID(int=1), 1, (observer.EvidenceDigest(UUID(int=2), "a" * 64, "a" * 64),),
    "b" * 64, 1, "c" * 64, 1, ((1, "d" * 64),), "e" * 64, "d" * 64, True,
)
AUDIT = ("audit_logs_append_only", "O", 58, True, True)
RESERVED = ("public", "audit_logs", "source_registry_reserved_audit_disabled", "A", 7, True,
            "CREATE TRIGGER source_registry_reserved_audit_disabled BEFORE INSERT ON public.audit_logs "
            "FOR EACH ROW WHEN (starts_with((new.action)::text, 'source_authority.'::text)) "
            "EXECUTE FUNCTION source_registry.deny_staged_write()", True)


def catalog(rows):
    def plain(value):
        if isinstance(value, str):
            return str(value)
        return tuple(map(plain, value)) if isinstance(value, tuple) else value

    return observer.Catalog(plain(tuple(rows.items())))


def make_observation(successor, rows):
    revision = plan.STAGED_REVISION if successor else plan.EXPECTED_PREDECESSOR
    observations = catalog(rows)
    baseline = observer.Baseline(revision, observer.catalog_sha256(observations, successor=successor), (TENANT,))
    return observer.Observation(IDENTITY, VISIBILITY, (revision,), observations, baseline, AUTHORITY)


@pytest.fixture
def snapshots():
    before_rows = {
        "namespace": (),
        "shadow_routines": (),
        "public_owners": tuple((name, OWNER) for name in (*observer.guard.APPLICATION_TABLES, "alembic_version")),
        "keys": (("tenants", ("id",)), ("wazuh_integrations", ("tenant_id", "id")),
                 ("evidence_records", ("tenant_id", "id")), ("audit_logs", ("tenant_id", "sequence_number"))),
        "lineage_keys": (("fk_lineage_parent_same_tenant", True), ("fk_lineage_child_same_tenant", True)),
        "audit_routine": ((OWNER, "plpgsql", False, None,
                           " BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; ", True),),
        "audit_triggers": (AUDIT,),
        "audit_mutators": (),
        "reserved_history": ((True,),),
    }
    after_rows = dict(
        before_rows, namespace=(("source_registry", OWNER),),
        registry=((OWNER, 0, 0, True, True),), defaults=((True,),),
        audit_triggers=(AUDIT, ("source_registry_reserved_audit_disabled", "A", 7, False, False)),
        tables=tuple((table.name, OWNER, True, True, True, True) for table in plan.TABLES),
        routines=(("deny_staged_write", 0, OWNER, False, ("search_path=pg_catalog, pg_temp",),
                   plan._DENY_WRITES.split("$source_registry$")[1], True, True),),
        triggers=(RESERVED, *((t.schema, t.name, "source_registry_disabled", "A", 62, False, "", True)
                              for t in plan.TABLES)),
    )
    constraints, indexes, backing = [], [], []
    expressions = {}
    for table in plan.TABLES:
        expressions[f"columns:{table.fullname}"] = tuple(
            (column.name, str(column.type), not column.nullable, "s" if column.computed else "", "",
             None, None, str(column.computed.sqltext) if column.computed else None)
            for column in table.columns
        )
        expressions[f"checks:{table.fullname}"] = tuple(
            (str(key.sqltext),) for key in table.constraints if isinstance(key, CheckConstraint)
        )
        for key in table.constraints:
            fields = tuple(key.columns.keys())
            if isinstance(key, ForeignKeyConstraint):
                constraints.append((table.name, "f", True, fields, key.referred_table.schema,
                                    key.referred_table.name, tuple(e.column.name for e in key.elements),
                                    "r", "a", "s", True))
            elif not isinstance(key, CheckConstraint):
                kind = "p" if isinstance(key, PrimaryKeyConstraint) else "u"
                constraints.append((table.name, kind, True, fields, None, None, None, None, None, None, None))
                backing.append((table.name, kind, fields, True))
        for index in table.indexes:
            def sql(expr):
                return str(expr.compile(dialect=postgresql.dialect(), compile_kwargs={"include_table": False}))
            parts = tuple(map(sql, index.expressions))
            predicate = index.dialect_options["postgresql"]["where"]
            indexes.append((index.name, table.name, index.unique, True,
                            tuple(p.removesuffix(" DESC") for p in parts),
                            " ".join("3" if p.endswith(" DESC") else "0" for p in parts),
                            sql(predicate) if predicate is not None else None, "btree", True))
    # Each CHECK has a distinct expression observation. The shared constraint
    # query currently returns identical structural tuples for CHECKs.
    for table in plan.TABLES:
        constraints += [(table.name, "c", True, None, None, None, None, None, None, None, None)] * len(
            expressions[f"checks:{table.fullname}"]
        )
    after_rows.update(expressions, constraints=tuple(constraints), indexes=tuple(indexes), backing_indexes=tuple(backing))
    return (make_observation(False, before_rows), make_observation(True, after_rows),
            observer.ExpressionReference(IDENTITY.version_num, observer.DDL_SHA256, catalog(expressions)))


def test_exact_predecessor_and_successor(snapshots):
    before, after, reference = snapshots
    assert observer.validate_predecessor(TARGET, before) is None
    assert observer.validate_successor(TARGET, before, after, reference) is None
    assert observer.validate_predecessor(TARGET, after) is observer.Failure.REVISION_MISMATCH


@pytest.mark.parametrize(("field", "value", "failure"), [
    ("database", "ai_soc", "WRONG_DATABASE"),
    ("database_owner", "postgres", "WRONG_DATABASE"),
    ("version_num", 150006, "WRONG_POSTGRES_VERSION"),
    ("container_id", "b" * 64, "WRONG_CONTAINER"),
    ("server", IPv4Address("192.0.2.9"), "WRONG_SERVER"),
    ("client", IPv4Address("192.0.2.9"), "WRONG_SERVER"),
    ("port", 5433, "WRONG_SERVER"),
    ("session_user", "other", "WRONG_OBSERVER_LOGIN"),
    ("current_user", OWNER, "WRONG_OBSERVER_LOGIN"),
    ("restricted_attributes", False, "PRIVILEGED_OBSERVER"),
    ("excess_privileges", True, "PRIVILEGED_OBSERVER"),
    ("membership_free", False, "PRIVILEGED_OBSERVER"),
    ("membership_free", None, "ROLE_REACHABILITY_UNVERIFIED"),
    ("read_only", False, "TRANSACTION_NOT_READ_ONLY"),
    ("repeatable_snapshot", False, "INCOMPLETE_VISIBILITY"),
    ("trusted_search_path", False, "INCOMPLETE_VISIBILITY"),
])
def test_identity(snapshots, field, value, failure):
    before, _, _ = snapshots
    observation = replace(before, identity=replace(before.identity, **{field: value}))
    assert observer.validate_predecessor(TARGET, observation) is observer.Failure[failure]


@pytest.mark.parametrize("login", [OWNER, "ai_soc_test_migrator", "postgres"])
def test_caller_cannot_approve_a_privileged_login(snapshots, login):
    before, _, _ = snapshots
    assert observer.validate_predecessor(replace(TARGET, login=login), before) is observer.Failure.WRONG_OBSERVER_LOGIN


@pytest.mark.parametrize(("revisions", "failure"), [
    ((), "REVISION_MISMATCH"), ((plan.EXPECTED_PREDECESSOR,), "REVISION_MISMATCH"),
    (("malformed",), "REVISION_MISMATCH"), ((plan.STAGED_REVISION,) * 2, "MULTIPLE_REVISIONS"),
])
def test_successor_requires_exactly_one_revision(snapshots, revisions, failure):
    before, after, reference = snapshots
    assert observer.validate_successor(TARGET, before, replace(after, revisions=revisions),
                                      reference) is observer.Failure[failure]


@pytest.mark.parametrize(("query", "change", "failure"), [
    ("tables", lambda rows: rows[1:], "SUCCESSOR_CATALOG_MISMATCH"),
    ("tables", lambda rows: ((rows[0][0], "other", *rows[0][2:]), *rows[1:]), "SUCCESSOR_CATALOG_MISMATCH"),
    ("tables", lambda rows: ((*rows[0][:3], False, *rows[0][4:]), *rows[1:]), "RLS_NOT_FORCED"),
    ("tables", lambda rows: ((*rows[0][:-1], False), *rows[1:]), "UNEXPECTED_RUNTIME_GRANT"),
    ("constraints", lambda rows: tuple(row for row in rows if row[1] != "f"), "SUCCESSOR_CATALOG_MISMATCH"),
    ("indexes", lambda rows: ((*rows[0][:3], False, *rows[0][4:]), *rows[1:]), "SUCCESSOR_CATALOG_MISMATCH"),
    ("registry", lambda rows: ((OWNER, 1, 0, True, True),), "ACCEPTING_POLICY_PRESENT"),
    ("registry", lambda rows: ((OWNER, 0, 0, True, False),), "AUTHORITY_PRESENT"),
    ("triggers", lambda rows: rows[:-1], "DENY_TRIGGER_MISSING"),
    ("triggers", lambda rows: (rows[0], (*rows[1][:4], 30, *rows[1][5:]), *rows[2:]), "DENY_TRIGGER_MISSING"),
    ("triggers", lambda rows: rows[1:], "RESERVED_AUDIT_FENCE_MISSING"),
    ("audit_triggers", lambda rows: ((AUDIT[0], "D", *AUDIT[2:]), *rows[1:]), "AUDIT_IMMUTABILITY_MISMATCH"),
    ("routines", lambda rows: ((*rows[0][:3], True, *rows[0][4:]),), "UNEXPECTED_AUTHORITY_ROUTINE"),
    ("routines", lambda rows: ((*rows[0][:-1], False),), "UNEXPECTED_RUNTIME_GRANT"),
    ("defaults", lambda rows: ((False,),), "UNEXPECTED_RUNTIME_GRANT"),
    ("columns:source_registry.source_collection_receipts", lambda rows: rows[:-1], "SUCCESSOR_CATALOG_MISMATCH"),
    ("checks:source_registry.source_collection_receipts", lambda rows: (("true",), *rows[1:]), "SUCCESSOR_CATALOG_MISMATCH"),
])
def test_catalog_drift(snapshots, query, change, failure):
    before, after, reference = snapshots
    rows = dict(after.catalog.results)
    rows[query] = change(rows[query])
    assert observer.validate_successor(
        TARGET, before, make_observation(True, rows), reference
    ) is observer.Failure[failure]


@pytest.mark.parametrize(("query", "result", "failure"), [
    ("namespace", (("source_registry", OWNER),), "PREDECESSOR_CATALOG_MISMATCH"),
    ("keys", (), "PREDECESSOR_CATALOG_MISMATCH"),
    ("audit_routine", (), "AUDIT_IMMUTABILITY_MISMATCH"),
    ("shadow_routines", (("public", "source_authority_issue"),), "UNEXPECTED_AUTHORITY_ROUTINE"),
])
def test_predecessor_drift(snapshots, query, result, failure):
    before, _, _ = snapshots
    rows = dict(before.catalog.results)
    rows[query] = result
    assert observer.validate_predecessor(TARGET, make_observation(False, rows)) is observer.Failure[failure]


@pytest.mark.parametrize(("field", "value", "failure"), [
    ("evidence", (observer.EvidenceDigest(UUID(int=2), "9" * 64, "9" * 64),), "EVIDENCE_BASELINE_MISMATCH"),
    ("evidence", (observer.EvidenceDigest(UUID(int=3), "a" * 64, "a" * 64),), "EVIDENCE_BASELINE_MISMATCH"),
    ("evidence", (observer.EvidenceDigest(UUID(int=2), "a" * 64, "9" * 64),), "EVIDENCE_BASELINE_MISMATCH"),
    ("lineage_count", 2, "EVIDENCE_BASELINE_MISMATCH"),
    ("lineage_sha256", "f" * 64, "EVIDENCE_BASELINE_MISMATCH"),
    ("evidence_metadata_sha256", "f" * 64, "EVIDENCE_BASELINE_MISMATCH"),
    ("audit_count", 2, "AUDIT_BASELINE_MISMATCH"),
    ("audit_entries", ((2, "d" * 64),), "AUDIT_BASELINE_MISMATCH"),
    ("audit_head", "f" * 64, "AUDIT_BASELINE_MISMATCH"),
    ("audit_ids_sha256", "f" * 64, "AUDIT_BASELINE_MISMATCH"),
    ("audit_verified", False, "AUDIT_BASELINE_MISMATCH"),
])
def test_baseline_changes(snapshots, field, value, failure):
    before, after, reference = snapshots
    baseline = replace(after.baseline, tenants=(replace(TENANT, **{field: value}),))
    assert observer.validate_successor(TARGET, before, replace(after, baseline=baseline),
                                      reference) is observer.Failure[failure]


@pytest.mark.parametrize(("field", "failure"), [
    ("catalog_complete", "INCOMPLETE_VISIBILITY"),
    ("historical_rows_complete", "INCOMPLETE_VISIBILITY"),
    ("roles_complete", "ROLE_REACHABILITY_UNVERIFIED"),
    ("authority_rows_complete", "AUTHORITY_STATE_UNKNOWN"),
])
def test_incomplete_visibility(snapshots, field, failure):
    before, after, reference = snapshots
    assert observer.validate_successor(TARGET, before, replace(after, visibility=replace(VISIBILITY, **{field: False})),
                                      reference) is observer.Failure[failure]


@pytest.mark.parametrize(("field", "value", "failure"), [
    ("registry_empty", False, "AUTHORITY_PRESENT"),
    ("reserved_audit_absent", False, "AUTHORITY_PRESENT"),
    ("application_isolation_verified", False, "AUTHORITY_PRESENT"),
    ("application_isolation_verified", None, "AUTHORITY_STATE_UNKNOWN"),
])
def test_authority_must_be_known_disabled(snapshots, field, value, failure):
    before, after, reference = snapshots
    assert observer.validate_successor(TARGET, before, replace(after, authority=replace(AUTHORITY, **{field: value})),
                                      reference) is observer.Failure[failure]


def test_expressions_require_matching_independent_reference(snapshots):
    before, after, reference = snapshots
    for candidate in (None, replace(reference, ddl_sha256="f" * 64), replace(reference, version_num=160005)):
        assert observer.validate_successor(TARGET, before, after, candidate) is observer.Failure.INCOMPLETE_VISIBILITY


def test_read_only_query_inventory():
    statements = (observer.IDENTITY_SQL, observer.REVISION_SQL, observer.HISTORY_VISIBILITY_SQL,
                  *(sql for _, sql in observer.HISTORY_QUERIES),
                  *(sql for _, sql, _ in observer.catalog_queries(successor=True)))
    for sql in statements:
        normalized = str(sql).lstrip().upper()
        assert normalized.startswith(("SELECT", "WITH"))
        assert not any(token in normalized for token in ("CREATE TEMP", "SET ROLE", "ADVISORY_LOCK", "NEXTVAL("))


def test_e2_fixture_still_rejects_b4_successor(monkeypatch):
    from unittest.mock import MagicMock

    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.scalar_one.return_value = False
    connection.execute.return_value.scalars.return_value.all.return_value = [plan.STAGED_REVISION]
    monkeypatch.setattr(e2, "create_engine", lambda *args, **kwargs: engine)
    monkeypatch.setattr(e2, "_verify_identity", lambda *args, **kwargs: None)
    with pytest.raises(pytest.fail.Exception, match="unexpected ai_soc_test Alembic revision"):
        e2._verify_revision(MagicMock(), frozenset())


def test_catalog_result_inventory_requires_complete_unique_queries(snapshots):
    before, _, _ = snapshots
    results = before.catalog.results
    for invalid in (results[:-1], (*results, results[0])):
        assert observer.validate_predecessor(
            TARGET, replace(before, catalog=observer.Catalog(invalid))
        ) is observer.Failure.INCOMPLETE_VISIBILITY


def test_predecessor_rejects_reserved_historical_audit_event(snapshots):
    before, _, _ = snapshots
    rows = dict(before.catalog.results, reserved_history=((False,),))
    assert observer.validate_predecessor(TARGET, make_observation(False, rows)) is observer.Failure.AUTHORITY_PRESENT


def test_row_visibility_requires_all_relations_and_no_rls():
    rows = tuple((name, True, True) for name in (
        "tenants", "evidence_records", "evidence_lineage", "audit_logs",
    ))
    assert observer.history_visible(rows)
    assert not observer.history_visible(rows[:-1])
    assert not observer.history_visible((*rows[:-1], ("audit_logs", False, True)))
    assert not observer.history_visible((*rows[:-1], ("audit_logs", True, False)))
    assert not observer.history_visible((*rows[:-1], rows[0]))


def test_baseline_builder_reuses_historical_hashes_and_discards_payloads():
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from app.audit.integrity import GENESIS_HASH, calculate_audit_hash
    from app.evidence.hashing import calculate_evidence_hash

    tenant_id = UUID(int=1)
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    fields = dict(evidence_type="observation", source_type="wazuh", source_reference="fixture",
                  collector_name="fixture", collector_version="1", trust_level="unverified",
                  payload={"private": "test-only content"}, event_time=stamp)
    row = SimpleNamespace(**fields, id=UUID(int=2), tenant_id=tenant_id,
                          content_sha256=calculate_evidence_hash(**fields),
                          collected_at=stamp, created_at=stamp, schema_version="1")
    audit_fields = dict(tenant_id=tenant_id, sequence_number=1, previous_hash=GENESIS_HASH,
                        actor_type="system", actor_id=None, action="fixture", resource_type="evidence",
                        resource_id=row.id, details={}, created_at=stamp)
    event = SimpleNamespace(**audit_fields, id=UUID(int=3), entry_hash=calculate_audit_hash(**audit_fields))
    baseline = observer.build_tenant_baseline(tenant_id, (row,), (), (event,))
    assert baseline.evidence == (observer.EvidenceDigest(row.id, row.content_sha256, row.content_sha256),)
    assert baseline.audit_verified and baseline.audit_head == event.entry_hash
    assert "test-only content" not in repr(baseline)
    assert observer.build_tenant_baseline(UUID(int=4), (row,), (), ()) is observer.Failure.INCOMPLETE_VISIBILITY
    event.entry_hash = "0" * 64
    assert not observer.build_tenant_baseline(tenant_id, (row,), (), (event,)).audit_verified


def test_identity_rows_reject_ambiguous_or_malformed_server_observations():
    row = (
        "ai_soc_test", 160006, TARGET.login, TARGET.login, *map(str, TARGET.address_pair), 5432,
        True, True, True, True, False, OWNER, True,
    )
    decode = observer.identity_from_rows
    assert decode((row,), observed_container_id=TARGET.container_id) == IDENTITY
    for rows in ((), (row, row), (row[:-1],)):
        assert decode(rows, observed_container_id=TARGET.container_id) is observer.Failure.INCOMPLETE_VISIBILITY
    bad = (*row[:4], "not-an-ip", *row[5:])
    assert decode((bad,), observed_container_id=TARGET.container_id) is observer.Failure.WRONG_SERVER
