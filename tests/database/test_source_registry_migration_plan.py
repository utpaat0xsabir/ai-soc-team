"""Offline checks for the fenced source-registry design."""

from unittest.mock import Mock

import pytest

from app.database import source_registry_migration_plan as plan


def test_candidate_contains_only_a_fenced_schema():
    statements = plan.compile_disabled_stage()
    assert statements[0] == "CREATE SCHEMA source_registry"
    assert len([sql for sql in statements if sql.startswith("CREATE TABLE")]) == 9
    assert not any(sql.startswith(("GRANT", "INSERT", "CREATE POLICY")) for sql in statements)


def test_candidate_denies_every_database_write_and_read_for_runtime():
    statements = plan.compile_disabled_stage()
    function = next(sql for sql in statements if sql.startswith("CREATE FUNCTION"))
    assert "SECURITY INVOKER" in function
    assert "SET search_path = pg_catalog, pg_temp" in function
    assert "ERRCODE = '42501'" in function
    assert "REVOKE ALL ON FUNCTION source_registry.deny_staged_write() FROM PUBLIC" in statements
    assert not any("SECURITY DEFINER" in sql or "DISABLE ROW LEVEL SECURITY" in sql for sql in statements)
    for table in plan.TABLES:
        relation = table.fullname
        assert f"ALTER TABLE {relation} ENABLE ROW LEVEL SECURITY" in statements
        assert f"ALTER TABLE {relation} FORCE ROW LEVEL SECURITY" in statements
        assert f"REVOKE ALL ON TABLE {relation} FROM PUBLIC" in statements
        assert f"CREATE TRIGGER source_registry_disabled BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {relation} FOR EACH STATEMENT EXECUTE FUNCTION source_registry.deny_staged_write()" in statements


def test_compilation_preserves_global_keys_and_tenant_foreign_keys():
    from app.database.models import Base
    from app.database import source_registry_schema as registry

    sql = "\n".join(plan.compile_disabled_stage())
    assert "UNIQUE (canonical_enrollment_identity)" in sql
    assert "UNIQUE (installation_id, index_uuid, document_id)" in sql
    assert "UNIQUE (tenant_id, attestation_id, evidence_id, content_sha256)" in sql
    assert "FOREIGN KEY(tenant_id, source_scope_id, generation, config_sha256)" in sql
    assert "REFERENCES public.wazuh_integrations (tenant_id, id) ON DELETE RESTRICT" in sql
    assert "REFERENCES public.audit_logs (tenant_id, sequence_number) ON DELETE RESTRICT" in sql
    assert "REFERENCES public.evidence_records (tenant_id, id) ON DELETE RESTRICT" in sql
    assert registry.RECEIPTS.metadata is not Base.metadata
    assert all(table.fullname not in Base.metadata.tables for table in plan.TABLES)


def test_staged_revision_is_the_sole_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == [plan.STAGED_REVISION]
    revision = scripts.get_revision(plan.STAGED_REVISION)
    assert revision.down_revision == plan.EXPECTED_PREDECESSOR


def test_disabled_candidate_respects_existing_statement_guard():
    from app.database.migration_guard import _check_statement

    for statement in plan.compile_disabled_stage():
        _check_statement(None, None, statement, None, None, False)


def test_supporting_provenance_bindings_and_reserved_audit_fence():
    from app.database import source_registry_schema as registry

    sql = "\n".join(plan.compile_disabled_stage())
    assert "source_workload_enrollments" in sql
    assert "publisher_action = 'publish_retrieval' AND attestor_action = 'attest'" in sql
    assert "publisher_database_role_oid <> attestor_database_role_oid" in sql
    assert "uq_source_receipt_locator" in sql and "GENERATED ALWAYS AS (COALESCE(event_revision, -1)) STORED" in sql
    assert "REFERENCES source_registry.source_retrieval_attempts" in sql
    assert "UNIQUE (tenant_id, retrieval_attempt_id)" in sql
    assert registry.AUDIT_BINDINGS.c.server_xid.type.get_col_spec() == "xid8"
    assert "DEFAULT pg_catalog.pg_current_xact_id()" in sql
    assert "UNIQUE (tenant_id, actor_principal_id, action, request_id)" in sql
    assert "pg_catalog.starts_with(NEW.action, 'source_authority.')" in sql
    assert "ENABLE ALWAYS TRIGGER source_registry_reserved_audit_disabled" in sql
    assert not any("CREATE POLICY" in statement or statement.startswith("GRANT") for statement in plan.compile_disabled_stage())


def test_staged_revision_rejects_unguarded_use_and_downgrade(monkeypatch):
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    import pytest

    revision = ScriptDirectory.from_config(Config("alembic.ini")).get_revision(plan.STAGED_REVISION).module
    monkeypatch.setattr(revision.guard, "guarded_environment", lambda: None)
    with pytest.raises(revision.guard.Denied, match="guarded_connection_required"):
        revision.upgrade()
    with pytest.raises(RuntimeError, match="explicit_recovery_plan"):
        revision.downgrade()


def test_guarded_revision_uses_same_connection_and_rejects_drift(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from alembic.config import Config
    from alembic.script import ScriptDirectory
    import pytest

    revision = ScriptDirectory.from_config(Config("alembic.ini")).get_revision(plan.STAGED_REVISION).module
    connection = Mock()
    request = SimpleNamespace(predecessor=plan.EXPECTED_PREDECESSOR, successor=plan.STAGED_REVISION)
    monkeypatch.setattr(revision.guard, "guarded_environment", lambda: (connection, None, request, None, None))
    monkeypatch.setattr(revision.op, "get_bind", lambda: connection)
    pre = Mock(return_value=False)
    post = Mock(return_value=False)
    monkeypatch.setattr(plan, "verify_predecessor_keys", pre)
    monkeypatch.setattr(plan, "verify_disabled_catalog", post)

    with pytest.raises(revision.guard.Denied, match="migration_ownership_mismatch"):
        revision.upgrade()
    connection.exec_driver_sql.assert_not_called()
    pre.return_value = True
    with pytest.raises(revision.guard.Denied, match="migration_ownership_mismatch"):
        revision.upgrade()
    assert connection.exec_driver_sql.call_count == len(plan.compile_disabled_stage())
    post.assert_called_once_with(connection, owner=revision.guard.OWNER)
    connection.reset_mock()
    rendered = plan.compile_disabled_stage()
    monkeypatch.setattr(plan, "compile_disabled_stage", lambda: (*rendered, "SELECT 1"))
    with pytest.raises(revision.guard.Denied, match="unexpected_upgrade_plan"):
        revision.upgrade()
    connection.exec_driver_sql.assert_not_called()


def test_inactive_catalog_rejects_visibility_ownership_and_trigger_drift(monkeypatch):
    from unittest.mock import Mock

    owner = "ai_soc_test_owner"
    catalog = (owner, 0, 0, True, True)
    tables = [(table.name, owner, True, True, True, True) for table in plan.TABLES]
    routine = ("deny_staged_write", 0, owner, False, ["search_path=pg_catalog, pg_temp"],
               plan._DENY_WRITES.split("$source_registry$")[1], True, True)
    triggers = [("source_registry", table.name, "source_registry_disabled", "A", 62, False, "", True)
                for table in plan.TABLES]
    triggers.append(("public", "audit_logs", "source_registry_reserved_audit_disabled", "A", 7, True,
                     "CREATE TRIGGER source_registry_reserved_audit_disabled BEFORE INSERT ON public.audit_logs "
                     "FOR EACH ROW WHEN (starts_with((new.action)::text, 'source_authority.'::text)) "
                     "EXECUTE FUNCTION source_registry.deny_staged_write()", True))
    rows = {plan._CATALOG_CHECK: Mock(one=lambda: catalog), plan._TABLE_CHECK: tables,
            plan._ROUTINE_CHECK: [routine], plan._TRIGGER_CHECK: triggers}
    connection = Mock()
    connection.execute.side_effect = rows.__getitem__
    monkeypatch.setattr(plan, "verify_legacy_audit", lambda bind, **kwargs: True)
    monkeypatch.setattr(plan, "verify_default_privileges", lambda bind, **kwargs: True)
    monkeypatch.setattr(plan, "_verify_column_and_check_expressions", lambda bind: True)
    monkeypatch.setattr(plan, "_verify_backing_indexes", lambda bind: True)
    monkeypatch.setattr(plan, "_verify_constraints", lambda bind: True)
    monkeypatch.setattr(plan, "_verify_indexes", lambda bind: True)
    assert plan.verify_disabled_catalog(connection, owner=owner)
    rows[plan._CATALOG_CHECK] = Mock(one=lambda: (owner, 1, 0, True, True))
    assert not plan.verify_disabled_catalog(connection, owner=owner)
    rows[plan._CATALOG_CHECK] = Mock(one=lambda: catalog)
    rows[plan._ROUTINE_CHECK] = [(*routine[:3], True, *routine[4:])]
    assert not plan.verify_disabled_catalog(connection, owner=owner)
    rows[plan._ROUTINE_CHECK] = [routine]
    rows[plan._TRIGGER_CHECK] = triggers[:-1]
    assert not plan.verify_disabled_catalog(connection, owner=owner)
    bad_trigger = triggers[-1]
    rows[plan._TRIGGER_CHECK] = [
        *triggers[:-1], (*bad_trigger[:6], bad_trigger[6].replace("source_authority.", "SOURCE_AUTHORITY."), True),
    ]
    assert not plan.verify_disabled_catalog(connection, owner=owner)


def test_predecessor_and_explicit_index_inventory_reject_missing_keys():
    from unittest.mock import Mock

    connection = Mock()
    required = [("tenants", ["id"]), ("wazuh_integrations", ["tenant_id", "id"]),
                ("evidence_records", ["tenant_id", "id"]), ("audit_logs", ["tenant_id", "sequence_number"])]
    connection.execute.return_value = required
    assert plan.verify_predecessor_keys(connection)
    connection.execute.return_value = required[:-1]
    assert not plan.verify_predecessor_keys(connection)

    rows = [
        ("uq_source_active_installation", "source_scopes", True, True, ["installation_id"], "0",
         "(suspended_at IS NULL)", "btree", True),
        ("ix_source_receipt_history", "source_collection_receipts", False, True,
         ["tenant_id", "evidence_id", "collected_at", "receipt_id"], "0 0 3 0", None, "btree", True),
        ("ix_source_attestation_history", "source_verification_attestations", False, True,
         ["tenant_id", "evidence_id", "verified_at", "attestation_id"], "0 0 3 0", None, "btree", True),
    ]
    for name in ("principal_id", "workload_scope_id", "database_role_oid", "database_login"):
        rows.append((f"uq_source_active_enrollment_{name}", "source_workload_enrollments", True, True,
                     ["tenant_id", "source_scope_id", name], "0 0 0", "(terminated_at IS NULL)", "btree", True))
    connection.execute.return_value = rows
    assert plan._verify_indexes(connection)
    connection.execute.return_value = rows[:-1]
    assert not plan._verify_indexes(connection)


@pytest.mark.parametrize(("target", "value"), [
    ("trigger", []),
    ("trigger", [("audit_logs_append_only", "D", 58, True, True)]),
    ("trigger", [("audit_logs_append_only", "O", 58, False, True)]),
    ("trigger", [("audit_logs_append_only", "O", 10, True, True)]),
    ("trigger", [("audit_logs_append_only", "O", 56, True, True)]),
    ("trigger", [("audit_logs_append_only", "O", 59, True, True)]),
    ("routine", [("wrong", "plpgsql", False, None, "", True)]),
    ("routine", [("owner", "plpgsql", True, None, "", True)]),
    ("routine", [("owner", "plpgsql", False, None, " BEGIN RETURN NULL; END; ", True)]),
    ("privilege", [("runtime_mutator",)]),
    ("competing", [("extra_trigger", "O", 58, True, True)]),
])
def test_legacy_audit_rejects_drift(target, value):
    rows = {
        "routine": [("owner", "plpgsql", False, None,
                     " BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; ", True)],
        "trigger": [("audit_logs_append_only", "O", 58, True, True)],
        "privilege": [],
    }
    bind = Mock()
    queries = {plan._LEGACY_AUDIT_ROUTINE: "routine", plan._LEGACY_AUDIT_TRIGGERS: "trigger",
               plan._AUDIT_MUTATION_ROLES: "privilege"}
    bind.execute.side_effect = lambda query, params=None: rows[queries[query]]
    assert plan.verify_legacy_audit(bind, owner="owner")
    if target == "competing":
        rows["trigger"] += value
    else:
        rows[target] = value
    assert not plan.verify_legacy_audit(bind, owner="owner")


@pytest.mark.parametrize("condition", [
    "starts_with((new.action)::text, 'source_authority.'::text)",
    "pg_catalog.starts_with(new.action, 'source_authority.')",
])
def test_reserved_predicate_accepts_only_exact_prefix_call(condition):
    definition = ("CREATE TRIGGER source_registry_reserved_audit_disabled BEFORE INSERT ON public.audit_logs "
                  f"FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION source_registry.deny_staged_write()")
    assert plan._reserved_condition(definition)
    for weaker in (
        condition.replace("source_authority.", "source_authority"),
        condition.replace("source_authority.", "SOURCE_AUTHORITY."),
        condition.replace("source_authority.", "source_authority.attest"),
        condition.replace("starts_with", "ends_with"),
        f"NOT {condition}",
        f"{condition} OR true",
    ):
        assert not plan._reserved_condition(definition.replace(condition, weaker))


@pytest.mark.parametrize("action, reserved", [
    ("source_authority.attest", True),
    ("source_authority.future_operation", True),
    ("source_authority.", True),
    ("source_authority", False),
    ("SOURCE_AUTHORITY.attest", False),
    ("source_authority_other.attest", False),
])
def test_reserved_namespace_contract(action, reserved):
    # This is the contract for PG starts_with, exercised against PG in B4.
    assert action.startswith("source_authority.") is reserved


@pytest.mark.parametrize("drift", ["not_null", "generated", "check", "type", "collation", "identity", "default"])
def test_same_count_expression_and_column_drift(monkeypatch, drift):
    from sqlalchemy import CheckConstraint

    table = plan.registry.RECEIPTS
    monkeypatch.setattr(plan, "TABLES", (table,))
    columns = [[column.name, "type", True, "", "", None, None, None] for column in table.columns]
    index = list(table.columns.keys()).index("locator_revision_key")
    columns[index][3] = "s"
    columns[index][7] = "COALESCE(event_revision, '-1'::integer)"
    expected = [tuple(column) for column in columns]
    checks = [str(constraint.sqltext) for constraint in table.constraints if isinstance(constraint, CheckConstraint)]
    actual_checks = checks.copy()
    actual = [column.copy() for column in columns]

    def catalog(sql, params):
        reference = params["relation"].startswith("pg_temp.")
        if sql is plan._COLUMN_CHECK:
            return expected if reference else list(map(tuple, actual))
        return Mock(scalars=lambda: checks if reference else actual_checks)

    bind = Mock()
    bind.execute.side_effect = catalog
    assert plan._verify_column_and_check_expressions(bind)
    from app.database import migration_guard
    for call in bind.exec_driver_sql.call_args_list:
        migration_guard._check_statement(None, None, call.args[0], None, None, False)
    if drift == "check":
        actual_checks[0] = "true"
    else:
        attribute, value = {"type": (1, "bigint"), "not_null": (2, False), "generated": (3, ""),
                            "identity": (4, "d"), "collation": (6, "default"), "default": (7, "0")}[drift]
        actual[index][attribute] = value
    assert not plan._verify_column_and_check_expressions(bind)


@pytest.mark.parametrize(("attribute", "value"), [(7, "c"), (8, "c"), (9, "f"), (2, False), (10, False)])
def test_constraint_fk_actions_and_enforcement_are_exact(monkeypatch, attribute, value):
    from sqlalchemy import Table, Column, MetaData, Integer, ForeignKeyConstraint

    metadata = MetaData()
    Table("parent", metadata, Column("id", Integer, primary_key=True), schema="public")
    table = Table("child", metadata, Column("id", Integer, primary_key=True), schema="source_registry")
    table.append_constraint(ForeignKeyConstraint(["id"], ["public.parent.id"], ondelete="RESTRICT"))
    monkeypatch.setattr(plan, "TABLES", (table,))
    fk = ["child", "f", True, ["id"], "public", "parent", ["id"], "r", "a", "s", True]
    pk = ("child", "p", True, ["id"], None, None, None, None, None, None, None)
    bind = Mock()
    bind.execute.return_value = [pk, fk]
    assert plan._verify_constraints(bind)
    fk[attribute] = value
    assert not plan._verify_constraints(bind)


def test_owner_global_and_schema_acl_checks_fail_closed():
    bind = Mock()
    for observation in (False, None, True):
        bind.execute.return_value.scalar_one.return_value = observation
        assert plan.verify_default_privileges(bind, owner="owner") is (observation is True)
    sql = str(plan._DEFAULT_ACL_CHECK)
    assert "d.defaclnamespace = 0" in sql and "acldefault" in sql
    assert "n.nspname IN ('source_registry', 'public')" in sql
    assert "a.grantee <> r.oid" in sql


@pytest.mark.parametrize(("attribute", "value"), [(2, False), (3, False), (6, "(suspended_at IS NOT NULL)")])
def test_index_inventory_rejects_weakened_definition(monkeypatch, attribute, value):
    monkeypatch.setattr(plan, "TABLES", (plan.registry.SCOPES,))
    row = ["uq_source_active_installation", "source_scopes", True, True,
           ["installation_id"], "0", "(suspended_at IS NULL)", "btree", True]
    bind = Mock()
    bind.execute.return_value = [row]
    assert plan._verify_indexes(bind)
    row[attribute] = value
    assert not plan._verify_indexes(bind)


def test_constraint_backing_indexes_require_exact_valid_keys(monkeypatch):
    from sqlalchemy import PrimaryKeyConstraint, UniqueConstraint

    table = plan.registry.SCOPES
    monkeypatch.setattr(plan, "TABLES", (table,))
    rows = [[table.name, "p" if isinstance(key, PrimaryKeyConstraint) else "u", list(key.columns.keys()), True]
            for key in table.constraints if isinstance(key, (PrimaryKeyConstraint, UniqueConstraint))]
    bind = Mock()
    bind.execute.return_value = rows
    assert plan._verify_backing_indexes(bind)
    rows[0][3] = False
    assert not plan._verify_backing_indexes(bind)


def test_retrieval_attempt_reserves_negative_locator_revision_for_null_only():
    statement = next(sql for sql in plan.compile_disabled_stage()
                     if sql.startswith("CREATE TABLE source_registry.source_retrieval_attempts "))
    assert "GENERATED ALWAYS AS (COALESCE(event_revision, -1)) STORED" in statement
    assert "CHECK (event_revision IS NULL OR event_revision >= 0)" in statement
