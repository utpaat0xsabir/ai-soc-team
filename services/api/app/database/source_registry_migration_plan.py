"""SQL and catalog expectations for the default-disabled source registry."""

from collections import Counter
import re

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, PrimaryKeyConstraint, UniqueConstraint, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateColumn, CreateIndex, CreateTable

from app.database import source_registry_schema as registry


EXPECTED_PREDECESSOR = "d93c6e4fb132"
STAGED_REVISION = "e4b2b2000001"
TABLES = (
    registry.INSTALLATIONS, registry.SCOPES, registry.CONFIGURATIONS,
    registry.RECEIPTS, registry.ENROLLMENTS, registry.ATTEMPTS, registry.ATTESTATIONS,
    registry.REVOCATIONS, registry.AUDIT_BINDINGS,
)

_DENY_WRITES = """CREATE FUNCTION source_registry.deny_staged_write()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $source_registry$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'source_registry_disabled';
END;
$source_registry$"""


def compile_disabled_stage() -> tuple[str, ...]:
    """Render one statement per item for offline review, without selecting a target."""
    dialect = postgresql.dialect()
    statements = [
        "CREATE SCHEMA source_registry",
        "REVOKE ALL ON SCHEMA source_registry FROM PUBLIC",
        _DENY_WRITES,
        "REVOKE ALL ON FUNCTION source_registry.deny_staged_write() FROM PUBLIC",
    ]
    for table in TABLES:
        relation = dialect.identifier_preparer.format_table(table)
        statements.append(str(CreateTable(table).compile(dialect=dialect)).strip())
        statements.extend(str(CreateIndex(index).compile(dialect=dialect))
                          for index in sorted(table.indexes, key=lambda index: index.name))
        statements.extend((
            f"REVOKE ALL ON TABLE {relation} FROM PUBLIC",
            f"ALTER TABLE {relation} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {relation} FORCE ROW LEVEL SECURITY",
            f"CREATE TRIGGER source_registry_disabled BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE "
            f"ON {relation} FOR EACH STATEMENT EXECUTE FUNCTION source_registry.deny_staged_write()",
            f"ALTER TABLE {relation} ENABLE ALWAYS TRIGGER source_registry_disabled",
        ))
    statements.extend((
        "CREATE TRIGGER source_registry_reserved_audit_disabled BEFORE INSERT ON public.audit_logs "
        "FOR EACH ROW WHEN (pg_catalog.starts_with(NEW.action, 'source_authority.')) "
        "EXECUTE FUNCTION source_registry.deny_staged_write()",
        "ALTER TABLE public.audit_logs ENABLE ALWAYS TRIGGER source_registry_reserved_audit_disabled",
    ))
    return tuple(statements)


_LEGACY_AUDIT_ROUTINE = text("""
    SELECT pg_get_userbyid(p.proowner), l.lanname, p.prosecdef, p.proconfig, p.prosrc,
           p.prorettype = 'pg_catalog.trigger'::regtype AND p.prokind = 'f'
           AND p.pronargs = 0 AND p.pronargdefaults = 0 AND p.proargnames IS NULL
           AND EXISTS (
               SELECT FROM pg_attribute a WHERE a.attrelid = 'public.audit_logs'::regclass
                 AND a.attname = 'action' AND a.attnotnull AND NOT a.attisdropped
                 AND a.atttypid = 'pg_catalog.varchar'::regtype AND a.atttypmod = 104
           )
    FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
    WHERE p.oid = to_regprocedure('public.prevent_audit_log_mutation()')
""")

_LEGACY_AUDIT_TRIGGERS = text("""
    SELECT t.tgname, t.tgenabled, t.tgtype,
           t.tgfoid = to_regprocedure('public.prevent_audit_log_mutation()'),
           t.tgnargs = 0 AND t.tgqual IS NULL AND t.tgconstraint = 0
           AND t.tgattr::text = '' AND t.tgparentid = 0
           AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
    FROM pg_trigger t WHERE t.tgrelid = 'public.audit_logs'::regclass AND NOT t.tgisinternal
""")

_AUDIT_MUTATION_ROLES = text("""
    SELECT r.rolname FROM pg_roles r
    WHERE NOT r.rolsuper AND r.rolname NOT IN (:owner, 'pg_write_all_data')
      AND (has_table_privilege(r.oid, 'public.audit_logs', 'UPDATE,DELETE,TRUNCATE,TRIGGER')
           OR has_any_column_privilege(r.oid, 'public.audit_logs', 'UPDATE')
           OR has_parameter_privilege(r.oid, 'session_replication_role', 'SET'))
""")


def verify_legacy_audit(connection, *, owner: str, staged: bool = False) -> bool:
    # prosrc is the literal dollar-quoted body from revision 211e576b1806.
    if [tuple(row) for row in connection.execute(_LEGACY_AUDIT_ROUTINE)] != [
        (owner, "plpgsql", False, None, " BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; ", True)
    ]:
        return False
    expected = [("audit_logs_append_only", "O", 58, True, True)]
    if staged:
        expected.append(("source_registry_reserved_audit_disabled", "A", 7, False, False))
    return (
        Counter(map(tuple, connection.execute(_LEGACY_AUDIT_TRIGGERS))) == Counter(expected)
        and not list(connection.execute(_AUDIT_MUTATION_ROLES, {"owner": owner}))
    )


_DEFAULT_ACL_CHECK = text("""
    WITH owner_role AS (SELECT oid FROM pg_roles WHERE rolname = :owner),
    classes(kind, builtin) AS (
        VALUES ('r', 'r'), ('S', 's'), ('f', 'f'), ('T', 'T'), ('n', 'n')
    )
    SELECT EXISTS (SELECT FROM owner_role) AND NOT EXISTS (
        SELECT FROM owner_role r CROSS JOIN classes c
        LEFT JOIN pg_default_acl d ON d.defaclrole = r.oid
            AND d.defaclnamespace = 0 AND d.defaclobjtype = CAST(c.kind AS "char")
        CROSS JOIN LATERAL aclexplode(
            coalesce(d.defaclacl, acldefault(CAST(c.builtin AS "char"), r.oid))
        ) a WHERE a.grantee <> r.oid
    ) AND NOT EXISTS (
        SELECT FROM owner_role r JOIN pg_default_acl d ON d.defaclrole = r.oid
        JOIN pg_namespace n ON n.oid = d.defaclnamespace
        CROSS JOIN LATERAL aclexplode(d.defaclacl) a
        WHERE n.nspname IN ('source_registry', 'public') AND a.grantee <> r.oid
    )
""")


def verify_default_privileges(connection, *, owner: str) -> bool:
    return connection.execute(_DEFAULT_ACL_CHECK, {"owner": owner}).scalar_one() is True


_CATALOG_CHECK = text("""
    SELECT
        (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'source_registry'),
        (SELECT count(*) FROM pg_policies WHERE schemaname = 'source_registry'),
        (SELECT count(*) FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace
         WHERE n.nspname = 'source_registry'),
        NOT EXISTS (
            SELECT FROM pg_namespace n CROSS JOIN LATERAL
                aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
            WHERE n.nspname = 'source_registry' AND a.grantee <> n.nspowner
        ),
        NOT EXISTS (
            SELECT FROM public.audit_logs WHERE pg_catalog.starts_with(action, 'source_authority.')
        )
""")

_TABLE_CHECK = text("""
    SELECT c.relname, pg_get_userbyid(c.relowner), c.relrowsecurity, c.relforcerowsecurity,
        c.relkind = 'r' AND c.relpersistence = 'p' AND NOT c.relispartition,
        NOT EXISTS (
            SELECT FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
            WHERE a.grantee <> c.relowner
        ) AND NOT EXISTS (
            SELECT FROM pg_attribute col WHERE col.attrelid = c.oid AND col.attacl IS NOT NULL
        )
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'source_registry' AND c.relkind NOT IN ('i', 'I')
""")

_ROUTINE_CHECK = text("""
    SELECT p.proname, p.pronargs, pg_get_userbyid(p.proowner), p.prosecdef, p.proconfig, p.prosrc,
        p.prokind = 'f' AND p.prorettype = 'pg_catalog.trigger'::regtype
        AND p.prolang = (SELECT oid FROM pg_language WHERE lanname = 'plpgsql')
        AND p.pronargdefaults = 0 AND p.proargnames IS NULL,
        NOT EXISTS (
            SELECT FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
            WHERE a.grantee <> p.proowner
        )
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'source_registry'
""")

_TRIGGER_CHECK = text("""
    SELECT n.nspname, c.relname, t.tgname, t.tgenabled, t.tgtype, t.tgqual IS NOT NULL, pg_get_triggerdef(t.oid),
           t.tgfoid = to_regprocedure('source_registry.deny_staged_write()')
           AND t.tgnargs = 0 AND t.tgconstraint = 0 AND t.tgattr::text = ''
           AND t.tgparentid = 0 AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE NOT t.tgisinternal AND (n.nspname = 'source_registry' OR
          (n.nspname = 'public' AND c.relname = 'audit_logs'
           AND t.tgname = 'source_registry_reserved_audit_disabled'))
""")


_RESERVED_TRIGGER_DEFINITION = re.compile(
    r"CREATE TRIGGER source_registry_reserved_audit_disabled BEFORE INSERT ON "
    r"(?:public\.)?audit_logs FOR EACH ROW\s+WHEN\s+\(\s*(?P<condition>.*?)\s*\)"
    r"\s+EXECUTE FUNCTION\s+source_registry\.deny_staged_write\(\)", re.DOTALL
)
_ACTION = r"(?:new\.action|\(\s*new\.action\s*\))"
_PREFIX = r"'source_authority\.'"
_RESERVED_CONDITIONS = (
    re.compile(rf"starts_with\s*\(\s*{_ACTION}\s*::text\s*,\s*{_PREFIX}\s*::text\s*\)"),
    re.compile(rf"pg_catalog\.starts_with\s*\(\s*{_ACTION}\s*(?:::text)?\s*,"
               rf"\s*{_PREFIX}\s*(?:::text)?\s*\)"),
)


def _reserved_condition(definition):
    if type(definition) is not str:
        return False
    match = _RESERVED_TRIGGER_DEFINITION.fullmatch(definition)
    # Unqualified calls must deparse with exact text arguments so an overload
    # using varchar and an untyped literal cannot look like the builtin.
    return match is not None and any(shape.fullmatch(match["condition"]) for shape in _RESERVED_CONDITIONS)


def verify_disabled_catalog(connection, *, owner: str) -> bool:
    """Match the inactive stage. Only the guarded caller supplies the connection."""
    if not verify_legacy_audit(connection, owner=owner, staged=True):
        return False
    if not verify_default_privileges(connection, owner=owner):
        return False
    if tuple(connection.execute(_CATALOG_CHECK).one()) != (owner, 0, 0, True, True):
        return False
    tables = {tuple(row) for row in connection.execute(_TABLE_CHECK)}
    if tables != {(table.name, owner, True, True, True, True) for table in TABLES}:
        return False
    routines = [tuple(row) for row in connection.execute(_ROUTINE_CHECK)]
    body = _DENY_WRITES.split("$source_registry$")[1]
    if routines != [("deny_staged_write", 0, owner, False, ["search_path=pg_catalog, pg_temp"], body, True, True)]:
        return False
    # PostgreSQL trigger flags: BEFORE (2), INSERT (4), DELETE (8),
    # UPDATE (16), TRUNCATE (32), and ROW (1).
    triggers = {tuple(row) for row in connection.execute(_TRIGGER_CHECK)}
    reserved = [row for row in triggers if row[:3] == (
        "public", "audit_logs", "source_registry_reserved_audit_disabled",
    )]
    if len(reserved) != 1:
        return False
    audit_trigger = reserved[0]
    if (audit_trigger[3:6] != ("A", 7, True) or audit_trigger[7] is not True
            or not _reserved_condition(audit_trigger[6])):
        return False
    if {row[:6] + (row[7],) for row in triggers - {audit_trigger}} != {
        ("source_registry", table.name, "source_registry_disabled", "A", 62, False, True)
        for table in TABLES
    }:
        return False
    return (
        _verify_constraints(connection) and _verify_indexes(connection)
        and _verify_backing_indexes(connection) and _verify_column_and_check_expressions(connection)
    )


# Predecessor keys must be actual valid, immediate unique constraints, not
# merely model metadata or a table with the expected name.
_DEPENDENCY_CHECK = text("""
    SELECT c.relname, ARRAY(
        SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY AS key(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = key.attnum ORDER BY key.ord
    )
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_index i ON i.indexrelid = k.conindid
    WHERE n.nspname = 'public' AND k.contype IN ('p','u') AND k.convalidated
      AND NOT k.condeferrable AND i.indisvalid AND i.indisready AND i.indislive
      AND i.indisunique AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL
      AND i.indrelid = c.oid AND i.indnkeyatts = i.indnatts
      AND c.relname IN ('tenants','wazuh_integrations','evidence_records','audit_logs')
""")


def verify_predecessor_keys(connection) -> bool:
    return {
        ("tenants", ("id",)), ("wazuh_integrations", ("tenant_id", "id")),
        ("evidence_records", ("tenant_id", "id")), ("audit_logs", ("tenant_id", "sequence_number")),
    } <= {(name, tuple(keys)) for name, keys in connection.execute(_DEPENDENCY_CHECK)}


_CONSTRAINT_CHECK = text("""
    SELECT c.relname, k.contype,
      k.convalidated AND NOT k.condeferrable AND NOT k.condeferred
      AND k.conislocal AND k.coninhcount = 0 AND k.conparentid = 0
      AND (k.contype <> 'c' OR NOT k.connoinherit),
      CASE WHEN k.contype <> 'c' THEN ARRAY(
        SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY AS key(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = key.attnum ORDER BY key.ord
      ) END,
      rn.nspname, r.relname, CASE WHEN k.contype = 'f' THEN ARRAY(
        SELECT a.attname FROM unnest(k.confkey) WITH ORDINALITY AS key(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = key.attnum ORDER BY key.ord
      ) END,
      CASE WHEN k.contype = 'f' THEN k.confdeltype END,
      CASE WHEN k.contype = 'f' THEN k.confupdtype END,
      CASE WHEN k.contype = 'f' THEN k.confmatchtype END,
      CASE WHEN k.contype = 'f' THEN k.confdelsetcols IS NULL
          AND EXISTS (
              SELECT FROM pg_index i WHERE i.indexrelid = k.conindid AND i.indrelid = k.confrelid
                 AND i.indisunique AND i.indimmediate AND i.indisvalid AND i.indisready AND i.indislive
                 AND i.indpred IS NULL AND i.indexprs IS NULL
          )
          AND (SELECT array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") = ARRAY[
                   'RI_FKey_check_ins', 'RI_FKey_check_upd', 'RI_FKey_noaction_upd', 'RI_FKey_restrict_del'
               ] AND bool_and(t.tgenabled = 'O' AND t.tgisinternal
                   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgparentid = 0
                   AND t.tgnargs = 0 AND t.tgqual IS NULL AND t.tgattr::text = ''
                   AND p.pronamespace = 'pg_catalog'::regnamespace
                   AND CASE p.proname
                       WHEN 'RI_FKey_check_ins' THEN t.tgrelid = k.conrelid AND t.tgtype = 5
                       WHEN 'RI_FKey_check_upd' THEN t.tgrelid = k.conrelid AND t.tgtype = 17
                       WHEN 'RI_FKey_noaction_upd' THEN t.tgrelid = k.confrelid AND t.tgtype = 17
                       WHEN 'RI_FKey_restrict_del' THEN t.tgrelid = k.confrelid AND t.tgtype = 9
                       ELSE false END
               )
               FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid WHERE t.tgconstraint = k.oid) END
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_class r ON r.oid = k.confrelid
    LEFT JOIN pg_namespace rn ON rn.oid = r.relnamespace
    WHERE n.nspname = 'source_registry'
""")


def _verify_constraints(connection) -> bool:
    expected = Counter()
    for table in TABLES:
        for constraint in table.constraints:
            columns = tuple(constraint.columns.keys())
            if isinstance(constraint, ForeignKeyConstraint):
                expected[(table.name, "f", True, columns, constraint.referred_table.schema,
                          constraint.referred_table.name, tuple(e.column.name for e in constraint.elements), "r", "a", "s", True)] += 1
            else:
                kind = {CheckConstraint: "c", PrimaryKeyConstraint: "p", UniqueConstraint: "u"}[type(constraint)]
                expected[(table.name, kind, True, None if kind == "c" else columns, None, None, None, None, None, None, None)] += 1
    return expected == Counter(
        (table, kind, valid, None if cols is None else tuple(cols), schema, target,
         None if refs is None else tuple(refs), delete, update, match, flags)
        for table, kind, valid, cols, schema, target, refs, delete, update, match, flags in connection.execute(_CONSTRAINT_CHECK)
    )


_COLUMN_CHECK = text("""
    SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attgenerated,
        a.attidentity, coll_ns.nspname, coll.collname, pg_get_expr(d.adbin, a.attrelid, false)
    FROM pg_attribute a
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
    LEFT JOIN pg_collation coll ON coll.oid = a.attcollation
    LEFT JOIN pg_namespace coll_ns ON coll_ns.oid = coll.collnamespace
    WHERE a.attrelid = to_regclass(:relation) AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY a.attnum
""")

_CHECK_EXPRESSION = text("""
    SELECT pg_get_expr(conbin, conrelid, false) FROM pg_constraint
    WHERE conrelid = to_regclass(:relation) AND contype = 'c'
""")


def _verify_column_and_check_expressions(connection) -> bool:
    # Parse the pinned expressions using the same server as the observed catalog.
    # The empty scratch relation has no FKs, authority rows or runtime grants.
    dialect = postgresql.dialect()
    scratch = "pg_temp.source_registry_catalog_reference"
    for table in TABLES:
        definitions = [str(CreateColumn(col).compile(dialect=dialect)) for col in table.columns]
        definitions.extend(
            f"CHECK ({constraint.sqltext})" for constraint in table.constraints
            if isinstance(constraint, CheckConstraint)
        )
        connection.exec_driver_sql(f"CREATE TEMPORARY TABLE {scratch} ({', '.join(definitions)}) ON COMMIT DROP")
        expected = {"relation": scratch}
        actual = {"relation": table.fullname}
        columns = list(connection.execute(_COLUMN_CHECK, expected))
        checks = Counter(connection.execute(_CHECK_EXPRESSION, expected).scalars())
        matches = (
            len(columns) == len(table.columns)
            and columns == list(connection.execute(_COLUMN_CHECK, actual))
            and sum(checks.values()) == sum(isinstance(key, CheckConstraint) for key in table.constraints)
            and None not in checks
            and checks == Counter(connection.execute(_CHECK_EXPRESSION, actual).scalars())
        )
        connection.exec_driver_sql(f"DROP TABLE {scratch}")
        if not matches:
            return False
    return True


_BACKING_INDEX_CHECK = text("""
    SELECT c.relname, k.contype, ARRAY(
        SELECT col.attname FROM unnest(i.indkey) WITH ORDINALITY AS keys(attnum, ord)
        JOIN pg_attribute col ON col.attrelid = c.oid AND col.attnum = keys.attnum ORDER BY keys.ord
    ), i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate
       AND i.indisprimary = (k.contype = 'p') AND NOT i.indnullsnotdistinct
       AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts = i.indnatts
       AND ci.relnamespace = c.relnamespace AND am.amname = 'btree'
       AND NOT EXISTS (
           SELECT FROM unnest(i.indclass, i.indcollation, i.indoption, i.indkey)
                       AS attrs(opclass, collation_id, direction, attnum)
           JOIN pg_opclass opc ON opc.oid = attrs.opclass
           JOIN pg_attribute col ON col.attrelid = c.oid AND col.attnum = attrs.attnum
           WHERE NOT opc.opcdefault OR attrs.collation_id <> col.attcollation OR attrs.direction <> 0
       )
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_index i ON i.indexrelid = k.conindid AND i.indrelid = c.oid
    JOIN pg_class ci ON ci.oid = i.indexrelid JOIN pg_am am ON am.oid = ci.relam
    WHERE n.nspname = 'source_registry' AND k.contype IN ('p','u')
""")


def _verify_backing_indexes(connection) -> bool:
    expected = Counter(
        (table.name, "p" if isinstance(key, PrimaryKeyConstraint) else "u", tuple(key.columns.keys()), True)
        for table in TABLES for key in table.constraints if isinstance(key, (PrimaryKeyConstraint, UniqueConstraint))
    )
    return expected == Counter(
        (table, kind, tuple(columns), valid)
        for table, kind, columns, valid in connection.execute(_BACKING_INDEX_CHECK)
    )


_INDEX_CHECK = text("""
    SELECT ci.relname, c.relname, i.indisunique, i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate AND NOT i.indnullsnotdistinct,
           ARRAY(
               SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY AS cols(attnum, ord)
               JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = cols.attnum ORDER BY cols.ord
           ), i.indoption::text, pg_get_expr(i.indpred, c.oid), am.amname,
           i.indexprs IS NULL AND i.indnkeyatts = i.indnatts
           AND ci.relnamespace = c.relnamespace AND NOT i.indisprimary
           AND NOT EXISTS (
               SELECT FROM unnest(i.indclass, i.indcollation, i.indkey) AS attrs(opclass, collation_id, attnum)
               JOIN pg_opclass opc ON opc.oid = attrs.opclass
               JOIN pg_attribute col ON col.attrelid = c.oid AND col.attnum = attrs.attnum
               WHERE NOT opc.opcdefault OR attrs.collation_id <> col.attcollation
           )
    FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
    JOIN pg_class ci ON ci.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am am ON am.oid = ci.relam
    WHERE n.nspname = 'source_registry' AND NOT EXISTS (
          SELECT FROM pg_constraint k WHERE k.conindid = i.indexrelid AND k.conrelid = c.oid
    )
""")


def _verify_indexes(connection) -> bool:
    expected = {}
    for table in TABLES:
        for index in table.indexes:
            dialect = postgresql.dialect()
            expressions = [str(expr.compile(dialect=dialect, compile_kwargs={"include_table": False}))
                           for expr in index.expressions]
            names = tuple(expr.removesuffix(" DESC") for expr in expressions)
            options = " ".join("3" if expr.endswith(" DESC") else "0" for expr in expressions)
            where = index.dialect_options["postgresql"]["where"]
            predicate = str(where.compile(dialect=dialect, compile_kwargs={"include_table": False})) if where is not None else None
            expected[index.name] = (table.name, bool(index.unique), True, names, options, predicate, "btree", True)
    rows = list(connection.execute(_INDEX_CHECK))
    return len(rows) == len(expected) and {
        name: (table, unique, valid, tuple(cols), options, _partial_predicate(predicate), method, simple)
        for name, table, unique, valid, cols, options, predicate, method, simple in rows
    } == expected


def _partial_predicate(predicate):
    if predicate is not None:
        match = re.fullmatch(r"\(?((?:suspended_at|terminated_at) IS NULL)\)?", predicate)
        if match and predicate.startswith("(") == predicate.endswith(")"):
            return match[1]
        return predicate
    return None
