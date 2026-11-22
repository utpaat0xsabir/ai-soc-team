"""Offline B4 observation contract. The approved live collector is a separate boundary."""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
from ipaddress import IPv4Address
import json
import re
from typing import Protocol
from uuid import UUID

from sqlalchemy import CheckConstraint, text

from app.audit.integrity import GENESIS_HASH, verify_audit_chain
from app.database import migration_guard as guard
from app.database import source_registry_migration_plan as plan
from app.evidence.hashing import calculate_evidence_hash


class Failure(str, Enum):
    WRONG_DATABASE = "WRONG_DATABASE"
    WRONG_SERVER = "WRONG_SERVER"
    WRONG_CONTAINER = "WRONG_CONTAINER"
    WRONG_POSTGRES_VERSION = "WRONG_POSTGRES_VERSION"
    WRONG_OBSERVER_LOGIN = "WRONG_OBSERVER_LOGIN"
    PRIVILEGED_OBSERVER = "PRIVILEGED_OBSERVER"
    ROLE_REACHABILITY_UNVERIFIED = "ROLE_REACHABILITY_UNVERIFIED"
    TRANSACTION_NOT_READ_ONLY = "TRANSACTION_NOT_READ_ONLY"
    REVISION_MISMATCH = "REVISION_MISMATCH"
    MULTIPLE_REVISIONS = "MULTIPLE_REVISIONS"
    PREDECESSOR_CATALOG_MISMATCH = "PREDECESSOR_CATALOG_MISMATCH"
    SUCCESSOR_CATALOG_MISMATCH = "SUCCESSOR_CATALOG_MISMATCH"
    INCOMPLETE_VISIBILITY = "INCOMPLETE_VISIBILITY"
    RLS_NOT_FORCED = "RLS_NOT_FORCED"
    ACCEPTING_POLICY_PRESENT = "ACCEPTING_POLICY_PRESENT"
    DENY_TRIGGER_MISSING = "DENY_TRIGGER_MISSING"
    AUDIT_IMMUTABILITY_MISMATCH = "AUDIT_IMMUTABILITY_MISMATCH"
    RESERVED_AUDIT_FENCE_MISSING = "RESERVED_AUDIT_FENCE_MISSING"
    UNEXPECTED_RUNTIME_GRANT = "UNEXPECTED_RUNTIME_GRANT"
    UNEXPECTED_AUTHORITY_ROUTINE = "UNEXPECTED_AUTHORITY_ROUTINE"
    EVIDENCE_BASELINE_MISMATCH = "EVIDENCE_BASELINE_MISMATCH"
    AUDIT_BASELINE_MISMATCH = "AUDIT_BASELINE_MISMATCH"
    AUTHORITY_STATE_UNKNOWN = "AUTHORITY_STATE_UNKNOWN"
    AUTHORITY_PRESENT = "AUTHORITY_PRESENT"


@dataclass(frozen=True)
class Target:
    """Operator-approved pin. The pair contains the server IP and client gateway."""
    container_id: str
    address_pair: tuple[IPv4Address, IPv4Address]
    login: str


@dataclass(frozen=True, repr=False)
class Identity:
    database: str
    version_num: int
    session_user: str
    current_user: str
    server: IPv4Address
    client: IPv4Address
    port: int
    read_only: bool
    repeatable_snapshot: bool
    restricted_attributes: bool
    membership_free: bool | None
    excess_privileges: bool | None
    database_owner: str
    trusted_search_path: bool
    container_id: str  # Independently verified by the collector, not returned by SQL.


@dataclass(frozen=True)
class Visibility:
    """Independent evidence of snapshot coverage. Missing evidence never means empty."""
    catalog_complete: bool
    roles_complete: bool
    historical_rows_complete: bool
    authority_rows_complete: bool  # Includes attestation, workload and revocation rows.


@dataclass(frozen=True)
class Authority:
    registry_empty: bool | None
    reserved_audit_absent: bool | None
    application_isolation_verified: bool | None  # Separately reviewed, same build.


@dataclass(frozen=True)
class EvidenceDigest:
    evidence_id: UUID
    stored_sha256: str
    recomputed_sha256: str


@dataclass(frozen=True)
class TenantBaseline:
    tenant_id: UUID
    evidence_count: int
    evidence: tuple[EvidenceDigest, ...]
    evidence_metadata_sha256: str
    lineage_count: int
    lineage_sha256: str
    audit_count: int
    audit_entries: tuple[tuple[int, str], ...]
    audit_ids_sha256: str
    audit_head: str
    audit_verified: bool


@dataclass(frozen=True)
class Baseline:
    revision: str
    catalog_sha256: str
    tenants: tuple[TenantBaseline, ...]


@dataclass(frozen=True, repr=False)
class Catalog:
    """Tuple-only rows from the complete allowlisted query inventory for one snapshot."""
    results: tuple[tuple[str, tuple[tuple, ...]], ...]


@dataclass(frozen=True)
class ExpressionReference:
    """Independently approved PG16 deparse reference generated from pinned DDL."""
    version_num: int
    ddl_sha256: str
    catalog: Catalog  # Only the per-table columns and checks.


@dataclass(frozen=True, repr=False)
class Observation:
    identity: Identity
    visibility: Visibility
    revisions: tuple[str, ...]
    catalog: Catalog
    baseline: Baseline
    authority: Authority


class RestrictedReadConnection(Protocol):
    """Future adapter contract. One verified read-only snapshot, fixed queries only.

    The adapter must prove identity and visibility independently, consume complete
    results, and never switch role or create an engine, temp object or lock here.
    """
    def observe(self, *, successor: bool) -> Observation: ...


DDL_SHA256 = "0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4"
_DIGEST = re.compile(r"[a-f0-9]{64}")
_LOGIN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_TABLES = tuple(table.name for table in plan.TABLES)

# Fixed SELECTs only. Statement parameters for the shared queries are fixed
# below. No public application routine, lock function or TEMP-backed verifier.
IDENTITY_SQL = text("""
    SELECT pg_catalog.current_database(), pg_catalog.current_setting('server_version_num')::integer,
           session_user, current_user, pg_catalog.inet_server_addr(), pg_catalog.inet_client_addr(),
           pg_catalog.inet_server_port(), pg_catalog.current_setting('transaction_read_only') = 'on',
           pg_catalog.current_setting('transaction_isolation') IN ('repeatable read', 'serializable'),
           r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
               OR r.rolreplication OR r.rolbypassrls OR r.rolinherit),
           NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members m
                       WHERE r.oid IN (m.member, m.roleid)),
           pg_catalog.has_database_privilege(r.oid, pg_catalog.current_database(), 'CREATE,TEMP')
           OR pg_catalog.has_parameter_privilege(r.oid, 'session_replication_role', 'SET')
           OR EXISTS (SELECT FROM pg_catalog.pg_shdepend d
                      WHERE d.refclassid = 'pg_catalog.pg_authid'::regclass
                        AND d.refobjid = r.oid AND d.deptype = 'o')
           OR EXISTS (SELECT FROM pg_catalog.pg_namespace n
                      WHERE pg_catalog.has_schema_privilege(r.oid, n.oid, 'CREATE'))
           OR EXISTS (SELECT FROM pg_catalog.pg_proc p WHERE p.prosecdef
                      AND pg_catalog.has_schema_privilege(r.oid, p.pronamespace, 'USAGE')
                      AND pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE'))
           OR EXISTS (
               SELECT FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                 AND CASE WHEN c.relkind = 'S' THEN
                       pg_catalog.has_sequence_privilege(r.oid, c.oid, 'USAGE,UPDATE')
                     WHEN c.relkind IN ('r','p','v','m','f') THEN
                       pg_catalog.has_table_privilege(r.oid, c.oid,
                           'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                       OR pg_catalog.has_any_column_privilege(r.oid, c.oid, 'INSERT,UPDATE,REFERENCES')
                     ELSE false END), pg_catalog.pg_get_userbyid(d.datdba),
      pg_catalog.current_schemas(true) = ARRAY['pg_catalog']::name[]
    FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_database d
    WHERE r.rolname = session_user AND d.datname = pg_catalog.current_database()
""")
def identity_from_rows(rows: tuple[tuple, ...], *, observed_container_id: str) -> Identity | Failure:
    """Decode exactly one server identity row and attach the independent Docker observation."""
    if type(rows) is not tuple or len(rows) != 1 or type(rows[0]) is not tuple or len(rows[0]) != 14:
        return Failure.INCOMPLETE_VISIBILITY
    row = rows[0]
    try:
        if any(type(value) not in (str, IPv4Address) for value in row[4:6]):
            return Failure.WRONG_SERVER
        server, client = map(IPv4Address, row[4:6])
    except ValueError:
        return Failure.WRONG_SERVER
    return Identity(*row[:4], server, client, *row[6:], observed_container_id)


REVISION_SQL = text("SELECT version_num FROM public.alembic_version")
HISTORY_QUERIES = (
    ("tenants", text("SELECT id FROM public.tenants ORDER BY id")),
    ("evidence", text("""
        SELECT id, tenant_id, evidence_type, source_type, source_reference, collector_name,
               collector_version, trust_level, payload, event_time, content_sha256,
               collected_at, created_at, schema_version
        FROM public.evidence_records ORDER BY tenant_id, id
    """)),
    ("lineage", text("""
        SELECT tenant_id, parent_evidence_id, child_evidence_id, relationship_type, created_at
        FROM public.evidence_lineage ORDER BY tenant_id, parent_evidence_id, child_evidence_id, relationship_type
    """)),
    ("audit", text("""
        SELECT id, tenant_id, sequence_number, previous_hash, entry_hash, actor_type, actor_id,
               action, resource_type, resource_id, details, created_at
        FROM public.audit_logs ORDER BY tenant_id, sequence_number
    """)),
)
HISTORY_VISIBILITY_SQL = text("""
    SELECT c.relname, NOT c.relrowsecurity AND NOT pg_catalog.row_security_active(c.oid),
           pg_catalog.has_table_privilege(c.oid, 'SELECT')
           OR NOT EXISTS (
               SELECT FROM pg_catalog.pg_attribute a
               WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                 AND (c.relname <> 'tenants' OR a.attname = 'id')
                 AND NOT pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT')
           )
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      AND c.relname IN ('tenants', 'evidence_records', 'evidence_lineage', 'audit_logs')
""")


def history_visible(rows: tuple[tuple, ...]) -> bool:
    """Conservative proof of ordinary-table row visibility. Drain queries separately."""
    expected = {"tenants", "evidence_records", "evidence_lineage", "audit_logs"}
    if type(rows) is not tuple or len(rows) != len(expected):
        return False
    for row in rows:
        if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str
                or row[0] not in expected or row[1] is not True or row[2] is not True):
            return False
        expected.remove(row[0])
    return not expected

_RESERVED_HISTORY_SQL = text("""
    SELECT NOT EXISTS (
        SELECT FROM public.audit_logs WHERE pg_catalog.starts_with(action, 'source_authority.')
    )
""")
_NAMESPACE_SQL = text("""
    SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner)
    FROM pg_catalog.pg_namespace n WHERE n.nspname = 'source_registry'
""")
_SHADOW_ROUTINES_SQL = text("""
    SELECT n.nspname, p.proname FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname <> 'source_registry'
      AND (pg_catalog.starts_with(p.proname::text, 'source_authority')
           OR p.proname = 'deny_staged_write')
""")
_PUBLIC_OWNERS_SQL = text("""
    SELECT c.relname, pg_catalog.pg_get_userbyid(c.relowner)
    FROM pg_catalog.pg_class c
    WHERE c.relnamespace = 'public'::regnamespace
      AND c.relkind = 'r' AND c.relname::text = ANY(:names)
""")


_LINEAGE_KEYS = text("""
    SELECT k.conname::text,
           k.convalidated AND NOT k.condeferrable AND NOT k.condeferred
           AND k.conislocal AND k.coninhcount = 0 AND k.conparentid = 0
           AND k.confrelid = 'public.evidence_records'::regclass
           AND k.confupdtype = 'a' AND k.confdeltype = 'r' AND k.confmatchtype = 's'
           AND k.conkey = ARRAY[
               (SELECT attnum FROM pg_attribute WHERE attrelid = k.conrelid AND attname = 'tenant_id'),
               (SELECT attnum FROM pg_attribute WHERE attrelid = k.conrelid AND attname =
                CASE k.conname WHEN 'fk_lineage_parent_same_tenant' THEN 'parent_evidence_id'
                               WHEN 'fk_lineage_child_same_tenant' THEN 'child_evidence_id' END)
           ]
           AND k.confkey = ARRAY[
               (SELECT attnum FROM pg_attribute WHERE attrelid = k.confrelid AND attname = 'tenant_id'),
               (SELECT attnum FROM pg_attribute WHERE attrelid = k.confrelid AND attname = 'id')
           ]
           AND (SELECT array_agg(p.proname::text ORDER BY p.proname::text COLLATE "C") = ARRAY[
                    'RI_FKey_check_ins', 'RI_FKey_check_upd', 'RI_FKey_noaction_upd', 'RI_FKey_restrict_del'
                ] AND bool_and(t.tgisinternal AND t.tgenabled = 'O' AND NOT t.tgdeferrable
                    AND p.pronamespace = 'pg_catalog'::regnamespace AND CASE p.proname
                      WHEN 'RI_FKey_check_ins' THEN t.tgrelid = k.conrelid AND t.tgtype = 5
                      WHEN 'RI_FKey_check_upd' THEN t.tgrelid = k.conrelid AND t.tgtype = 17
                      WHEN 'RI_FKey_noaction_upd' THEN t.tgrelid = k.confrelid AND t.tgtype = 17
                      WHEN 'RI_FKey_restrict_del' THEN t.tgrelid = k.confrelid AND t.tgtype = 9
                      ELSE false END)
                FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid WHERE t.tgconstraint = k.oid)
    FROM pg_constraint k WHERE k.conrelid = 'public.evidence_lineage'::regclass AND k.contype = 'f'
""")

_LINEAGE_RELATIONSHIPS = frozenset({"derived_from", "supports", "contradicts", "references"})


def catalog_queries(*, successor: bool) -> tuple[tuple[str, object, tuple], ...]:
    """Return (result name, fixed SELECT, immutable bind pairs) for adapter review."""
    common = (
        ("namespace", _NAMESPACE_SQL, ()),
        ("shadow_routines", _SHADOW_ROUTINES_SQL, ()),
        ("public_owners", _PUBLIC_OWNERS_SQL, (("names", (*guard.APPLICATION_TABLES, "alembic_version")),)),
        ("keys", plan._DEPENDENCY_CHECK, ()),
        ("lineage_keys", _LINEAGE_KEYS, ()),
        ("audit_routine", plan._LEGACY_AUDIT_ROUTINE, ()),
        ("audit_triggers", plan._LEGACY_AUDIT_TRIGGERS, ()),
        ("audit_mutators", plan._AUDIT_MUTATION_ROLES, (("owner", guard.OWNER),)),
        ("reserved_history", _RESERVED_HISTORY_SQL, ()),
    )
    if not successor:
        return common
    return common + (
        ("registry", plan._CATALOG_CHECK, ()),
        ("defaults", plan._DEFAULT_ACL_CHECK, (("owner", guard.OWNER),)),
        ("tables", plan._TABLE_CHECK, ()),
        ("routines", plan._ROUTINE_CHECK, ()),
        ("triggers", plan._TRIGGER_CHECK, ()),
        ("constraints", plan._CONSTRAINT_CHECK, ()),
        ("indexes", plan._INDEX_CHECK, ()),
        ("backing_indexes", plan._BACKING_INDEX_CHECK, ()),
    ) + tuple(
        (f"{kind}:{table.fullname}", sql, (("relation", table.fullname),))
        for table in plan.TABLES
        for kind, sql in (("columns", plan._COLUMN_CHECK), ("checks", plan._CHECK_EXPRESSION))
    )


def _items(catalog: Catalog, names) -> dict:
    if type(catalog.results) is not tuple:
        raise ValueError
    result = dict(catalog.results)
    if len(result) != len(catalog.results) or set(result) != set(names):
        raise ValueError
    for name, rows in result.items():
        if (type(rows) is not tuple or any(type(row) is not tuple for row in rows)
                or (name != "constraints" and len(set(rows)) != len(rows))):
            raise ValueError
        for row in rows:
            if any(type(value) not in (str, int, bool, tuple, type(None)) for value in row):
                raise ValueError
    return result


def _catalog_sha256(rows) -> str:
    ordered = {name: value if name.startswith("columns:") else sorted(value, key=repr)
               for name, value in rows.items()}
    return hashlib.sha256(json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def catalog_sha256(catalog: Catalog, *, successor: bool) -> str:
    return _catalog_sha256(_items(catalog, (name for name, _, _ in catalog_queries(successor=successor))))


class _CatalogReplay:
    """Replay SELECT rows for the existing guard validators. No driver methods."""
    def __init__(self, rows, queries):
        self.rows = rows
        self.names = {sql: name for name, sql, _ in queries}

    def execute(self, sql, params=None):
        return self.rows[self.names[sql]]


def _identity(target: Target, observed: Identity, visibility: Visibility) -> Failure | None:
    if observed.database != guard.TARGET or observed.database_owner != guard.OWNER:
        return Failure.WRONG_DATABASE
    if type(observed.version_num) is not int or observed.version_num // 10000 != 16:
        return Failure.WRONG_POSTGRES_VERSION
    if not _DIGEST.fullmatch(target.container_id) or observed.container_id != target.container_id:
        return Failure.WRONG_CONTAINER
    if (type(observed.server) is not IPv4Address or type(observed.client) is not IPv4Address
            or observed.port != 5432 or (observed.server, observed.client) != target.address_pair
            or any(ip.is_loopback or ip.is_unspecified for ip in target.address_pair)
            or observed.server == observed.client):
        return Failure.WRONG_SERVER
    if (not _LOGIN.fullmatch(target.login) or target.login.startswith("pg_")
            or target.login in {guard.LOGIN, guard.OWNER, "ai_soc", "postgres", "ai_soc_test_runner"}
            or (observed.session_user, observed.current_user) != (target.login, target.login)):
        return Failure.WRONG_OBSERVER_LOGIN
    if observed.trusted_search_path is not True:
        return Failure.INCOMPLETE_VISIBILITY
    if observed.read_only is not True:
        return Failure.TRANSACTION_NOT_READ_ONLY
    if observed.restricted_attributes is not True or observed.excess_privileges is True:
        return Failure.PRIVILEGED_OBSERVER
    if visibility.roles_complete is not True or observed.membership_free is None or observed.excess_privileges is not False:
        return Failure.ROLE_REACHABILITY_UNVERIFIED
    if observed.membership_free is not True:
        return Failure.PRIVILEGED_OBSERVER
    return None


def _registry(rows, replay, observed: Observation, reference: ExpressionReference | None) -> Failure | None:
    if rows["namespace"] != (("source_registry", guard.OWNER),):
        return Failure.SUCCESSOR_CATALOG_MISMATCH
    if len(rows["registry"]) != 1:
        return Failure.INCOMPLETE_VISIBILITY
    owner, policies, local_defaults, namespace_acl, audit_absent = rows["registry"][0]
    if policies != 0:
        return Failure.ACCEPTING_POLICY_PRESENT
    if rows["defaults"] != ((True,),) or local_defaults != 0 or namespace_acl is not True:
        return Failure.UNEXPECTED_RUNTIME_GRANT
    if owner != guard.OWNER:
        return Failure.SUCCESSOR_CATALOG_MISMATCH
    if audit_absent is not True:
        return Failure.AUTHORITY_PRESENT
    tables = rows["tables"]
    if len(tables) != len(_TABLES) or {row[0] for row in tables} != set(_TABLES):
        return Failure.SUCCESSOR_CATALOG_MISMATCH
    for _, owner, enabled, forced, regular, acl in tables:
        if enabled is not True or forced is not True:
            return Failure.RLS_NOT_FORCED
        if acl is not True:
            return Failure.UNEXPECTED_RUNTIME_GRANT
        if owner != guard.OWNER or regular is not True:
            return Failure.SUCCESSOR_CATALOG_MISMATCH
    body = plan._DENY_WRITES.split("$source_registry$")[1]
    routines = rows["routines"]
    if len(routines) != 1 or routines[0][:-1] != (
        "deny_staged_write", 0, guard.OWNER, False, ("search_path=pg_catalog, pg_temp",), body, True
    ):
        return Failure.UNEXPECTED_AUTHORITY_ROUTINE
    if routines[0][-1] is not True:
        return Failure.UNEXPECTED_RUNTIME_GRANT
    reserved = [row for row in rows["triggers"] if row[:3] == (
        "public", "audit_logs", "source_registry_reserved_audit_disabled",
    )]
    if (len(reserved) != 1 or reserved[0][3:6] != ("A", 7, True)
            or reserved[0][7] is not True or not plan._reserved_condition(reserved[0][6])):
        return Failure.RESERVED_AUDIT_FENCE_MISSING
    triggers = [row[:6] + (row[7],) for row in rows["triggers"] if row not in reserved]
    if len(triggers) != len(_TABLES) or set(triggers) != {
        ("source_registry", name, "source_registry_disabled", "A", 62, False, True) for name in _TABLES
    }:
        return Failure.DENY_TRIGGER_MISSING
    if not (plan._verify_constraints(replay) and plan._verify_indexes(replay) and plan._verify_backing_indexes(replay)):
        return Failure.SUCCESSOR_CATALOG_MISMATCH
    if (reference is None or reference.version_num != observed.identity.version_num
            or reference.ddl_sha256 != DDL_SHA256):
        return Failure.INCOMPLETE_VISIBILITY
    names = tuple(name for name in rows if name.startswith(("columns:", "checks:")))
    try:
        expected = _items(reference.catalog, names)
    except (ValueError, TypeError):
        return Failure.INCOMPLETE_VISIBILITY
    for table in plan.TABLES:
        columns = f"columns:{table.fullname}"
        checks = f"checks:{table.fullname}"
        if (tuple(row[0] for row in expected[columns]) != tuple(table.columns.keys())
                or len(expected[checks]) != sum(isinstance(key, CheckConstraint) for key in table.constraints)
                or any(len(row) != 1 or type(row[0]) is not str for row in expected[checks])):
            return Failure.INCOMPLETE_VISIBILITY
        if expected[columns] != rows[columns] or set(expected[checks]) != set(rows[checks]):
            return Failure.SUCCESSOR_CATALOG_MISMATCH
    return None


def _utc(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError
    return value.astimezone(timezone.utc).isoformat()


def _manifest(rows) -> str:
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()


def build_tenant_baseline(tenant_id: UUID, evidence: tuple, lineage: tuple, audit: tuple) -> TenantBaseline | Failure:
    """Reduce trusted snapshot rows using the existing E2 digest and audit verifier."""
    try:
        if any(row.tenant_id != tenant_id for rows in (evidence, lineage, audit) for row in rows):
            return Failure.INCOMPLETE_VISIBILITY
        entries = tuple(EvidenceDigest(row.id, row.content_sha256, calculate_evidence_hash(
            evidence_type=row.evidence_type, source_type=row.source_type, source_reference=row.source_reference,
            collector_name=row.collector_name, collector_version=row.collector_version,
            trust_level=row.trust_level, payload=row.payload, event_time=row.event_time,
        )) for row in evidence)
        endpoints = {entry.evidence_id for entry in entries}
        relationships = set()
        for row in lineage:
            edge = (row.parent_evidence_id, row.child_evidence_id, row.relationship_type)
            if (edge[0] not in endpoints or edge[1] not in endpoints or edge[0] == edge[1]
                    or edge[2] not in _LINEAGE_RELATIONSHIPS or edge in relationships):
                return Failure.EVIDENCE_BASELINE_MISMATCH
            relationships.add(edge)
        evidence_metadata = _manifest(
            (str(row.id), _utc(row.collected_at), _utc(row.created_at), row.schema_version) for row in evidence
        )
        lineage_sha = _manifest(
            (str(row.parent_evidence_id), str(row.child_evidence_id), row.relationship_type, _utc(row.created_at))
            for row in lineage
        )
        audit_entries = tuple((row.sequence_number, row.entry_hash) for row in audit)
        return TenantBaseline(
            tenant_id, len(entries), entries, evidence_metadata, len(lineage), lineage_sha, len(audit),
            audit_entries, _manifest((row.sequence_number, str(row.id)) for row in audit),
            audit_entries[-1][1] if audit_entries else GENESIS_HASH, verify_audit_chain(list(audit))["valid"],
        )
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return Failure.INCOMPLETE_VISIBILITY


def _history(baseline: Baseline, revision: str) -> Failure | None:
    if baseline.revision != revision or type(baseline.tenants) is not tuple:
        return Failure.INCOMPLETE_VISIBILITY
    tenants = set()
    evidence_ids = set()
    for tenant in baseline.tenants:
        if type(tenant.tenant_id) is not UUID or not tenant.tenant_id.int or tenant.tenant_id in tenants:
            return Failure.INCOMPLETE_VISIBILITY
        tenants.add(tenant.tenant_id)
        if (type(tenant.evidence) is not tuple or type(tenant.evidence_count) is not int
                or tenant.evidence_count != len(tenant.evidence) or type(tenant.lineage_count) is not int
                or tenant.lineage_count < 0 or not _DIGEST.fullmatch(tenant.lineage_sha256)
                or not _DIGEST.fullmatch(tenant.evidence_metadata_sha256)):
            return Failure.EVIDENCE_BASELINE_MISMATCH
        for entry in tenant.evidence:
            if (type(entry.evidence_id) is not UUID or not entry.evidence_id.int or entry.evidence_id in evidence_ids
                    or not _DIGEST.fullmatch(entry.stored_sha256) or entry.stored_sha256 != entry.recomputed_sha256):
                return Failure.EVIDENCE_BASELINE_MISMATCH
            evidence_ids.add(entry.evidence_id)
        if (type(tenant.audit_entries) is not tuple or type(tenant.audit_count) is not int
                or tenant.audit_count != len(tenant.audit_entries) or tenant.audit_verified is not True
                or not _DIGEST.fullmatch(tenant.audit_ids_sha256)
                or any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not int
                       or row[0] != index or not _DIGEST.fullmatch(row[1])
                       for index, row in enumerate(tenant.audit_entries, 1))
                or tenant.audit_head != (tenant.audit_entries[-1][1] if tenant.audit_entries else GENESIS_HASH)):
            return Failure.AUDIT_BASELINE_MISMATCH
    return None


def _validate(target: Target, observed: Observation, successor: bool,
              reference: ExpressionReference | None) -> Failure | None:
    failure = _identity(target, observed.identity, observed.visibility)
    if failure is not None:
        return failure
    revision = plan.STAGED_REVISION if successor else plan.EXPECTED_PREDECESSOR
    if type(observed.revisions) is tuple and len(observed.revisions) > 1:
        return Failure.MULTIPLE_REVISIONS
    if observed.revisions != (revision,):
        return Failure.REVISION_MISMATCH
    if (observed.identity.repeatable_snapshot is not True or observed.visibility.catalog_complete is not True
            or observed.visibility.historical_rows_complete is not True):
        return Failure.INCOMPLETE_VISIBILITY
    authority = observed.authority
    if any(value is False for value in (authority.registry_empty, authority.reserved_audit_absent,
                                        authority.application_isolation_verified)):
        return Failure.AUTHORITY_PRESENT
    if (observed.visibility.authority_rows_complete is not True
            or any(value is not True for value in (authority.registry_empty, authority.reserved_audit_absent,
                                                   authority.application_isolation_verified))):
        return Failure.AUTHORITY_STATE_UNKNOWN
    queries = catalog_queries(successor=successor)
    rows = _items(observed.catalog, (name for name, _, _ in queries))
    replay = _CatalogReplay(rows, queries)
    mismatch = Failure.SUCCESSOR_CATALOG_MISMATCH if successor else Failure.PREDECESSOR_CATALOG_MISMATCH
    if rows["reserved_history"] == ((False,),):
        return Failure.AUTHORITY_PRESENT
    if rows["reserved_history"] != ((True,),):
        return Failure.INCOMPLETE_VISIBILITY
    if rows["shadow_routines"]:
        return Failure.UNEXPECTED_AUTHORITY_ROUTINE
    if not successor and rows["namespace"]:
        return mismatch
    if successor and not any(row[:1] == ("source_registry_reserved_audit_disabled",)
                             for row in rows["audit_triggers"]):
        return Failure.RESERVED_AUDIT_FENCE_MISSING
    lineage_keys = rows["lineage_keys"]
    if (len(lineage_keys) != 2 or {name for name, valid in lineage_keys if valid is True} != {
        "fk_lineage_parent_same_tenant", "fk_lineage_child_same_tenant",
    }):
        return mismatch
    if not plan.verify_legacy_audit(replay, owner=guard.OWNER, staged=successor):
        return Failure.AUDIT_IMMUTABILITY_MISMATCH
    if (set(rows["public_owners"]) != {(name, guard.OWNER) for name in (*guard.APPLICATION_TABLES, "alembic_version")}
            or not plan.verify_predecessor_keys(replay)):
        return mismatch
    if successor:
        failure = _registry(rows, replay, observed, reference)
        if failure is not None:
            return failure
    if observed.baseline.catalog_sha256 != _catalog_sha256(rows):
        return mismatch
    return _history(observed.baseline, revision)


def validate_predecessor(target: Target, observed: Observation) -> Failure | None:
    """None accepts this observation only. It grants no execution authority."""
    try:
        return _validate(target, observed, False, None)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return Failure.INCOMPLETE_VISIBILITY


def validate_successor(target: Target, before: Observation, after: Observation,
                       reference: ExpressionReference | None) -> Failure | None:
    """Validate both snapshots and require unchanged historical manifests."""
    try:
        failure = validate_predecessor(target, before) or _validate(target, after, True, reference)
        if failure is not None:
            return failure
        old = {tenant.tenant_id: tenant for tenant in before.baseline.tenants}
        new = {tenant.tenant_id: tenant for tenant in after.baseline.tenants}
        if old.keys() != new.keys():
            return Failure.EVIDENCE_BASELINE_MISMATCH
        for identity in sorted(old):
            left, right = old[identity], new[identity]
            if ({*left.evidence} != {*right.evidence}
                    or left.evidence_metadata_sha256 != right.evidence_metadata_sha256
                    or (left.lineage_count, left.lineage_sha256) != (right.lineage_count, right.lineage_sha256)):
                return Failure.EVIDENCE_BASELINE_MISMATCH
            if (left.audit_entries, left.audit_head, left.audit_ids_sha256) != (
                right.audit_entries, right.audit_head, right.audit_ids_sha256
            ):
                return Failure.AUDIT_BASELINE_MISMATCH
        return None
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return Failure.INCOMPLETE_VISIBILITY
