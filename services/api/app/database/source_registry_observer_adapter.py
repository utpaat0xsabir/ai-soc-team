"""Restricted B4 capture on a caller-owned PostgreSQL transaction.

Approval values come from a trusted operator channel. Capturing observations
and accepting observations grant no execution or source authority.
"""
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import IPv4Address
import json
from pathlib import Path
import re
from types import MappingProxyType, SimpleNamespace
from typing import Protocol
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError, TimeoutError

from app.database import migration_guard as guard
from app.database import source_registry_observer as contract
from app.database import source_registry_migration_plan as plan
from app.database.source_registry_artifact import manifest_bytes
from app.database.test_target import docker_postgres_identity


class Connection(Protocol):
    dialect: object
    connection: object
    closed: bool
    invalidated: bool

    def get_transaction(self): ...
    def get_nested_transaction(self): ...
    def execute(self, statement, parameters): ...


@dataclass(frozen=True)
class Rejection:
    code: str


@dataclass(frozen=True)
class ContainerEvidence:
    target: contract.Target


def verify_container(target: contract.Target) -> ContainerEvidence | Rejection:
    """Explicit operator check through the existing Docker target verifier."""
    try:
        pairs = docker_postgres_identity(container_id=target.container_id, local=True)
    except ValueError:
        return Rejection("MISSING_CONTAINER_PIN")
    if pairs != frozenset({target.address_pair}):
        return Rejection("WRONG_CONTAINER")
    return ContainerEvidence(target)


@dataclass(frozen=True)
class Approval:
    """Separately approved pins and budgets. No field authorizes migration."""
    target: contract.Target
    manifest_sha256: str
    application_isolation_sha256: str
    statement_timeout_ms: int
    max_rows_per_query: int
    expression_reference_sha256: str | None = None


@dataclass(frozen=True)
class Snapshot:
    database_oid: int
    backend_pid: int
    transaction_started: datetime
    server_started: datetime
    mvcc_snapshot: str
    timeout_ms: int


@dataclass(frozen=True)
class Capture:
    observation: contract.Observation
    snapshot: Snapshot
    approval: Approval
    evidence_sha256: str


@dataclass(frozen=True)
class EmptinessAttestation:
    database: str
    container_id: str
    endpoint: tuple[str, str, int]
    revision: str
    snapshot: Snapshot
    attestor: str
    generated_at: datetime
    scope: str
    table_counts: tuple[tuple[str, int], ...]
    evidence_sha256: str
    policy_id: str


@dataclass(frozen=True)
class AttestationApproval:
    """Independently verified exact receipt digest and approved freshness policy."""
    sha256: str
    attestor: str
    policy_id: str
    max_age: timedelta


@dataclass(frozen=True)
class Accepted:
    capture: Capture
    attestation_sha256: str | None


@dataclass(frozen=True)
class Query:
    sql: str
    width: int
    minimum: int
    maximum: int | None
    scope: str
    binds: tuple = ()
    successor_only: bool = False


_SNAPSHOT = """
SELECT d.oid::bigint, pg_catalog.pg_backend_pid(), pg_catalog.transaction_timestamp(),
       pg_catalog.pg_postmaster_start_time(), pg_catalog.pg_current_snapshot()::text,
       s.setting::integer
FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_settings s
WHERE d.datname = pg_catalog.current_database()
  AND s.name = 'statement_timeout' AND s.unit = 'ms'
"""
_PRIVILEGES = """
SELECT ARRAY[r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole,
             r.rolreplication, r.rolbypassrls, r.rolinherit],
       pg_catalog.has_database_privilege(r.oid, pg_catalog.current_database(), 'CONNECT'),
       pg_catalog.has_schema_privilege(r.oid, 'public', 'USAGE'),
       pg_catalog.has_column_privilege(r.oid, 'public.alembic_version', 'version_num', 'SELECT'),
       EXISTS (
           SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname NOT IN ('pg_catalog','information_schema')
             AND pg_catalog.has_schema_privilege(r.oid, n.oid, 'USAGE')
             AND pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')
             AND p.prorettype <> 'pg_catalog.trigger'::regtype
       ),
       pg_catalog.pg_get_userbyid(n.nspowner)
FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_namespace n
WHERE r.rolname = session_user AND n.nspname = 'public'
"""
_REVISION_RELATION = """
SELECT c.relkind = 'r' AND c.relpersistence = 'p' AND NOT c.relrowsecurity
       AND NOT c.relhasrules AND NOT c.relhassubclass
       AND a.atttypid = 'pg_catalog.varchar'::regtype
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
WHERE c.oid = pg_catalog.to_regclass('public.alembic_version')
  AND a.attname = 'version_num' AND NOT a.attisdropped
"""
_HISTORY_RELATIONS = """
SELECT c.relname, c.relkind = 'r' AND c.relpersistence = 'p'
       AND NOT c.relrowsecurity AND NOT c.relhasrules AND NOT c.relhassubclass
       AND NOT EXISTS (
           SELECT FROM pg_catalog.pg_attribute a
           WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
             AND a.atttypid NOT IN ('pg_catalog.uuid'::regtype, 'pg_catalog.varchar'::regtype,
                                    'pg_catalog.timestamptz'::regtype, 'pg_catalog.jsonb'::regtype,
                                    'pg_catalog.int8'::regtype)
       )
FROM pg_catalog.pg_class c
WHERE c.relnamespace = 'public'::regnamespace
  AND c.relname IN ('tenants','evidence_records','evidence_lineage','audit_logs')
"""
_ROLES = """
SELECT ARRAY(SELECT oid FROM pg_catalog.pg_roles ORDER BY oid),
       ARRAY(SELECT rolname::text FROM pg_catalog.pg_roles ORDER BY oid),
       ARRAY(SELECT ARRAY[member, roleid, grantor] FROM pg_catalog.pg_auth_members
             ORDER BY member, roleid, grantor),
       ARRAY(SELECT ARRAY[admin_option, inherit_option, set_option] FROM pg_catalog.pg_auth_members
             ORDER BY member, roleid, grantor),
       ARRAY(SELECT oid FROM pg_catalog.pg_roles
             WHERE rolsuper OR rolreplication OR rolbypassrls ORDER BY oid)
"""
_WIDTHS = dict(namespace=2, shadow_routines=2, public_owners=2, keys=2, lineage_keys=2, audit_routine=6,
               audit_triggers=5, audit_mutators=1, reserved_history=1, registry=5, defaults=1,
               tables=6, routines=8, triggers=8, constraints=11, indexes=9, backing_indexes=4,
               columns=8, checks=1)
_SINGLETONS = {"audit_routine", "reserved_history", "registry", "defaults"}
_COMMON_CATALOG = {name for name, _, _ in contract.catalog_queries(successor=False)}
_TABLES = tuple(sorted(table.name for table in plan.TABLES))
_SCOPE = "all_source_registry_tables_without_row_filtering"
_HEX = re.compile(r"[a-f0-9]{64}")


def _queries() -> dict[str, Query]:
    result = {
        "identity": Query(str(contract.IDENTITY_SQL), 14, 1, 1, "session"),
        "snapshot": Query(_SNAPSHOT, 6, 1, 1, "session"),
        "privileges": Query(_PRIVILEGES, 6, 1, 1, "roles"),
        "roles": Query(_ROLES, 5, 1, 1, "roles"),
        "revision_relation": Query(_REVISION_RELATION, 1, 0, 1, "catalog"),
        "revision": Query(str(contract.REVISION_SQL), 1, 0, None, "revision"),
        "history_relations": Query(_HISTORY_RELATIONS, 2, 0, 4, "catalog"),
        "history_visibility": Query(str(contract.HISTORY_VISIBILITY_SQL), 3, 0, 4, "history"),
    }
    widths = {"tenants": 1, "evidence": 14, "lineage": 5, "audit": 12}
    result.update((name, Query(str(sql), widths[name], 0, None, "history"))
                  for name, sql in contract.HISTORY_QUERIES)
    for name, sql, binds in contract.catalog_queries(successor=True):
        kind = name.split(":", 1)[0]
        minimum = int(name in _SINGLETONS)
        maximum = 1 if name in (_SINGLETONS | {"namespace"}) else None
        result[name] = Query(str(sql), _WIDTHS[kind], minimum, maximum, "catalog", binds,
                             name not in _COMMON_CATALOG)
    return result


# The manifest pins both these definitions and the imported query source.
READ_QUERIES = MappingProxyType(_queries())
QUERY_INVENTORY_SHA256 = "03a782227e4bf8cebb5052008f5ec037d51379ec22c622e767f1c8110922193a"


@dataclass(frozen=True)
class _Rejected(Exception):
    code: str


def _deny(code: str | contract.Failure):
    raise _Rejected(code.value if isinstance(code, contract.Failure) else code)


def _freeze(value):
    return tuple(map(_freeze, value)) if isinstance(value, (tuple, list)) else value


def _read(connection: Connection, name: str, *, successor: bool, max_rows: int):
    query = READ_QUERIES.get(name)
    if query is None or (query.successor_only and not successor):
        _deny("UNAPPROVED_QUERY")
    # All bindings come from the fixed query registry. Psycopg adapts a list
    # for PostgreSQL ANY(array), while tuple identifiers stay in the registry.
    params = {key: list(value) if type(value) is tuple else value for key, value in query.binds}
    result = connection.execute(text(query.sql), params)
    try:
        ceiling = min(max_rows, query.maximum) if query.maximum is not None else max_rows
        raw = []
        while len(raw) <= ceiling:
            batch = result.fetchmany(ceiling + 1 - len(raw))
            if not batch:
                break
            raw.extend(batch)
        if not query.minimum <= len(raw) <= ceiling:
            _deny("QUERY_RESULT_SHAPE_MISMATCH")
        rows = tuple(tuple(row) for row in raw)
        if any(len(row) != query.width for row in rows):
            _deny("QUERY_RESULT_SHAPE_MISMATCH")
        return rows
    finally:
        result.close()


def _wire(value):
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            raise ValueError
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (UUID, IPv4Address)):
        return str(value)
    raise TypeError


def _digest(value) -> str:
    encoded = json.dumps(value, default=_wire, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(encoded.encode()).hexdigest()


def attestation_sha256(attestation: EmptinessAttestation) -> str:
    return _digest(("b4-registry-emptiness-v1", asdict(attestation)))


def expression_reference_sha256(reference: contract.ExpressionReference) -> str:
    rows = {key: value if key.startswith("columns:") else sorted(value)
            for key, value in reference.catalog.results}
    if len(rows) != len(reference.catalog.results):
        raise ValueError
    return _digest(("b4-expression-reference-v1", reference.version_num, reference.ddl_sha256, rows))


def _capture_sha256(observation, snapshot, approval) -> str:
    manifests = [asdict(value) for value in sorted(observation.baseline.tenants, key=lambda item: item.tenant_id)]
    return _digest(("b4-observation-v1", approval.manifest_sha256, approval.application_isolation_sha256,
                    approval.target.container_id, approval.target.login, observation.identity.version_num,
                    tuple(map(str, approval.target.address_pair)), asdict(snapshot),
                    asdict(observation.identity), asdict(observation.visibility), asdict(observation.authority),
                    observation.revisions, observation.baseline.catalog_sha256, manifests))


def _snapshot(row, budget: int) -> Snapshot:
    value = Snapshot(*row)
    if (type(value.database_oid) is not int or value.database_oid <= 0
            or type(value.backend_pid) is not int or value.backend_pid <= 0
            or any(type(t) is not datetime or t.utcoffset() is None
                   for t in (value.transaction_started, value.server_started))
            or value.server_started > value.transaction_started
            or type(value.mvcc_snapshot) is not str
            or not re.fullmatch(r"\d+:\d+:(?:\d+(?:,\d+)*)?", value.mvcc_snapshot)):
        _deny("INCONSISTENT_SNAPSHOT")
    if type(value.timeout_ms) is not int or not 0 < value.timeout_ms <= budget:
        _deny("UNAPPROVED_QUERY_TIMEOUT")
    return value


def _history(read):
    tenants = [row[0] for row in read("tenants")]
    if any(type(value) is not UUID or not value.int for value in tenants) or len(set(tenants)) != len(tenants):
        _deny("QUERY_RESULT_SHAPE_MISMATCH")
    fields = {
        "evidence": ("id tenant_id evidence_type source_type source_reference collector_name collector_version "
                     "trust_level payload event_time content_sha256 collected_at created_at schema_version"),
        "lineage": "tenant_id parent_evidence_id child_evidence_id relationship_type created_at",
        "audit": ("id tenant_id sequence_number previous_hash entry_hash actor_type actor_id "
                  "action resource_type resource_id details created_at"),
    }
    observed = set(tenants)
    grouped = {}
    for name, keys in fields.items():
        groups = defaultdict(list)
        for row in read(name):
            item = SimpleNamespace(**dict(zip(keys.split(), row)))
            if type(item.tenant_id) is not UUID or item.tenant_id not in observed:
                _deny("INCOMPLETE_VISIBILITY")
            groups[item.tenant_id].append(item)
        grouped[name] = groups
    result = []
    for tenant in tenants:
        baseline = contract.build_tenant_baseline(
            tenant, *(tuple(grouped[name][tenant]) for name in fields)
        )
        if isinstance(baseline, contract.Failure):
            _deny(baseline)
        result.append(baseline)
    return tuple(result)


def capture(connection: Connection, *, root: Path, approval: Approval,
            container: ContainerEvidence | None, successor: bool) -> Capture | Rejection:
    """Collect complete query results without owning the supplied connection."""
    try:
        if _digest({name: asdict(query) for name, query in READ_QUERIES.items()}) != QUERY_INVENTORY_SHA256:
            _deny("UNAPPROVED_QUERY")
        if type(container) is not ContainerEvidence or not _HEX.fullmatch(approval.target.container_id):
            _deny("MISSING_CONTAINER_PIN")
        if container.target != approval.target:
            _deny("WRONG_CONTAINER")
        try:
            actual_manifest = sha256(manifest_bytes(root)).hexdigest()
        except ValueError:
            _deny("ARTIFACT_MISMATCH")
        if not _HEX.fullmatch(approval.manifest_sha256) or actual_manifest != approval.manifest_sha256:
            _deny("ARTIFACT_MISMATCH")
        if not _HEX.fullmatch(approval.application_isolation_sha256):
            _deny("AUTHORITY_STATE_UNKNOWN")
        if (type(successor) is not bool or type(approval.statement_timeout_ms) is not int
                or approval.statement_timeout_ms < 1 or type(approval.max_rows_per_query) is not int
                or approval.max_rows_per_query < 1):
            _deny("UNAPPROVED_OBSERVATION_POLICY")
        transaction = connection.get_transaction()
        if (connection.closed is not False or connection.invalidated is not False
                or connection.dialect.name != "postgresql" or connection.dialect.driver != "psycopg"
                or transaction is None or transaction.is_active is not True
                or connection.get_nested_transaction() is not None
                or connection.connection.driver_connection.autocommit is not False):
            _deny("CONNECTION_NOT_INDEPENDENTLY_AUTHENTICATED")

        def read(name):
            if (connection.get_transaction() is not transaction or transaction.is_active is not True
                    or connection.get_nested_transaction() is not None or connection.invalidated is not False):
                _deny("INCONSISTENT_SNAPSHOT")
            return _read(connection, name, successor=successor, max_rows=approval.max_rows_per_query)

        identity = contract.identity_from_rows(read("identity"), observed_container_id=container.target.container_id)
        if isinstance(identity, contract.Failure):
            _deny(identity)
        failure = contract._identity(approval.target, identity, contract.Visibility(False, True, False, False))
        if failure is not None:
            _deny(failure)
        if identity.repeatable_snapshot is not True:
            _deny("INCONSISTENT_SNAPSHOT")
        snapshot = _snapshot(read("snapshot")[0], approval.statement_timeout_ms)
        privileges = _freeze(read("privileges")[0])
        if privileges not in (
            ((True, False, False, False, False, False, False), True, True, True, False, guard.OWNER),
            ((True, False, False, False, False, False, False), True, True, True, False, "pg_database_owner"),
        ):
            _deny("PRIVILEGED_OBSERVER")
        roles = _freeze(read("roles")[0])
        if not guard.approved_role_graph(*roles) or identity.session_user not in roles[1]:
            _deny("ROLE_REACHABILITY_UNVERIFIED")
        observer_oid = roles[0][roles[1].index(identity.session_user)]
        if observer_oid in roles[4] or any(observer_oid in grant[:2] for grant in roles[2]):
            _deny("ROLE_REACHABILITY_UNVERIFIED")

        if read("revision_relation") != ((True,),):
            _deny("INCOMPLETE_VISIBILITY")
        revisions = tuple(row[0] for row in read("revision"))
        revision = plan.STAGED_REVISION if successor else plan.EXPECTED_PREDECESSOR
        if len(revisions) > 1:
            _deny("MULTIPLE_REVISIONS")
        if revisions != (revision,):
            _deny("REVISION_MISMATCH")
        relations = read("history_relations")
        if (len(relations) != 4 or {name for name, safe in relations if safe is True}
                != {"tenants", "evidence_records", "evidence_lineage", "audit_logs"}
                or not contract.history_visible(_freeze(read("history_visibility")))):
            _deny("INCOMPLETE_VISIBILITY")
        catalog = contract.Catalog(tuple(
            (name, _freeze(read(name))) for name, _, _ in contract.catalog_queries(successor=successor)
        ))
        catalog_hash = contract.catalog_sha256(catalog, successor=successor)
        catalog_rows = dict(catalog.results)
        absent = catalog_rows["reserved_history"] == ((True,),)
        if not absent:
            _deny("AUTHORITY_PRESENT")
        history = _history(read)
        if (_snapshot(read("snapshot")[0], approval.statement_timeout_ms) != snapshot
                or connection.get_transaction() is not transaction or transaction.is_active is not True):
            _deny("INCONSISTENT_SNAPSHOT")
        baseline = contract.Baseline(revision, catalog_hash, history)
        observation = contract.Observation(
            identity, contract.Visibility(True, True, True, not successor), revisions, catalog, baseline,
            contract.Authority(None if successor else not catalog_rows["namespace"], absent, True),
        )
        if not successor:
            failure = contract.validate_predecessor(approval.target, observation)
            if failure is not None:
                _deny(failure)
        return Capture(observation, snapshot, approval, _capture_sha256(observation, snapshot, approval))
    except _Rejected as exc:
        return Rejection(exc.code)
    except TimeoutError:
        return Rejection("QUERY_TIMEOUT")
    except DBAPIError as exc:
        state = getattr(exc.orig, "sqlstate", None)
        if state in {"57014", "55P03"}:
            return Rejection("QUERY_TIMEOUT")
        if state in {"42501", "42P01", "42703", "3F000"}:
            return Rejection("INCOMPLETE_VISIBILITY")
        return Rejection("QUERY_FAILED")
    except SQLAlchemyError:
        return Rejection("QUERY_FAILED")
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, OSError, OverflowError):
        return Rejection("QUERY_RESULT_SHAPE_MISMATCH")


def accept_predecessor(value: Capture) -> Accepted | Rejection:
    try:
        if _capture_sha256(value.observation, value.snapshot, value.approval) != value.evidence_sha256:
            return Rejection("INCONSISTENT_SNAPSHOT")
    except (AttributeError, TypeError, ValueError):
        return Rejection("INCONSISTENT_SNAPSHOT")
    failure = contract.validate_predecessor(value.approval.target, value.observation)
    if failure is not None:
        return Rejection(failure.value)
    return Accepted(value, None)


def accept_successor(
    before: Capture, after: Capture, *, reference: contract.ExpressionReference | None,
    attestation: EmptinessAttestation | None, attestation_approval: AttestationApproval | None,
    now: datetime,
) -> Accepted | Rejection:
    """Compare independently approved evidence. Never attest to hidden rows here."""
    try:
        approval = before.approval
        if approval != after.approval:
            _deny("ARTIFACT_MISMATCH")
        if (before.snapshot.database_oid != after.snapshot.database_oid
                or before.snapshot.server_started != after.snapshot.server_started
                or before.snapshot.transaction_started >= after.snapshot.transaction_started):
            _deny("INCONSISTENT_SNAPSHOT")
        if (_capture_sha256(before.observation, before.snapshot, approval) != before.evidence_sha256
                or _capture_sha256(after.observation, after.snapshot, approval) != after.evidence_sha256):
            _deny("INCONSISTENT_SNAPSHOT")
        if reference is None or expression_reference_sha256(reference) != approval.expression_reference_sha256:
            _deny("INCOMPLETE_VISIBILITY")
        if attestation is None or attestation_approval is None:
            _deny("MISSING_EMPTINESS_ATTESTATION")
        if (not attestation_approval.attestor or not attestation_approval.policy_id
                or attestation.attestor == approval.target.login
                or attestation.attestor != attestation_approval.attestor
                or attestation.policy_id != attestation_approval.policy_id
                or attestation_sha256(attestation) != attestation_approval.sha256):
            _deny("UNAPPROVED_EMPTINESS_ATTESTATION")
        if (type(attestation_approval.max_age) is not timedelta or attestation_approval.max_age <= timedelta(0)
                or now.utcoffset() is None or attestation.generated_at.utcoffset() is None
                or not after.snapshot.transaction_started <= attestation.generated_at <= now
                or now - attestation.generated_at > attestation_approval.max_age):
            _deny("EMPTINESS_ATTESTATION_FRESHNESS_UNVERIFIED")
        if (attestation.database != guard.TARGET or attestation.container_id != approval.target.container_id
                or attestation.endpoint != (*map(str, approval.target.address_pair), 5432)
                or attestation.revision != plan.STAGED_REVISION or attestation.snapshot != after.snapshot
                or attestation.evidence_sha256 != after.evidence_sha256 or attestation.scope != _SCOPE
                or type(attestation.table_counts) is not tuple
                or any(type(row) is not tuple or len(row) != 2 for row in attestation.table_counts)
                or tuple(name for name, _ in attestation.table_counts) != _TABLES
                or any(type(count) is not int or count < 0 for _, count in attestation.table_counts)):
            _deny("EMPTINESS_ATTESTATION_MISMATCH")
        if any(count for _, count in attestation.table_counts):
            _deny("AUTHORITY_PRESENT")
        observed = replace(
            after.observation, visibility=replace(after.observation.visibility, authority_rows_complete=True),
            authority=replace(after.observation.authority, registry_empty=True),
        )
        failure = contract.validate_successor(approval.target, before.observation, observed, reference)
        if failure is not None:
            _deny(failure)
        return Accepted(after, attestation_approval.sha256)
    except _Rejected as exc:
        return Rejection(exc.code)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return Rejection("INCOMPLETE_VISIBILITY")
