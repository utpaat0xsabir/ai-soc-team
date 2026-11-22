"""Inert PostgreSQL schema specifications. No DDL or authority is installed.

Deployment still requires protected login enrollment, global origin claiming,
RLS, reserved audit actions, and database enforcement of history transitions.
"""

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Column, Computed, ForeignKeyConstraint, Index,
    MetaData, String, Table, UniqueConstraint, Uuid, text,
)
from sqlalchemy.dialects.postgresql import JSONB, OID, TIMESTAMP
from sqlalchemy.types import UserDefinedType

from app.database.models import AuditLog, EvidenceRecord, Tenant, WazuhIntegration


_SCHEMA = "source_registry"
_METADATA = MetaData(info={"deployment_ready": False})
for model in (Tenant, EvidenceRecord, AuditLog, WazuhIntegration):
    model.__table__.to_metadata(_METADATA, schema="public")
AUDIT = _METADATA.tables["public.audit_logs"]

# Keep public evidence identity separate from content integrity verification.
EVIDENCE_KEY = ("tenant_id", "evidence_id", "content_sha256")
SOURCE_KEY = ("tenant_id", "source_scope_id", "integration_id")
CONFIG_KEY = ("tenant_id", "source_scope_id", "generation", "config_sha256")
RECEIPT_BINDING = (*EVIDENCE_KEY, "source_scope_id", "integration_id", "generation",
                   "config_sha256", "collector_principal_id", "origin_sha256", "receipt_sha256", "receipt_id")
CLASSIFICATION_TARGET = ("tenant_id", "attestation_id", "evidence_id", "content_sha256")


def _id(name, *, pk=False):
    return Column(name, Uuid(), primary_key=pk, nullable=False)


def _text(name, length=64):
    return Column(name, String(length, collation="C"), nullable=False)


def _time(name, *, nullable=False):
    return Column(name, TIMESTAMP(timezone=True, precision=6), nullable=nullable)


def _sequence(name="audit_sequence", *, nullable=False):
    return Column(name, BigInteger, nullable=nullable)


def _digest(name):
    return _text(name), CheckConstraint(f"{name} ~ '^[0-9a-f]{{64}}$'")


def _fk(local, table, remote):
    return ForeignKeyConstraint(local, [f"{table}.{key}" for key in remote], ondelete="RESTRICT")


def _audit(name="audit_sequence"):
    return (
        _fk(("tenant_id", name), "public.audit_logs", ("tenant_id", "sequence_number")),
        CheckConstraint(f"{name} > 0"), UniqueConstraint("tenant_id", name),
    )


def _table(name, *fields, mutation):
    table = Table(name, _METADATA, *fields, schema=_SCHEMA, info={"mutation_contract": mutation})
    for column in table.columns:
        if isinstance(column.type, Uuid):
            table.append_constraint(CheckConstraint(
                f"{column.name} <> '00000000-0000-0000-0000-000000000000'::uuid"
            ))
    return table


INSTALLATIONS = _table(
    "source_installations",
    _id("installation_id", pk=True), _id("tenant_id"), _text("canonical_enrollment_identity", 256),
    _id("identity_proof_id"), *_digest("identity_proof_sha256"), _id("enrollment_authority_id"),
    _id("approval_id"), _time("enrolled_at"), _sequence(), *_audit(),
    _fk(("tenant_id",), "public.tenants", ("id",)),
    UniqueConstraint("canonical_enrollment_identity"), UniqueConstraint("tenant_id", "installation_id"),
    CheckConstraint("length(canonical_enrollment_identity) > 0 AND isfinite(enrolled_at)"),
    mutation="permanent global ownership; no transfer; protected enrollment proof required",
)

SCOPES = _table(
    "source_scopes",
    _id("tenant_id", pk=True), _id("source_scope_id", pk=True), _id("installation_id"), _id("integration_id"),
    _id("collector_principal_id"), _id("collector_scope_id"), _id("enrollment_authority_id"), _id("approval_id"),
    _time("enrolled_at"), _sequence(), _time("suspended_at", nullable=True),
    _sequence("suspension_audit_sequence", nullable=True), *_audit(), *_audit("suspension_audit_sequence"),
    _fk(("tenant_id", "installation_id"), INSTALLATIONS.fullname, ("tenant_id", "installation_id")),
    _fk(("tenant_id", "integration_id"), "public.wazuh_integrations", ("tenant_id", "id")),
    UniqueConstraint(*SOURCE_KEY),
    UniqueConstraint(*SOURCE_KEY, "installation_id", "collector_principal_id", "collector_scope_id"),
    CheckConstraint("isfinite(enrolled_at)"),
    CheckConstraint("(suspended_at IS NULL) = (suspension_audit_sequence IS NULL)"),
    CheckConstraint("suspended_at IS NULL OR (isfinite(suspended_at) AND suspended_at >= enrolled_at "
                    "AND suspension_audit_sequence > audit_sequence)"),
    mutation="immutable enrollment; suspension once through protected operation",
)
Index("uq_source_active_installation", SCOPES.c.installation_id, unique=True,
      postgresql_where=SCOPES.c.suspended_at.is_(None))

CONFIGURATIONS = _table(
    "source_config_activations",
    _id("tenant_id", pk=True), _id("source_scope_id", pk=True), _id("integration_id"), _id("installation_id"),
    Column("generation", BigInteger, primary_key=True), *_digest("config_sha256"),
    _text("normalization"), _text("normalization_version"), _text("collector_build"),
    _id("collector_principal_id"), _id("collector_scope_id"), _text("collector_database_login", 63),
    _id("credential_epoch_id"), Column("approved_index_uuids", JSONB, nullable=False),
    _text("mode"), Column("active", Boolean, nullable=False),
    _id("approval_id"), _time("activated_at"), _sequence(), *_audit(),
    _fk((*SOURCE_KEY, "installation_id", "collector_principal_id", "collector_scope_id"), SCOPES.fullname,
        (*SOURCE_KEY, "installation_id", "collector_principal_id", "collector_scope_id")),
    UniqueConstraint(*CONFIG_KEY),
    CheckConstraint("generation > 0 AND mode = 'DEDICATED' AND isfinite(activated_at)"),
    # JSONB object keys represent the set, with true as the only allowed value.
    CheckConstraint("jsonb_typeof(approved_index_uuids) = 'object' AND "
                    "jsonb_array_length(jsonb_path_query_array(approved_index_uuids, '$.keyvalue()')) "
                    "BETWEEN 1 AND 64 AND NOT jsonb_path_exists(approved_index_uuids, "
                    "'$.keyvalue() ? (!(@.key like_regex \"^[A-Za-z0-9_-]{21}[AQgw]$\") "
                    "|| @.value.type() != \"boolean\" || @.value == false)')"),
    mutation="append only; generation increases under tenant lock",
)


def _evidence_fk():
    return _fk(("tenant_id", "evidence_id"), "public.evidence_records", ("tenant_id", "id"))


RECEIPTS = _table(
    "source_collection_receipts",
    _id("tenant_id", pk=True), _id("receipt_id", pk=True), _id("evidence_id"), *_digest("content_sha256"),
    _id("source_scope_id"), _id("integration_id"), _id("installation_id"),
    Column("generation", BigInteger, nullable=False), *_digest("config_sha256"),
    _id("collector_principal_id"), _id("collector_scope_id"),
    _text("locator_schema_version", 8), _text("index_uuid", 22), _text("document_id", 512),
    Column("event_revision", BigInteger),
    *_digest("origin_sha256"), *_digest("receipt_sha256"), *_digest("request_sha256"),
    _text("record_domain"), _text("schema_version", 8), _time("collected_at"), _id("request_id"),
    _sequence(), *_audit(), _evidence_fk(),
    _fk((*SOURCE_KEY, "installation_id", "collector_principal_id", "collector_scope_id"), SCOPES.fullname,
        (*SOURCE_KEY, "installation_id", "collector_principal_id", "collector_scope_id")),
    _fk(CONFIG_KEY, CONFIGURATIONS.fullname, CONFIG_KEY),
    UniqueConstraint("installation_id", "index_uuid", "document_id", name="uq_source_global_origin"),
    UniqueConstraint("tenant_id", "collector_principal_id", "request_id"), UniqueConstraint(*RECEIPT_BINDING),
    CheckConstraint("record_domain = 'ai-soc-team.source-collection-receipt' AND schema_version = '1.0' "
                    "AND locator_schema_version = '1.0'"),
    CheckConstraint("index_uuid ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND document_id ~ '^[A-Za-z0-9_.:-]+$' "
                    "AND document_id NOT IN ('.', '..') AND event_revision >= 0"),
    CheckConstraint("generation > 0 AND isfinite(collected_at)"),
    mutation="append only; authoritative global origin claim required",
)
Index("ix_source_receipt_history", RECEIPTS.c.tenant_id, RECEIPTS.c.evidence_id,
      RECEIPTS.c.collected_at.desc(), RECEIPTS.c.receipt_id)
ENROLLMENTS = _table(
    "source_workload_enrollments",
    _id("tenant_id", pk=True), _id("enrollment_id", pk=True), _id("source_scope_id"),
    _id("principal_id"), _id("workload_scope_id"), _text("database_login", 63),
    Column("database_role_oid", OID, nullable=False), _id("credential_epoch_id"),
    _text("action"), _id("approval_id"), _time("enrolled_at"),
    _time("terminated_at", nullable=True),
    Column("verification_method", String(64, collation="C")),
    Column("verification_version", String(64, collation="C")),
    _fk(("tenant_id", "source_scope_id"), SCOPES.fullname, ("tenant_id", "source_scope_id")),
    UniqueConstraint("tenant_id", "source_scope_id", "enrollment_id", "principal_id", "workload_scope_id",
                     "database_role_oid", "credential_epoch_id", "action"),
    CheckConstraint("action IN ('collect', 'publish_retrieval', 'attest', 'revoke')"),
    CheckConstraint("database_role_oid <> 0 AND database_login ~ '^[a-z_][a-z0-9_]*$'"),
    CheckConstraint("(verification_method IS NULL) = (verification_version IS NULL)"),
    CheckConstraint("action NOT IN ('publish_retrieval', 'attest') OR verification_method IS NOT NULL"),
    CheckConstraint("isfinite(enrolled_at) AND (terminated_at IS NULL OR "
                    "(isfinite(terminated_at) AND terminated_at >= enrolled_at))"),
    mutation="immutable enrollment; termination once; no authentication from a row alone",
)
for identity in ("principal_id", "workload_scope_id", "database_role_oid", "database_login"):
    Index(f"uq_source_active_enrollment_{identity}", ENROLLMENTS.c.tenant_id, ENROLLMENTS.c.source_scope_id,
          ENROLLMENTS.c[identity], unique=True, postgresql_where=ENROLLMENTS.c.terminated_at.is_(None))


def _enrollment(prefix):
    identity = ("enrollment_id", "principal_id", "workload_scope_id", "database_role_oid",
                "credential_epoch_id", "action")
    return (
        _id(f"{prefix}_enrollment_id"), _id(f"{prefix}_principal_id"), _id(f"{prefix}_workload_scope_id"),
        Column(f"{prefix}_database_role_oid", OID, nullable=False), _id(f"{prefix}_credential_epoch_id"),
        _text(f"{prefix}_action"),
        _fk(("tenant_id", "source_scope_id", *(f"{prefix}_{key}" for key in identity)), ENROLLMENTS.fullname,
            ("tenant_id", "source_scope_id", *identity)),
    )


LOCATOR_KEY = ("installation_id", "index_uuid", "document_id", "locator_revision_key")
RECEIPTS.append_column(Column("locator_revision_key", BigInteger,
                              Computed("COALESCE(event_revision, -1)", persisted=True), nullable=False))
RECEIPTS.append_constraint(UniqueConstraint(*(RECEIPT_BINDING + LOCATOR_KEY), name="uq_source_receipt_locator"))
ATTEMPT_BINDING = (
    "tenant_id", "retrieval_attempt_id", "source_scope_id", "receipt_id", "requester_principal_id", "request_id",
    "request_sha256", "retrieval_attempt_sha256", "attestor_principal_id", "attestor_scope_id",
    "verification_method", "verification_version",
)
ATTEMPTS = _table(
    "source_retrieval_attempts",
    _id("tenant_id", pk=True), _id("attempt_id", pk=True), _id("source_scope_id"), _id("integration_id"),
    _id("receipt_id"), *_digest("receipt_sha256"), _id("evidence_id"), *_digest("content_sha256"),
    _id("installation_id"), _text("index_uuid", 22), _text("document_id", 512),
    Column("event_revision", BigInteger),
    Column("locator_revision_key", BigInteger, Computed("COALESCE(event_revision, -1)", persisted=True), nullable=False),
    Column("generation", BigInteger, nullable=False), *_digest("config_sha256"),
    _id("collector_principal_id"), *_digest("origin_sha256"),
    *_enrollment("publisher"), *_enrollment("attestor"),
    _text("verification_method"), _text("verification_version"), _time("started_at"), _time("completed_at"),
    *_digest("result_sha256"), *_digest("retrieval_attempt_sha256"), *_digest("request_sha256"),
    _id("requester_principal_id"), _id("request_id"),
    _fk(RECEIPT_BINDING + LOCATOR_KEY, RECEIPTS.fullname, RECEIPT_BINDING + LOCATOR_KEY),
    _fk(CONFIG_KEY, CONFIGURATIONS.fullname, CONFIG_KEY),
    UniqueConstraint(*("attempt_id" if key == "retrieval_attempt_id" else
                       "attestor_workload_scope_id" if key == "attestor_scope_id" else key
                       for key in ATTEMPT_BINDING), name="uq_source_attempt_attestation"),
    CheckConstraint("event_revision IS NULL OR event_revision >= 0"),
    CheckConstraint("publisher_action = 'publish_retrieval' AND attestor_action = 'attest'"),
    CheckConstraint("publisher_principal_id <> attestor_principal_id AND "
                    "publisher_principal_id <> collector_principal_id AND attestor_principal_id <> collector_principal_id "
                    "AND publisher_database_role_oid <> attestor_database_role_oid "
                    "AND publisher_workload_scope_id <> attestor_workload_scope_id"),
    CheckConstraint("isfinite(started_at) AND isfinite(completed_at) AND started_at <= completed_at"),
    mutation="immutable independently published attempt; caller MATCH is never authority",
)


ATTESTATIONS = _table(
    "source_verification_attestations",
    _id("tenant_id", pk=True), _id("attestation_id", pk=True), _id("evidence_id"), *_digest("content_sha256"),
    _id("receipt_id"), *_digest("receipt_sha256"), _id("source_scope_id"), _id("integration_id"),
    _id("collector_principal_id"), _id("attestor_principal_id"), _id("attestor_scope_id"),
    _text("verification_method"), _text("verification_version"),
    Column("generation", BigInteger, nullable=False), *_digest("config_sha256"), *_digest("origin_sha256"),
    _time("verified_at"), _time("expires_at"), _id("requester_principal_id"), _id("request_id"),
    _text("record_domain"), _text("schema_version", 8),
    *_digest("attestation_sha256"), *_digest("request_sha256"),
    _id("retrieval_attempt_id"), *_digest("retrieval_attempt_sha256"), _sequence(), *_audit(), _evidence_fk(),
    _fk(SOURCE_KEY, SCOPES.fullname, SOURCE_KEY),
    _fk(CONFIG_KEY, CONFIGURATIONS.fullname, CONFIG_KEY),
    _fk(RECEIPT_BINDING, RECEIPTS.fullname, RECEIPT_BINDING),
    _fk(ATTEMPT_BINDING, ATTEMPTS.fullname,
        tuple("attempt_id" if key == "retrieval_attempt_id" else
              "attestor_workload_scope_id" if key == "attestor_scope_id" else key for key in ATTEMPT_BINDING)),
    UniqueConstraint(*CLASSIFICATION_TARGET),
    UniqueConstraint("tenant_id", "requester_principal_id", "request_id"),
    UniqueConstraint("tenant_id", "retrieval_attempt_id"),
    UniqueConstraint(*EVIDENCE_KEY, "source_scope_id", "generation"),
    CheckConstraint("record_domain = 'ai-soc-team.source-verification-attestation' AND schema_version = '1.0'"),
    CheckConstraint("collector_principal_id <> attestor_principal_id AND generation > 0"),
    CheckConstraint("isfinite(verified_at) AND isfinite(expires_at) AND verified_at < expires_at"),
    mutation="append only; protected attestor enrollment, retrieval provenance and audit required",
)
Index("ix_source_attestation_history", ATTESTATIONS.c.tenant_id, ATTESTATIONS.c.evidence_id,
      ATTESTATIONS.c.verified_at.desc(), ATTESTATIONS.c.attestation_id)

REVOCATIONS = _table(
    "source_verification_revocations",
    _id("tenant_id", pk=True), _id("attestation_id", pk=True), _id("revoker_principal_id"), _id("request_id"),
    *_digest("request_sha256"), _time("revoked_at"), _text("reason_code"), _sequence(), *_audit(),
    _fk(("tenant_id", "attestation_id"), ATTESTATIONS.fullname, ("tenant_id", "attestation_id")),
    UniqueConstraint("tenant_id", "revoker_principal_id", "request_id"),
    CheckConstraint("isfinite(revoked_at) AND reason_code ~ '^[A-Z][A-Z0-9_]*$'"),
    mutation="append only; permanent",
)


RESERVED_ACTIONS = (
    "installation_enroll", "scope_enroll", "config_activate", "receipt",
    "attest", "revoke", "scope_suspend",
)


class _TransactionId(UserDefinedType):
    cache_ok = True

    def get_col_spec(self, **kwargs):
        return "xid8"


AUDIT_BINDINGS = _table(
    "source_audit_bindings",
    _id("tenant_id", pk=True), _id("operation_id", pk=True), _text("database_login", 63),
    Column("database_role_oid", OID, nullable=False), _id("actor_principal_id"),
    _text("action"), _text("resource_type"), _id("resource_id"), _id("request_id"),
    *_digest("request_sha256"), *_digest("record_sha256"),
    Column("retrieval_attempt_sha256", String(64, collation="C")),
    Column("server_xid", _TransactionId(), nullable=False, server_default=text("pg_catalog.pg_current_xact_id()")),
    Column("approval_id", Uuid()), _sequence(nullable=True), *_audit(),
    _fk(("tenant_id",), "public.tenants", ("id",)),
    UniqueConstraint("tenant_id", "actor_principal_id", "action", "request_id"),
    CheckConstraint("database_role_oid <> 0 AND database_login ~ '^[a-z_][a-z0-9_]*$'"),
    CheckConstraint("action IN (" + ", ".join(f"'source_authority.{action}'" for action in RESERVED_ACTIONS) + ")"),
    CheckConstraint("(action = 'source_authority.attest') = (retrieval_attempt_sha256 IS NOT NULL)"),
    CheckConstraint("retrieval_attempt_sha256 ~ '^[0-9a-f]{64}$'"),
    CheckConstraint("action NOT IN ('source_authority.installation_enroll', 'source_authority.scope_enroll', "
                    "'source_authority.config_activate', 'source_authority.scope_suspend') OR approval_id IS NOT NULL"),
    mutation="staged without preparation or pairing writer; all changes denied",
)
