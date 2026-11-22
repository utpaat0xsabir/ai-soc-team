"""Non-deployable PostgreSQL schema specifications for offline review.

Deliberately outside Alembic and application metadata. A migration must supply
source attestation linkage, append-only enforcement, grants and RLS separately.
"""

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Column, ForeignKey, ForeignKeyConstraint,
    Index, MetaData, String, Table, UniqueConstraint, Uuid,
)
from sqlalchemy.dialects.postgresql import OID, TIMESTAMP

from app.database.models import AuditLog, EvidenceRecord, Tenant


_SCHEMA = "classification_registry"
_METADATA = MetaData(info={"deployment_ready": False})
for model in (Tenant, EvidenceRecord, AuditLog):
    model.__table__.to_metadata(_METADATA, schema="public")

AUDIT = _METADATA.tables["public.audit_logs"]


def _id(name, *, primary_key=False):
    return Column(name, Uuid(), primary_key=primary_key, nullable=False)


def _tenant():
    return Column("tenant_id", Uuid(), ForeignKey("public.tenants.id", ondelete="RESTRICT"),
                  primary_key=True)


def _time(name, *, nullable=False):
    return Column(name, TIMESTAMP(timezone=True, precision=6), nullable=nullable)


def _digest(name):
    return (
        Column(name, String(64), nullable=False),
        CheckConstraint(f"{name} ~ '^[0-9a-f]{{64}}$'"),
    )


def _audit_link(name):
    return (
        ForeignKeyConstraint(["tenant_id", name], ["public.audit_logs.tenant_id",
                                                   "public.audit_logs.sequence_number"], ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", name),
        CheckConstraint(f"{name} > 0"),
    )


def _reference(table, *columns):
    return [f"{_SCHEMA}.{table}.{column}" for column in columns]


SCOPES = Table(
    "classification_issuer_scopes", _METADATA,
    _tenant(), _id("scope_id", primary_key=True), _id("principal_id"),
    Column("database_login", String(63), nullable=False),
    Column("database_role_oid", OID, nullable=False),
    Column("authority_id", String(64), nullable=False),
    _id("source_id"), _id("enrollment_approval_id"),
    Column("enrollment_audit_sequence", BigInteger, nullable=False),
    _time("suspended_at", nullable=True),
    Column("suspension_audit_sequence", BigInteger),
    *_audit_link("enrollment_audit_sequence"), *_audit_link("suspension_audit_sequence"),
    UniqueConstraint("tenant_id", "scope_id", "principal_id", "authority_id"),
    CheckConstraint("database_role_oid <> 0"),
    CheckConstraint("database_login ~ '^[a-z_][a-z0-9_]*$'"),
    CheckConstraint("(suspended_at IS NULL) = (suspension_audit_sequence IS NULL)"),
    CheckConstraint("suspended_at IS NULL OR (isfinite(suspended_at) "
                    "AND suspension_audit_sequence > enrollment_audit_sequence)"),
    schema=_SCHEMA, info={"mutation_contract": "immutable identity; suspension once"},
)
Index("uq_classification_active_issuer_login", SCOPES.c.database_login, unique=True,
      postgresql_where=SCOPES.c.suspended_at.is_(None))
Index("uq_classification_active_issuer_oid", SCOPES.c.database_role_oid, unique=True,
      postgresql_where=SCOPES.c.suspended_at.is_(None))

POLICIES = Table(
    "classification_policy_activations", _METADATA,
    _tenant(), Column("policy_id", String(64), primary_key=True),
    Column("generation", BigInteger, primary_key=True),
    *_digest("policy_sha256"), Column("active", Boolean, nullable=False),
    _id("approval_id"), _time("activated_at"), Column("audit_sequence", BigInteger, nullable=False),
    *_audit_link("audit_sequence"),
    UniqueConstraint("tenant_id", "policy_id", "generation", "policy_sha256"),
    CheckConstraint("generation > 0"), CheckConstraint("isfinite(activated_at)"),
    schema=_SCHEMA, info={"mutation_contract": "append only; generation increases under tenant lock"},
)

DECISIONS = Table(
    "evidence_classification_decisions", _METADATA,
    _tenant(), _id("decision_id", primary_key=True), _id("evidence_id"),
    *_digest("content_sha256"), Column("record_domain", String(64), nullable=False),
    Column("schema_version", String(8), nullable=False),
    Column("classification", String(24), nullable=False),
    Column("authority_id", String(64), nullable=False),
    Column("evaluator_policy_version", String(8), nullable=False),
    _id("issuer_scope_id"), _id("issuer_principal_id"), _id("requester_principal_id"),
    Column("policy_id", String(64), nullable=False), Column("policy_generation", BigInteger, nullable=False),
    *_digest("policy_sha256"), _id("source_verification_id"),
    _time("issued_at"), _time("expires_at"), _id("request_id"),
    *_digest("issuance_sha256"), *_digest("request_sha256"),
    Column("audit_sequence", BigInteger, nullable=False),
    *_audit_link("audit_sequence"),
    ForeignKeyConstraint(["tenant_id", "evidence_id"], ["public.evidence_records.tenant_id",
                                                       "public.evidence_records.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(
        ["tenant_id", "issuer_scope_id", "issuer_principal_id", "authority_id"],
        _reference(SCOPES.name, "tenant_id", "scope_id", "principal_id", "authority_id"), ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "policy_id", "policy_generation", "policy_sha256"],
        _reference(POLICIES.name, "tenant_id", "policy_id", "generation", "policy_sha256"), ondelete="RESTRICT",
    ),
    UniqueConstraint("tenant_id", "requester_principal_id", "request_id"),
    UniqueConstraint("tenant_id", "evidence_id", "content_sha256", "policy_id", "policy_generation"),
    CheckConstraint("record_domain = 'ai-soc-team.evidence-classification' AND schema_version = '1.0'"),
    CheckConstraint("classification = 'OBSERVED' AND evaluator_policy_version = '1'"),
    CheckConstraint("policy_generation > 0"),
    CheckConstraint("isfinite(issued_at) AND isfinite(expires_at) AND issued_at < expires_at"),
    schema=_SCHEMA,
    info={"mutation_contract": "append only", "unresolved_dependency": "source_verification_authority"},
)
Index("ix_classification_evidence_history", DECISIONS.c.tenant_id, DECISIONS.c.evidence_id,
      DECISIONS.c.issued_at.desc(), DECISIONS.c.decision_id)

REVOCATIONS = Table(
    "evidence_classification_revocations", _METADATA,
    _tenant(), _id("decision_id", primary_key=True), _id("revoker_principal_id"), _id("request_id"),
    *_digest("request_sha256"), _time("revoked_at"), Column("reason_code", String(64), nullable=False),
    Column("audit_sequence", BigInteger, nullable=False),
    *_audit_link("audit_sequence"),
    ForeignKeyConstraint(["tenant_id", "decision_id"], _reference(DECISIONS.name, "tenant_id", "decision_id"),
                         ondelete="RESTRICT"),
    UniqueConstraint("tenant_id", "revoker_principal_id", "request_id"),
    CheckConstraint("isfinite(revoked_at)"),
    CheckConstraint("reason_code ~ '^[A-Z][A-Z0-9_]*$'"),
    schema=_SCHEMA, info={"mutation_contract": "append only; permanent revocation"},
)
