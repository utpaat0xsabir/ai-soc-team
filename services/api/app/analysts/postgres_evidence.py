"""Read tenant-scoped evidence with a caller-owned restricted PostgreSQL session."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Text, case, cast, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.analysts import contracts
from app.analysts.evidence_adapter import (
    EvidenceRejected,
    VerifiedStoredEvidence,
    _checked_evidence_ids,
    validate_stored_evidence,
)
from app.database.models import EvidenceRecord


_READER_IS_RESTRICTED = text("""
    SELECT EXISTS (
        SELECT FROM pg_catalog.pg_roles
        WHERE rolname = session_user AND session_user = current_user
          AND rolname = :login AND rolcanlogin
          AND NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
    )
""")


@dataclass(frozen=True)
class PostgresEvidenceRepository:
    """Uses the supplied transaction. No default engine, autoflush, commit, or retry."""

    session: Session

    def load_stored_bundle(
        self, tenant_id: UUID, evidence_ids: tuple[UUID, ...],
    ) -> tuple[VerifiedStoredEvidence, ...]:
        if type(tenant_id) is not UUID or not tenant_id.int:
            raise EvidenceRejected("INVALID_CONTEXT")
        ids = _checked_evidence_ids(evidence_ids)

        columns = EvidenceRecord.__table__.c
        bounded_payload = case(
            (func.pg_catalog.octet_length(cast(columns.payload, Text)) <= contracts.MAX_INPUT_BYTES,
             columns.payload),
            else_=None,
        ).label("payload")
        statement = select(
            columns.id.label("evidence_id"), columns.tenant_id, columns.evidence_type,
            columns.source_type, columns.source_reference, columns.collector_name,
            columns.collector_version, columns.trust_level, columns.schema_version,
            columns.event_time, columns.collected_at, columns.content_sha256, bounded_payload,
        ).where(
            columns.tenant_id == tenant_id, columns.id.in_(ids),
        ).order_by(columns.id).limit(len(ids))

        try:
            bind = self.session.get_bind()
            if bind.dialect.name != "postgresql":
                raise EvidenceRejected("UNSAFE_EVIDENCE_SESSION")
            login = bind.engine.url.username
            if not login or login in ("ai_soc", "postgres"):
                raise EvidenceRejected("UNSAFE_EVIDENCE_SESSION")
            connection = self.session.connection(bind_arguments={"bind": bind})
            if connection.execute(_READER_IS_RESTRICTED, {"login": login}).scalar_one() is not True:
                raise EvidenceRejected("UNSAFE_EVIDENCE_SESSION")
            # Execution-level options take precedence over the caller's schema map.
            result = connection.execute(
                statement, execution_options={"schema_translate_map": {None: "public"}},
            )
            rows = result.mappings().fetchmany(len(ids) + 1)
        except SQLAlchemyError:
            raise EvidenceRejected("EVIDENCE_LOOKUP_FAILED") from None

        by_id = {row["evidence_id"]: row for row in rows}
        if (len(rows) != len(ids) or set(by_id) != set(ids)
                or any(row["tenant_id"] != tenant_id for row in rows)):
            raise EvidenceRejected("EVIDENCE_NOT_FOUND")

        bundle = []
        size = 0
        for key in ids:
            record = validate_stored_evidence(by_id[key])
            size += len(record.model_dump_json().encode("utf-8"))
            if size > contracts.MAX_INPUT_BYTES:
                raise EvidenceRejected("EVIDENCE_BUNDLE_TOO_LARGE")
            bundle.append(record)
        return tuple(bundle)
