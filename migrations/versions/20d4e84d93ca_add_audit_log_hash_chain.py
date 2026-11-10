
"""add audit log hash chain

Revision ID: 20d4e84d93ca
Revises: 211e576b1806
"""

import hashlib
import json
from datetime import timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20d4e84d93ca"
down_revision: Union[str, Sequence[str], None] = "211e576b1806"
branch_labels = None
depends_on = None


GENESIS_HASH = "0" * 64


def calculate_migration_hash(
    *,
    tenant_id,
    sequence_number,
    previous_hash,
    actor_type,
    actor_id,
    action,
    resource_type,
    resource_id,
    details,
    created_at,
):
    canonical_data = {
        "tenant_id": str(tenant_id),
        "sequence_number": sequence_number,
        "previous_hash": previous_hash,
        "actor_type": actor_type,
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id else None,
        "details": details,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
    }

    serialized = json.dumps(
        canonical_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(serialized).hexdigest()


def upgrade() -> None:
    # Temporarily remove the append-only trigger for the backfill.
    op.execute(
        "DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs"
    )

    # Add nullable columns first so existing records can be populated.
    op.add_column(
        "audit_logs",
        sa.Column("sequence_number", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("entry_hash", sa.String(length=64), nullable=True),
    )

    connection = op.get_bind()

    records = connection.execute(
        sa.text(
            """
            SELECT
                id,
                tenant_id,
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                details,
                created_at
            FROM audit_logs
            ORDER BY tenant_id, created_at, id
            """
        )
    ).mappings()

    current_tenant = None
    sequence_number = 0
    previous_hash = GENESIS_HASH

    for record in records:
        if record["tenant_id"] != current_tenant:
            current_tenant = record["tenant_id"]
            sequence_number = 0
            previous_hash = GENESIS_HASH

        sequence_number += 1

        entry_hash = calculate_migration_hash(
            tenant_id=record["tenant_id"],
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            actor_type=record["actor_type"],
            actor_id=record["actor_id"],
            action=record["action"],
            resource_type=record["resource_type"],
            resource_id=record["resource_id"],
            details=record["details"],
            created_at=record["created_at"],
        )

        connection.execute(
            sa.text(
                """
                UPDATE audit_logs
                SET
                    sequence_number = :sequence_number,
                    previous_hash = :previous_hash,
                    entry_hash = :entry_hash
                WHERE id = :id
                """
            ),
            {
                "id": record["id"],
                "sequence_number": sequence_number,
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
            },
        )

        previous_hash = entry_hash

    # Enforce the new fields after backfill.
    op.alter_column(
        "audit_logs",
        "sequence_number",
        existing_type=sa.BigInteger(),
        nullable=False,
    )
    op.alter_column(
        "audit_logs",
        "entry_hash",
        existing_type=sa.String(length=64),
        nullable=False,
    )

    op.create_unique_constraint(
        "uq_audit_tenant_sequence",
        "audit_logs",
        ["tenant_id", "sequence_number"],
    )

    op.create_check_constraint(
        "ck_audit_sequence_positive",
        "audit_logs",
        "sequence_number > 0",
    )

    op.create_check_constraint(
        "ck_audit_entry_hash_length",
        "audit_logs",
        "length(entry_hash) = 64",
    )

    op.create_check_constraint(
        "ck_audit_previous_hash_length",
        "audit_logs",
        "previous_hash IS NULL OR length(previous_hash) = 64",
    )

    # Restore append-only protection.
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE OR TRUNCATE
        ON audit_logs
        FOR EACH STATEMENT
        EXECUTE FUNCTION prevent_audit_log_mutation();
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs"
    )

    op.drop_constraint(
        "ck_audit_previous_hash_length",
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        "ck_audit_entry_hash_length",
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        "ck_audit_sequence_positive",
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        "uq_audit_tenant_sequence",
        "audit_logs",
        type_="unique",
    )

    op.drop_column("audit_logs", "entry_hash")
    op.drop_column("audit_logs", "previous_hash")
    op.drop_column("audit_logs", "sequence_number")

    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE OR TRUNCATE
        ON audit_logs
        FOR EACH STATEMENT
        EXECUTE FUNCTION prevent_audit_log_mutation();
        """
    )
