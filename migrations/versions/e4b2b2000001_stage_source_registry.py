"""Stage the disabled source-verification registry."""

import hashlib

from alembic import op

from app.database import migration_guard as guard
from app.database import source_registry_migration_plan as plan


revision = "e4b2b2000001"
down_revision = "d93c6e4fb132"
branch_labels = None
depends_on = None
_DDL_SHA256 = "0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4"


def upgrade() -> None:
    active = guard.guarded_environment()
    if active is None:
        raise guard.Denied("guarded_connection_required")
    connection, _, request, _, _ = active
    if op.get_bind() is not connection or (request.predecessor, request.successor) != (down_revision, revision):
        raise guard.Denied("unexpected_upgrade_plan")

    if not plan.verify_predecessor_keys(connection):
        raise guard.Denied("migration_ownership_mismatch")

    statements = plan.compile_disabled_stage()
    if hashlib.sha256("\n".join(statements).encode("utf-8")).hexdigest() != _DDL_SHA256:
        raise guard.Denied("unexpected_upgrade_plan")

    for statement in statements:
        # Bypass text() bind parsing for SQL syntax in static CHECK and JSONPath literals.
        connection.exec_driver_sql(statement)

    if not plan.verify_disabled_catalog(connection, owner=guard.OWNER):
        raise guard.Denied("migration_ownership_mismatch")


def downgrade() -> None:
    raise RuntimeError("source_registry_downgrade_requires_explicit_recovery_plan")
