"""Run one approved AI-05B test upgrade with an explicit migration credential.

Inject AI_SOC_MIGRATION_DATABASE_URL into this process only. The operator must
already be authorized to use the dedicated login and the pinned local Docker
container. Possession of a request ID does not grant that authority.
The B4 successor requires a separately authorized transport-aware caller.
"""

import argparse
import json
import os
from pathlib import Path
import re
import sys

from alembic.config import Config

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from app.database import migration_guard as guard  # noqa: E402


DENIAL_CODES = frozenset({
    "ambient_connection_configuration",
    "b4_transport_required",
    "connected_identity_mismatch",
    "docker_identity_changed",
    "guarded_connection_required",
    "guarded_migration_required",
    "invalid_arguments",
    "invalid_container_id",
    "invalid_explicit_target",
    "invalid_request_id",
    "invalid_revision_request",
    "migration_lock_busy",
    "migration_memberships_not_approved",
    "migration_ownership_mismatch",
    "migration_privileges_not_approved",
    "migration_purge_forbidden",
    "migration_roles_not_approved",
    "migration_transaction_break",
    "migration_transaction_lost",
    "server_transaction_lost",
    "unexpected_database_revision",
    "unexpected_repository_heads",
    "unexpected_upgrade_path",
    "unexpected_upgrade_plan",
    "unsupported_postgresql_version",
})


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise guard.Denied("invalid_arguments")


def main(argv=None):
    diagnostic = {"request_id": None, "target": guard.TARGET, "predecessor": None,
                  "successor": None, "stage": "arguments"}

    def stage(name):
        diagnostic["stage"] = name

    try:
        parser = Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--request-id", required=True)
        parser.add_argument("--container-id", required=True)
        parser.add_argument("--predecessor", required=True)
        parser.add_argument("--successor", required=True)
        args = parser.parse_args(argv)
        for name, pattern in (("request_id", r"[A-Za-z0-9_-]{1,64}"),
                              ("predecessor", r"[0-9a-f]{12}"),
                              ("successor", r"[0-9a-f]{12}")):
            value = getattr(args, name)
            if re.fullmatch(pattern, value):
                diagnostic[name] = value
        request = guard.Request(**vars(args), database_url=os.environ.get(
            "AI_SOC_MIGRATION_DATABASE_URL", ""))
        config = Config()
        config.set_main_option("script_location", str(ROOT / "migrations"))
        guard.execute(config, request, os.environ, stage)
    except guard.Denied as exc:
        reason = str(exc)
        if reason not in DENIAL_CODES:
            reason = "execution_failed"
        print(json.dumps(dict(diagnostic, status="failure", reason=reason)), file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        print(json.dumps(dict(diagnostic, status="failure", reason="execution_failed")), file=sys.stderr)
        return 1
    print(json.dumps(dict(diagnostic, status="success")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
