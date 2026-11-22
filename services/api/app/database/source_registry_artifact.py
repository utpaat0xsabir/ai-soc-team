"""Render the secret-free B4 execution manifest with stdout as its only output."""
import ast
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path
from platform import python_version
import subprocess

from app.database.source_registry_migration_plan import compile_disabled_stage


REPORT = "docs/security/source-registry-execution-manifest.json"
FILES = tuple(sorted("""
alembic.ini
deploy/b4/ai-soc-b4-worker@.service
deploy/b4/ai-soc-b4-authority.service
deploy/b4/ai-soc-b4-authority.socket
deploy/b4/ai-soc-b4-host-control.service
deploy/b4/ai-soc-b4-host-control.socket
deploy/b4/b4workers.slice
deploy/b4/ai-soc-b4-broker.service
deploy/b4/ai-soc-b4-control.socket
deploy/b4/ai-soc-b4-worker.socket
deploy/b4/ai-soc-b4-docker-inspect.socket
pyproject.toml
requirements.txt
migrations/env.py
migrations/versions/013505dd4ffd_add_unique_tenant_scoped_wazuh_evidence_.py
migrations/versions/1e6b673facf2_add_tenant_api_keys.py
migrations/versions/20d4e84d93ca_add_audit_log_hash_chain.py
migrations/versions/211e576b1806_add_append_only_audit_logs.py
migrations/versions/5ad5e0e78db3_add_tenant_scoped_wazuh_integrations.py
migrations/versions/6cf3679d8b90_create_tenant_and_evidence_tables.py
migrations/versions/b71a4c2d9e10_add_wazuh_sync_checkpoints.py
migrations/versions/c82b5d3ea021_add_wazuh_sync_leases.py
migrations/versions/d93c6e4fb132_add_wazuh_attempt_status.py
migrations/versions/e4b2b2000001_stage_source_registry.py
scripts/run_guarded_migration.py
scripts/provision_b4.py
scripts/b4_preflight_bootstrap.py
scripts/b4_authority.py
scripts/b4_host_control.py
services/api/app/analysts/classification_authority.py
services/api/app/analysts/contracts.py
services/api/app/analysts/evidence_adapter.py
services/api/app/analysts/evidence_admission.py
services/api/app/analysts/inference.py
services/api/app/analysts/orchestration.py
services/api/app/analysts/postgres_classification.py
services/api/app/analysts/postgres_evidence.py
services/api/app/analysts/postgres_source_verification.py
services/api/app/analysts/source_verification.py
services/api/app/audit/integrity.py
services/api/app/database/classification_registry_schema.py
services/api/app/database/migration_guard.py
services/api/app/database/models.py
services/api/app/database/roles.py
services/api/app/database/source_registry_artifact.py
services/api/app/database/source_registry_migration_plan.py
services/api/app/database/source_registry_observer.py
services/api/app/database/source_registry_observer_adapter.py
services/api/app/database/source_registry_preflight.py
services/api/app/database/source_registry_preflight_launcher.py
services/api/app/database/source_registry_local_inputs.py
services/api/app/database/source_registry_b4_broker.py
services/api/app/database/source_registry_b4_broker_server.py
services/api/app/database/source_registry_b4_runtime.py
services/api/app/database/source_registry_b4_authority.py
services/api/app/database/source_registry_b4_admission.py
services/api/app/database/source_registry_b4_host_control.py
services/api/app/database/source_registry_schema.py
services/api/app/database/test_target.py
services/api/app/evidence/hashing.py
tests/conftest.py
tests/database/test_guarded_migration.py
tests/database/test_postgres_evidence_integration.py
tests/database/test_source_registry_migration_plan.py
tests/database/test_source_registry_observer.py
tests/database/test_source_registry_observer_adapter.py
tests/database/test_source_registry_preflight.py
tests/database/test_source_registry_preflight_launcher.py
tests/database/test_source_registry_local_inputs.py
tests/database/test_source_registry_b4_broker.py
tests/database/test_source_registry_b4_broker_server.py
tests/database/test_source_registry_b4_runtime.py
tests/database/test_source_registry_b4_authority.py
tests/database/test_source_registry_b4_admission.py
tests/database/test_source_registry_b4_host_control.py
tests/offline-selection.json
docs/security/source-registry-migration-gates.md
""".split()))
_PIN = "0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4"


def _read(root, name):
    path = root / name
    if path.resolve(strict=True) != path or not path.is_file():
        raise ValueError("unsafe_artifact_path")
    return path.read_bytes()


def _graph(sources):
    graph = {}
    for name, data in sources.items():
        if not name.startswith("migrations/versions/"):
            continue
        values = {}
        for node in ast.parse(data).body:
            target = (node.targets[0] if isinstance(node, ast.Assign) else
                      node.target if isinstance(node, ast.AnnAssign) else None)
            if isinstance(target, ast.Name) and target.id in {
                "revision", "down_revision", "depends_on", "branch_labels", "_DDL_SHA256",
            }:
                values[target.id] = ast.literal_eval(node.value)
        revision = values["revision"]
        if revision in graph or values.get("depends_on") or values.get("branch_labels"):
            raise ValueError("unexpected_revision_graph")
        graph[revision] = values["down_revision"]
        if revision == "e4b2b2000001" and values.get("_DDL_SHA256") != _PIN:
            raise ValueError("unexpected_ddl_pin")
    revision = "e4b2b2000001"
    if len(graph) != 10 or graph.get(revision) != "d93c6e4fb132":
        raise ValueError("unexpected_revision_graph")
    chain = []
    while revision is not None:
        if revision in chain or revision not in graph:
            raise ValueError("unexpected_revision_graph")
        chain.append(revision)
        revision = graph[revision]
    if len(chain) != len(graph):
        raise ValueError("unexpected_revision_graph")
    return graph


def _git(root, *args):
    result = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
    )
    return result.stdout


def _inventory(root):
    expected = {name for name in FILES if name.startswith("migrations/versions/")}
    actual = {path.relative_to(root).as_posix() for path in (root / "migrations/versions").glob("*.py")}
    if expected != actual:
        raise ValueError("unexpected_revision_files")
    sources = {name: _read(root, name) for name in FILES}
    ddl = compile_disabled_stage()
    if (len(ddl) != 67 or sha256("\n".join(ddl).encode()).hexdigest() != _PIN
            or any(sql.startswith(("GRANT ", "CREATE POLICY ")) for sql in ddl)):
        raise ValueError("unexpected_staged_ddl")
    return {
        "schema_version": 1,
        "generation_method": "b4-explicit-allowlist-v1",
        "runtime": {"python": python_version(), **{
            name: version(name) for name in ("alembic", "SQLAlchemy", "psycopg")
        }},
        "files": {name: sha256(data).hexdigest() for name, data in sources.items()},
        "migrations": _graph(sources),
        "head": "e4b2b2000001",
        "ddl_statements": len(ddl),
        "ddl_sha256": _PIN,
    }


def _canonical(body):
    return (json.dumps(body, indent=2, sort_keys=True) + "\n").encode()


def manifest_bytes(root: Path) -> bytes:
    """Reproduce checkout or frozen archive inventory before comparing its trusted pin."""
    try:
        root = root.resolve(strict=True)
        body = _inventory(root)
        marker = root / "B4-MANIFEST.json"
        if marker.exists() or marker.is_symlink():
            if (root / ".git").exists() or (root / ".git").is_symlink():
                raise ValueError("ambiguous_artifact_source")
            raw = _read(root, marker.name)
            supplied = json.loads(raw)
            if type(supplied) is not dict or type(supplied.get("dirty")) is not bool:
                raise ValueError("invalid_frozen_manifest")
            commit = supplied.get("commit")
            if (type(commit) is not str or len(commit) not in (40, 64)
                    or any(ch not in "0123456789abcdef" for ch in commit)):
                raise ValueError("invalid_frozen_commit")
            body.update(commit=commit, dirty=supplied["dirty"])
            if raw != _canonical(body):
                raise ValueError("frozen_manifest_drift")
            return raw
        if Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()) != root:
            raise ValueError("unexpected_repository")
        body.update(commit=_git(root, "rev-parse", "HEAD").decode().strip(),
                    dirty=bool(_git(root, "status", "--porcelain=v1", "--untracked-files=normal",
                                    "--", ".", f":(exclude){REPORT}")))
        return _canonical(body)
    except (OSError, subprocess.SubprocessError, KeyError, SyntaxError) as exc:
        raise ValueError("artifact_unavailable") from None


if __name__ == "__main__":
    import sys

    sys.stdout.buffer.write(manifest_bytes(Path.cwd()))
