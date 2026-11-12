# REF-01 implementation inventory

REF-01B through REF-01G and safe REF-01H1 route extraction implemented 2026-11-13 against the working tree, including existing untracked files. Seven analyst/provider, seven IAM, three gateway, nine Wazuh, four evidence/detection and four foundation implementations now use the canonical paths below; their former import paths are retained through deprecated explicit compatibility exports. The existing REF-01A plan is preserved unchanged. Other destinations remain proposed.

## Original-to-target module map and pre-move dependency ledger

The ledger records pre-move dependencies; the REF-01B through REF-01H1 completion sections below supersede their respective rows. Paths in the first two columns are relative to `services/api/app/`. Dependencies include eager and function-local imports; reverse references include tests, scripts and Alembic. Dynamic strings and source-path guards must also be reviewed within each batch.

| Current | Proposed | Responsibility | Application imports | Reverse dependencies |
| --- | --- | --- | --- | --- | --- |
| `__init__.py` | `__init__.py` | Empty application package marker. | — | — |
| `analyst_contracts.py` | `analysts/contracts.py` | AI-01 tasks, immutable evidence snapshots, findings and structural evidence validation. | `app.evidence`, `app.gateway_contracts` | `services/api/app/analyst_evaluation.py`, `services/api/app/analyst_inference.py`, `services/api/app/analyst_protocol.py`, `services/api/app/ollama_inference.py`, `services/api/app/ollama_prompt.py`, `tests/test_analyst_contracts.py`, `tests/test_analyst_evaluation.py`, `tests/test_analyst_protocol.py`, `tests/test_ollama_preparation.py` |
| `analyst_evaluation.py` | `analysts/evaluation.py` | AI-02 bounded input assembly and narrow deterministic evidence-support evaluation. | `app.analyst_contracts`, `app.gateway_contracts` | `services/api/app/analyst_inference.py`, `services/api/app/analyst_protocol.py`, `services/api/app/ollama_inference.py`, `services/api/app/ollama_prompt.py`, `tests/test_analyst_evaluation.py`, `tests/test_analyst_inference.py`, `tests/test_analyst_protocol.py`, `tests/test_ollama_preparation.py` |
| `analyst_inference.py` | `analysts/inference.py` | Model-independent registry/profiles, inference contracts, fake provider, admission and validation pipeline. | `app.analyst_contracts`, `app.analyst_evaluation`, `app.analyst_protocol`, `app.gateway_contracts`, `app.ollama_inference`, `app.ollama_prompt` | `services/api/app/ollama_inference.py`, `services/api/app/ollama_prompt.py`, `services/api/app/ollama_transport.py`, `tests/test_analyst_inference.py`, `tests/test_ollama_inference.py`, `tests/test_ollama_preparation.py` |
| `analyst_protocol.py` | `analysts/protocol.py` | AI-03 prompt envelope, strict JSON proposal parsing and adversarial replay. | `app.analyst_contracts`, `app.analyst_evaluation`, `app.gateway_contracts` | `services/api/app/analyst_inference.py`, `services/api/app/ollama_inference.py`, `services/api/app/ollama_prompt.py`, `tests/test_analyst_protocol.py` |
| `api_keys.py` | `iam/api_keys.py` | API-key generation and SHA-256 hashing utilities. | — | `services/api/app/auth.py`, `services/api/app/provision_api_key.py`, `services/api/app/provision_tenant.py`, `tests/test_api_keys.py`, `tests/test_audit_api.py`, `tests/test_auth.py`, `tests/test_evidence_api.py`, `tests/test_tenant_isolation.py`, `tests/test_wazuh_ingestion_api.py`, `tests/test_wazuh_integrations_api.py`, `tests/test_wazuh_sync.py` |
| `audit.py` | `audit/integrity.py` | Canonical audit hashing/verification and tenant-locked append-only audit staging in caller transaction. | `app.models` | `scripts/provision_wazuh_integration.py`, `services/api/app/main.py`, `services/api/app/provision_api_key.py`, `services/api/app/wazuh_sync.py`, `tests/test_audit.py`, `tests/test_audit_api.py`, `tests/test_audit_concurrency.py`, `tests/test_database_roles_integration.py`, `tests/test_wazuh_ingestion_api.py`, `tests/test_wazuh_recovery.py`, `tests/test_wazuh_sync.py`, `tests/test_wazuh_sync_concurrency.py` |
| `auth.py` | `iam/auth.py` | Existing API-key authentication dependency and frozen AuthenticatedPrincipal; no IAM runtime enforcement. | `app.api_keys`, `app.db`, `app.models` | `services/api/app/main.py`, `services/api/app/wazuh_scheduler.py`, `services/api/app/wazuh_sync.py`, `tests/test_auth.py`, `tests/test_wazuh_sync.py` |
| `config.py` | `core/config.py` | Pydantic settings and eager settings construction; reads configured environment file on import. | — | `migrations/env.py`, `scripts/provision_wazuh_integration.py`, `services/api/app/db.py`, `services/api/app/wazuh_leases.py`, `services/api/app/wazuh_scheduler.py`, `services/api/app/wazuh_service.py`, `services/api/app/wazuh_sync.py`, `tests/test_database_roles_integration.py`, `tests/test_wazuh_scheduler.py`, `tests/test_wazuh_service.py`, `tests/test_wazuh_sync.py`, `tests/test_wazuh_sync_concurrency.py`, `tests/test_wazuh_sync_policy.py`, `tests/test_wazuh_sync_status.py` |
| `database_roles.py` | `database/roles.py` | Pure PostgreSQL role SQL rendering and print-only CLI; does not execute SQL. | `app.models` | `scripts/prepare_database_roles.py`, `tests/test_database_roles.py`, `tests/test_database_roles_integration.py` |
| `db.py` | `db.py` | Configured SQLAlchemy engine, session factory and FastAPI session dependency; import constructs engine. | `app.config` | `scripts/provision_wazuh_integration.py`, `services/api/app/auth.py`, `services/api/app/main.py`, `services/api/app/provision_api_key.py`, `services/api/app/provision_tenant.py`, `services/api/app/wazuh_scheduler.py`, `tests/test_audit_api.py`, `tests/test_audit_concurrency.py`, `tests/test_database_roles_integration.py`, `tests/test_evidence_api.py`, `tests/test_tenant_isolation.py`, `tests/test_wazuh_checkpoint_migration.py`, `tests/test_wazuh_checkpoints.py`, `tests/test_wazuh_ingestion_api.py`, `tests/test_wazuh_integrations.py`, `tests/test_wazuh_integrations_api.py`, `tests/test_wazuh_lease_migration.py`, `tests/test_wazuh_status_migration.py`, `tests/test_wazuh_sync.py`, `tests/test_wazuh_sync_concurrency.py` |
| `detection_rules.py` | `detection/rules.py` | Bounded rule contracts, matching and source-backed match trace. | `app.security_events` | `services/api/app/event_correlation.py`, `tests/test_correlation_matches.py`, `tests/test_detection_rule_groups.py`, `tests/test_detection_rules.py` |
| `disclosure_policy.py` | `gateway/disclosure_policy.py` | TG-03A pure consent/disclosure assessment, including synthetic Wazuh shape checks. | `app.gateway_contracts`, `app.wazuh_gateway` | `services/api/app/tool_gateway.py`, `services/api/app/wazuh_manifest.py`, `tests/test_disclosure_policy.py`, `tests/test_gateway_disclosure_enforcement.py`, `tests/test_tool_gateway.py`, `tests/test_wazuh_gateway.py`, `tests/test_wazuh_manifest.py` |
| `event_correlation.py` | `detection/correlation.py` | Pure fixed-window tenant-scoped correlation and verified match grouping. | `app.detection_rules`, `app.security_events` | `tests/test_correlation_matches.py`, `tests/test_event_correlation.py` |
| `evidence.py` | `evidence/hashing.py` | Canonical evidence SHA-256 hashing; not an evidence repository or retrieval service. | — | `services/api/app/analyst_contracts.py`, `services/api/app/main.py`, `services/api/app/security_events.py`, `services/api/app/wazuh_sync.py`, `tests/test_analyst_contracts.py`, `tests/test_analyst_evaluation.py`, `tests/test_audit_concurrency.py`, `tests/test_evidence.py`, `tests/test_evidence_api.py`, `tests/test_security_events.py`, `tests/test_wazuh_sync.py` |
| `gateway_contracts.py` | `gateway/contracts.py` | Leaf strict/frozen base contracts, trusted context and exact tool-request binding shared by IAM/AI/gateway. | — | `services/api/app/analyst_contracts.py`, `services/api/app/analyst_evaluation.py`, `services/api/app/analyst_inference.py`, `services/api/app/analyst_protocol.py`, `services/api/app/disclosure_policy.py`, `services/api/app/iam_admission.py`, `services/api/app/iam_contracts.py`, `services/api/app/iam_policy.py`, `services/api/app/iam_postgres_authority.py`, `services/api/app/ollama_inference.py`, `services/api/app/ollama_prompt.py`, `services/api/app/tool_gateway.py`, `services/api/app/wazuh_gateway.py`, `services/api/app/wazuh_manifest.py`, `tests/test_analyst_contracts.py`, `tests/test_gateway_disclosure_enforcement.py`, `tests/test_iam_contracts.py`, `tests/test_iam_postgres_authority.py`, `tests/test_wazuh_manifest.py` |
| `iam_admission.py` | `iam/admission.py` | IAM-03A synthetic origin/issuer/freshness admission, API-key mapping and IAM-02 delegation. | `app.gateway_contracts`, `app.iam_contracts`, `app.iam_policy` | `services/api/app/iam_authority_provider.py`, `tests/test_iam_admission.py`, `tests/test_iam_authority_provider.py` |
| `iam_authority_provider.py` | `iam/authority_provider.py` | IAM-03B read/current-epoch protocol, synthetic provider registration and admission bridge. | `app.iam_admission`, `app.iam_contracts`, `app.iam_policy` | `services/api/app/iam_postgres_authority.py`, `tests/test_iam_authority_provider.py`, `tests/test_iam_postgres_authority.py` |
| `iam_contracts.py` | `iam/contracts.py` | IAM-01 immutable identities, scopes, provenance, approval and graph validation contracts. | `app.gateway_contracts` | `services/api/app/iam_admission.py`, `services/api/app/iam_authority_provider.py`, `services/api/app/iam_policy.py`, `services/api/app/iam_postgres_authority.py`, `tests/test_iam_admission.py`, `tests/test_iam_authority_provider.py`, `tests/test_iam_contracts.py`, `tests/test_iam_policy.py`, `tests/test_iam_postgres_authority.py` |
| `iam_policy.py` | `iam/policy.py` | IAM-02 pure role/action/classification policy evaluator and non-executable decisions. | `app.gateway_contracts`, `app.iam_contracts` | `services/api/app/iam_admission.py`, `services/api/app/iam_authority_provider.py`, `services/api/app/iam_postgres_authority.py`, `tests/test_iam_admission.py`, `tests/test_iam_authority_provider.py`, `tests/test_iam_policy.py` |
| `iam_postgres_authority.py` | `iam/postgres_authority.py` | Unfinished IAM-03C injected-session read-only skeleton; always fails closed on missing IAM schema. | `app.gateway_contracts`, `app.iam_authority_provider`, `app.iam_contracts`, `app.iam_policy`, `app.models` | `tests/test_iam_postgres_authority.py` |
| `main.py` | `main.py` | ASGI object, 16 route handlers, HTTP error mapping and current evidence/Wazuh transactions; retain entrypoint and later extract listed handlers. | `app.audit`, `app.auth`, `app.db`, `app.evidence`, `app.models`, `app.schemas`, `app.wazuh`, `app.wazuh_service`, `app.wazuh_status`, `app.wazuh_sync` | `tests/test_audit_api.py`, `tests/test_database_roles_integration.py`, `tests/test_evidence_api.py`, `tests/test_health.py`, `tests/test_tenant_isolation.py`, `tests/test_wazuh_ingestion_api.py`, `tests/test_wazuh_integrations_api.py`, `tests/test_wazuh_sync.py` |
| `models.py` | `database/models.py` | One DeclarativeBase and eight tenant/evidence/audit/Wazuh ORM models; retain shared metadata. | — | `migrations/env.py`, `scripts/provision_wazuh_integration.py`, `services/api/app/audit.py`, `services/api/app/auth.py`, `services/api/app/database_roles.py`, `services/api/app/iam_postgres_authority.py`, `services/api/app/main.py`, `services/api/app/provision_api_key.py`, `services/api/app/provision_tenant.py`, `services/api/app/wazuh_leases.py`, `services/api/app/wazuh_service.py`, `services/api/app/wazuh_status.py`, `services/api/app/wazuh_sync.py`, `tests/test_audit_api.py`, `tests/test_audit_concurrency.py`, `tests/test_database_roles_integration.py`, `tests/test_evidence_api.py`, `tests/test_tenant_isolation.py`, `tests/test_wazuh_checkpoint_migration.py`, `tests/test_wazuh_checkpoints.py`, `tests/test_wazuh_ingestion_api.py`, `tests/test_wazuh_integrations.py`, `tests/test_wazuh_integrations_api.py`, `tests/test_wazuh_lease_migration.py`, `tests/test_wazuh_leases.py`, `tests/test_wazuh_recovery.py`, `tests/test_wazuh_scheduler_integration.py`, `tests/test_wazuh_status_migration.py`, `tests/test_wazuh_sync.py`, `tests/test_wazuh_sync_concurrency.py`, `tests/test_wazuh_sync_status.py` |
| `ollama_inference.py` | `analysts/providers/ollama.py` | Strict Ollama chat mapping via injected MockTransport only; mandatory analyst validators. | `app.analyst_contracts`, `app.analyst_evaluation`, `app.analyst_inference`, `app.analyst_protocol`, `app.gateway_contracts`, `app.ollama_prompt` | `services/api/app/analyst_inference.py`, `services/api/app/ollama_transport.py`, `tests/test_ollama_inference.py`, `tests/test_ollama_preparation.py` |
| `ollama_prompt.py` | `analysts/providers/ollama_prompt.py` | Deterministic schema-title optimization and estimated wire/context budgeting. | `app.analyst_contracts`, `app.analyst_evaluation`, `app.analyst_inference`, `app.analyst_protocol`, `app.gateway_contracts` | `services/api/app/analyst_inference.py`, `services/api/app/ollama_inference.py`, `tests/test_ollama_preparation.py` |
| `ollama_transport.py` | `analysts/providers/ollama_transport.py` | Disabled-by-default live-capable transport mechanics and gated provider; no operational clearance issuer. | `app.analyst_inference`, `app.ollama_inference` | `tests/test_ollama_preparation.py` |
| `provision_api_key.py` | `iam/provision_api_key.py` | Explicit CLI provisioning and auditing of API keys; must never execute during refactor verification. | `app.api_keys`, `app.audit`, `app.db`, `app.models` | — |
| `provision_tenant.py` | `iam/provision_tenant.py` | Explicit CLI creation of tenant and initial API key; must never execute during refactor verification. | `app.api_keys`, `app.db`, `app.models` | — |
| `schemas.py` | `schemas.py` | HTTP request/response DTOs for tenant, evidence, lineage, audit and Wazuh endpoints. | — | `services/api/app/main.py`, `services/api/app/wazuh_status.py`, `tests/test_wazuh_sync_status.py` |
| `security_events.py` | `detection/security_events.py` | Pure normalized event derivation from explicit hashed Wazuh evidence snapshots. | `app.evidence`, `app.wazuh` | `services/api/app/detection_rules.py`, `services/api/app/event_correlation.py`, `tests/test_security_events.py` |
| `tool_gateway.py` | `gateway/tool_gateway.py` | TG-01/TG-03B deterministic authorization/disclosure boundary, explicit synthetic registry and test-only sinks. | `app.disclosure_policy`, `app.gateway_contracts`, `app.wazuh_gateway` | `tests/test_analyst_contracts.py`, `tests/test_analyst_evaluation.py`, `tests/test_analyst_inference.py`, `tests/test_analyst_protocol.py`, `tests/test_disclosure_policy.py`, `tests/test_gateway_disclosure_enforcement.py`, `tests/test_gateway_permission_design.py`, `tests/test_iam_admission.py`, `tests/test_iam_authority_provider.py`, `tests/test_iam_contracts.py`, `tests/test_iam_policy.py`, `tests/test_ollama_inference.py`, `tests/test_ollama_preparation.py`, `tests/test_tool_gateway.py`, `tests/test_wazuh_gateway.py`, `tests/test_wazuh_manifest.py` |
| `wazuh.py` | `integrations/wazuh/client.py` | Existing read-only Indexer HTTP/PIT client, normalization, timestamp parsing and scope fingerprints. | `app.wazuh_cursor` | `scripts/provision_wazuh_integration.py`, `services/api/app/main.py`, `services/api/app/security_events.py`, `services/api/app/wazuh_service.py`, `services/api/app/wazuh_sync.py`, `tests/test_correlation_matches.py`, `tests/test_security_events.py`, `tests/test_wazuh.py`, `tests/test_wazuh_ingestion_api.py`, `tests/test_wazuh_pagination.py`, `tests/test_wazuh_recovery_policy.py`, `tests/test_wazuh_sync.py`, `tests/test_wazuh_sync_policy.py` |
| `wazuh_cursor.py` | `integrations/wazuh/cursor.py` | Pure validated stable-sort cursor and serialization. | — | `services/api/app/wazuh.py`, `tests/test_wazuh_cursor.py` |
| `wazuh_gateway.py` | `integrations/wazuh/gateway.py` | TG-04A closed synthetic Wazuh adapter, source bindings and fake client. | `app.gateway_contracts` | `services/api/app/disclosure_policy.py`, `services/api/app/tool_gateway.py`, `tests/test_wazuh_gateway.py`, `tests/test_wazuh_manifest.py` |
| `wazuh_leases.py` | `integrations/wazuh/leases.py` | PostgreSQL-clock fenced leases and lock ordering. | `app.config`, `app.models`, `app.wazuh_status` | `services/api/app/wazuh_sync.py`, `tests/test_wazuh_leases.py`, `tests/test_wazuh_scheduler_integration.py`, `tests/test_wazuh_sync_status.py` |
| `wazuh_manifest.py` | `integrations/wazuh/manifest.py` | TG-04B-PRE2 offline source-manifest clearance/query planning with executable=False. | `app.disclosure_policy`, `app.gateway_contracts` | `tests/test_gateway_development_spec.py`, `tests/test_wazuh_manifest.py` |
| `wazuh_scheduler.py` | `integrations/wazuh/scheduler.py` | Explicit disabled-by-default foreground polling worker; no API startup hook. | `app.auth`, `app.config`, `app.db`, `app.wazuh_status`, `app.wazuh_sync` | `scripts/run_wazuh_scheduler.py`, `tests/test_wazuh_scheduler.py`, `tests/test_wazuh_scheduler_integration.py` |
| `wazuh_service.py` | `integrations/wazuh/service.py` | Tenant-integration settings/TLS/reference checks and existing client context manager. | `app.config`, `app.models`, `app.wazuh` | `services/api/app/main.py`, `services/api/app/wazuh_sync.py`, `tests/test_wazuh_service.py` |
| `wazuh_status.py` | `integrations/wazuh/status.py` | Tenant-owned synchronization status and sanitized safe error categories. | `app.models`, `app.schemas` | `services/api/app/main.py`, `services/api/app/wazuh_leases.py`, `services/api/app/wazuh_scheduler.py`, `services/api/app/wazuh_sync.py`, `tests/test_wazuh_sync_status.py` |
| `wazuh_sync.py` | `integrations/wazuh/sync.py` | Page-atomic checkpoint/evidence/audit synchronization, source validation and recovery. | `app.audit`, `app.auth`, `app.config`, `app.evidence`, `app.models`, `app.wazuh`, `app.wazuh_leases`, `app.wazuh_service`, `app.wazuh_status` | `services/api/app/main.py`, `services/api/app/wazuh_scheduler.py`, `tests/test_database_roles_integration.py`, `tests/test_wazuh_recovery.py`, `tests/test_wazuh_recovery_policy.py`, `tests/test_wazuh_scheduler.py`, `tests/test_wazuh_scheduler_integration.py`, `tests/test_wazuh_sync.py`, `tests/test_wazuh_sync_concurrency.py`, `tests/test_wazuh_sync_policy.py`, `tests/test_wazuh_sync_status.py` |

## Entry points and cycles

- Preserve `app.main:app`, all 16 existing HTTP handlers and route metadata.
- Preserve provisioning CLI guards, `scripts/prepare_database_roles.py`, `scripts/run_wazuh_scheduler.py` and `scripts/provision_wazuh_integration.py`; do not execute them.
- `migrations/env.py` imports `app.config` and `app.models`. Revision modules have no application imports. No migration execution or revision edits are proposed.
- Analyst inference has function-local imports back into Ollama prompt/provider modules. Preserve this lazy boundary; eager imports would introduce a cycle.
- `app.db`, `app.audit` and `app.evidence` collide with proposed package names. Each requires an atomic, separately approved migration and compatibility review.
- Test modules import helpers from sibling `test_*` modules. Keep test locations unchanged during application moves.

## REF-01B completed: analysts and providers

```text
services/api/app/analysts/
├── __init__.py
├── contracts.py
├── evaluation.py
├── protocol.py
├── inference.py
└── providers/
    ├── __init__.py
    ├── ollama.py
    ├── ollama_prompt.py
    └── ollama_transport.py
```

| Deprecated compatibility import | Canonical implementation |
| --- | --- |
| app.analyst_contracts | app.analysts.contracts |
| app.analyst_evaluation | app.analysts.evaluation |
| app.analyst_protocol | app.analysts.protocol |
| app.analyst_inference | app.analysts.inference |
| app.ollama_inference | app.analysts.providers.ollama |
| app.ollama_prompt | app.analysts.providers.ollama_prompt |
| app.ollama_transport | app.analysts.providers.ollama_transport |

Canonical modules and analyst/Ollama tests import canonical paths. Legacy files only explicitly re-export the same objects, including existing private helpers and exceptions; they create no authority and contain no duplicate implementation. Keep them until external consumers and a separate retirement decision are reviewed. New code must use canonical paths. Both package initializers are empty.

The existing lazy cycle remains: inference imports provider/prompt functions inside request processing; the provider imports inference eagerly, and prompt validation imports inference/protocol locally. No eager cycle is introduced. Do not promote these local imports to module scope without a separate dependency change.

IAM-03C diagnosis: reloading its module replaced TransactionObservation while the fixture retained the previous exact class. This independently reproduced SCHEMA_INCOMPLETE before reload, TRANSACTION_UNVERIFIED with the stale fixture, and SCHEMA_INCOMPLETE with a fresh fixture. The test now builds its fixture after guarded reload, retains the expected outcome and all I/O guards, and probes each patched I/O entry point. IAM production logic is unchanged; its provider remains incomplete and ineligible for operational authorization.

Verification on 2026-11-13: selected offline regression collected and passed 1,605 tests across 29 files (the previous 1,584 cases plus 21 package checks); focused post-move analyst/Ollama/gateway/IAM run passed 562 cases before adding fourteen fresh-process orders. IAM-03C alone passed all 44 cases after the isolation correction. Seven identity checks initially failed before package creation as expected. The first fourteen guarded subprocess checks failed on Pydantic plugin initialization; the harness now initializes that third-party machinery before guards, and all fourteen pass. No unresolved test failures remain in this selection. All 31 contract schemas, 80 signatures (ignoring process addresses), and seven implementation ASTs excluding imports match the pre-move snapshot. In-memory compilation passed for 107 files. Offline registration preserved 16 routes and generated 15 OpenAPI paths. Eager dependency analysis, git diff --check and whitespace checks of all 64 untracked text files passed. Database-backed suites were excluded; no live services were contacted. Existing analyst/security cases are retained; test_analyst_packages adds identity checks and fourteen fresh-process first-import orders with application I/O forbidden after third-party initialization. Compilation is in memory. Configuration/session stubs are mandatory for offline API registration; no operational database or transport is invoked.

Recovery copies and a pre-batch content manifest were captured outside the application tree before mutation. Recovery must reverse only this batch, never reset or clean unrelated tracked/untracked work.

## REF-01C completed: IAM package

```text
services/api/app/iam/
├── __init__.py
├── contracts.py
├── policy.py
├── admission.py
├── authority_provider.py
├── postgres_authority.py
├── auth.py
└── api_keys.py
```

| Deprecated compatibility import | Canonical implementation |
| --- | --- |
| app.iam_contracts | app.iam.contracts |
| app.iam_policy | app.iam.policy |
| app.iam_admission | app.iam.admission |
| app.iam_authority_provider | app.iam.authority_provider |
| app.iam_postgres_authority | app.iam.postgres_authority |
| app.auth | app.iam.auth |
| app.api_keys | app.iam.api_keys |

Each legacy file contains explicit re-exports only, including existing private helpers and exception classes. Package initialization is empty. New IAM files belong in this package and use absolute canonical imports. There are no duplicate implementations or new registrations. Compatibility retirement remains a separate decision after external callers are verified.

IAM internals, seven affected test modules and the authentication/API-key imports in main, Wazuh sync/scheduler and both provisioning modules use canonical paths. Database-backed tests may retain legacy imports to exercise compatibility when separately authorized. Scripts and Alembic have no direct imports needing repair in this batch and remain unchanged. Provisioning CLI locations and main guards are preserved; these commands were not executed.

The five IAM contract/policy/provider moves form an eager acyclic dependency chain and add no session factory or engine. HTTP authentication retains its existing get_db dependency from app.db. That existing database module constructs an engine when imported normally; offline authentication and API checks inject a database stub before importing it. This refactor does not change infrastructure construction timing. SQLAlchemy models and metadata remain in app.models; sessions remain in app.db.

IAM-03C remains an incomplete, fail-closed offline provider. Its no-I/O test reloads the canonical module, then builds a fixture with the current strict contract class as established in REF-01B. Runtime module reload is not a supported compatibility mechanism: explicit re-export modules are ordinary Python imports, not dynamic proxies. Identity/import-order checks run in fresh processes to avoid that deliberate reload contaminating unrelated tests.

Verification preserves 39 IAM JSON schemas and 75 signatures; seven canonical implementations and five runtime callers have identical ASTs after excluding imports. Exact OpenAPI equality, authentication dependency identities, 16 routes, 15 OpenAPI paths and existing SQLAlchemy table registration were verified with engine/session/network access denied. New tests exercise fourteen legacy/canonical first-import orders with shared exports, principal/exception identities and model/dependency identity assertions. They failed before package creation, then passed. Focused tests: 332 after the first five moves, 344 including authentication/API-key cases after all seven moves. Final selected offline regression: 1,626 collected and passed across 31 files, accounting for the REF-01B baseline of 1,605 plus fourteen new package checks and seven existing authentication cases newly included under an injected database dependency. In-memory compilation passed for 116 files. git diff --check and whitespace checks of all 73 untracked text files passed. No failing or deselected cases occurred in this selected run; database-backed suites were not collected. No operational database, Wazuh or Ollama connection, migration or provisioning command was executed. Instructions, handoff, models, sessions, scripts, migration files and analyst/provider implementations were preserved. No new dependency cycle is introduced; the existing analyst/provider lazy cycle is unchanged.

## REF-01D completed: shared Security Tool Gateway

```text
services/api/app/gateway/
├── __init__.py
├── contracts.py
├── disclosure_policy.py
└── tool_gateway.py
```

| Deprecated compatibility import | Canonical implementation |
| --- | --- |
| app.gateway_contracts | app.gateway.contracts |
| app.disclosure_policy | app.gateway.disclosure_policy |
| app.tool_gateway | app.gateway.tool_gateway |

The package initializer is empty. No adapters directory is needed: Wazuh-specific implementations stay in app.wazuh_gateway and app.wazuh_manifest until a separately approved Wazuh batch. No tools, providers, issuers or adapters are newly registered. Legacy modules contain only explicit canonical re-exports, including private helpers and shared exception classes. They contain no duplicate implementations; retain them until a separate compatibility-retirement review.

Canonical imports were updated in IAM, analyst/provider and Wazuh consumers and their affected tests, including the test patch targets for dispatch/disclosure. Wazuh changes are imports only; neither its location nor its query/execution behavior changed. FastAPI source, scripts, Alembic, models and sessions require no gateway import repairs and remain unchanged. New gateway contracts belong in contracts.py; disclosure/consent assessment in disclosure_policy.py; existing synthetic registry and dispatch policy in tool_gateway.py. New operational adapters require separate authorization and must preserve the policy boundaries.

There is no eager gateway cycle. Contracts are a leaf; the unmoved synthetic Wazuh adapter imports those contracts; disclosure imports that adapter; dispatch imports disclosure and the adapter. The existing analyst/Ollama function-local cycle remains unchanged. Runtime reload and monkeypatching a deprecated module's bindings are not forwarded by ordinary explicit re-exports; tests patch the canonical owning module. Classes, exceptions, functions and exported constant objects are shared across normal legacy/canonical imports.

Verification: the 1,626-test offline baseline was rerun successfully before editing. Each of the three relocation batches passed the same 408 focused gateway/disclosure/Wazuh/PRE2 tests. Six new fresh-process first-import tests failed before package creation, then passed with filesystem/network/subprocess and database/settings imports forbidden after third-party initialization. These tests check shared exports and TrustedContext/ToolRequest/Destination identities across IAM, analysts and Wazuh. All 106 affected cross-domain Pydantic schemas, 38 gateway signatures, exports, a deterministic synthetic result/audit/evidence fixture, exact OpenAPI and SQLAlchemy table registration match the pre-move snapshot. Existing implementation/test ASTs match after excluding imports. Final selected offline regression on 2026-11-13: 1,632 collected and passed across 32 files, equal to the 1,626 baseline plus six new gateway import tests. No failures, skips or deselections occurred in this selection. In-memory compilation passed for 121 files. Guarded route registration preserved all 16 routes and 15 OpenAPI paths with canonical authentication dependency identities. Eager import analysis, git diff --check and explicit whitespace checks of all 78 untracked text files passed. Database-backed suites were not collected. Three canonical implementations and seventeen affected existing test files use the new imports; ten IAM/analyst consumers and two unmoved Wazuh consumers received import-only updates. Main, database/models, scripts, migrations, instructions and handoff are unchanged from the pre-REF-01D snapshot.

Security behavior remains structural-only: no changed context construction, tenant/request/resource bindings, grants, allowlists, consent/disclosure checks, ceilings, denial handling, synthetic labels or audit metadata. Live Wazuh gateway and real Ollama execution remain blocked. No database, network, service activation, migration or operational tool execution is part of REF-01D.

## REF-01E completed: Wazuh integration package

```text
services/api/app/integrations/
├── __init__.py
└── wazuh/
    ├── __init__.py
    ├── client.py
    ├── cursor.py
    ├── gateway.py
    ├── leases.py
    ├── manifest.py
    ├── scheduler.py
    ├── service.py
    ├── status.py
    └── sync.py
```

| Deprecated compatibility import | Canonical implementation |
| --- | --- |
| app.wazuh | app.integrations.wazuh.client |
| app.wazuh_cursor | app.integrations.wazuh.cursor |
| app.wazuh_gateway | app.integrations.wazuh.gateway |
| app.wazuh_leases | app.integrations.wazuh.leases |
| app.wazuh_manifest | app.integrations.wazuh.manifest |
| app.wazuh_scheduler | app.integrations.wazuh.scheduler |
| app.wazuh_service | app.integrations.wazuh.service |
| app.wazuh_status | app.integrations.wazuh.status |
| app.wazuh_sync | app.integrations.wazuh.sync |

Both new initializers are empty. Each former module contains explicit canonical re-exports, including private helpers and exceptions. New code uses canonical paths. Test patch targets were updated to their canonical owning modules, including the preserved database-backed tests; those tests were not run. No implementation was duplicated. Retain compatibility imports until a separately justified retirement; ordinary re-exports do not forward assignment/monkeypatches to legacy module bindings.

Client retains TLS-verified read-only Indexer operations and alert normalization; cursor retains bound serialization; gateway retains the synthetic-only adapter; manifest retains offline PRE2 validation; service retains credential-reference and connection checks; status retains allowlisted tenant-owned metadata; leases retains database-clock fencing; sync retains page-atomic ingestion and checkpoints; scheduler retains disabled-by-default operator admission. These moves add no source mapping, transport, provider, issuer or activation. TG-04B remains blocked.

Imports were updated in the Wazuh implementations, FastAPI main, normalized-event consumer, shared gateway, affected tests and the two Wazuh scripts. The script paths and their main guards are unchanged. Guarded non-main imports verified that run_wazuh_scheduler.main is the canonical main and provisioning uses the canonical client, without invoking either entry point. Alembic still imports the unchanged app.config and app.models; revision files, models, sessions and configuration are untouched.

Dependency order: cursor precedes client; synthetic gateway depends on shared gateway contracts; manifest depends on shared disclosure contracts; service depends on client and existing config/models; status depends on existing models/API schemas; leases depends on status/config/models; sync depends on client/service/leases/status plus unchanged auth/evidence/audit; scheduler depends on sync/status/auth and the existing session dependency. No eager cycle is introduced. The existing analyst/Ollama lazy cycle remains unchanged.

One explicit preservation detail: scheduler uses logging.getLogger('app.wazuh_scheduler') so moving the source does not change the log category previously obtained from __name__. This is the only non-import production AST adjustment and preserves the original evaluated value. HTTP/session dependencies still use existing infrastructure; offline checks inject config/session stubs before imports, avoiding settings-file reads and engine construction. No runtime infrastructure behavior is changed.

Verification before relocation: the 1,632-case selected baseline passed, and six additional reviewed offline files passed 152 cases with synthetic configuration, database factories/connections denied, sockets denied and live HTTPTransport requests denied. Public CA certificates were read for the existing TLS-validating mocked client tests; TLS was not bypassed. Three relocation batches (cursor/client/gateway/manifest; service/status/leases; sync/scheduler) each passed 394 focused cases. Twenty-four new checks failed before package creation, then passed: eighteen fresh-process first-import orders with shared exports/exception/dataclass/model/dependency identities and six fake-session fencing/status-query checks. All sixteen Wazuh schemas, 139 function/class/method signatures, exports, cursor bytes, normalized evidence, query fingerprint, logger category, OpenAPI and model registration match the pre-move snapshot. Existing consumers differ only in imports or test patch strings. Final selected offline regression on 2026-11-13: 1,812 collected and passed across 40 files in 58.02 seconds, with no failures, skips or deselections in the selection. Count reconciliation: 1,632 prior cases + 152 existing offline Wazuh cases + four existing pure status cases selected explicitly by node ID + 24 new package/fake-session cases. The two pure status functions were selected without invoking the PostgreSQL fixture in their otherwise database-backed module. In-memory compilation passed for 133 files. Guarded checks preserved all 16 registered routes and 15 OpenAPI paths with exact OpenAPI equality; both script imports resolved to canonical implementations without entry-point execution. git diff --check and whitespace checks of all 90 untracked text files passed. Both new package initializers are empty and eager dependency analysis remains acyclic. No database-dependent test was executed.

Limits: real lease contention, PostgreSQL fencing/locking/constraints, database sync/status/checkpoint transitions, transaction atomicity, migrations and scheduler integration tests remain excluded. Fake-session checks do not establish database concurrency guarantees. No protected database, test database, Wazuh, Ollama or operational scheduler was accessed. Only synthetic/mock test execution occurred.

## REF-01F completed: evidence hashing and detection/correlation

```text
services/api/app/
├── evidence/
│   ├── __init__.py
│   └── hashing.py
└── detection/
    ├── __init__.py
    ├── security_events.py
    ├── rules.py
    └── correlation.py
```

| Legacy compatibility import | Canonical implementation |
| --- | --- |
| app.evidence | app.evidence.hashing |
| app.security_events | app.detection.security_events |
| app.detection_rules | app.detection.rules |
| app.event_correlation | app.detection.correlation |

The evidence.py/package collision was resolved by moving the original file into evidence/hashing.py and making evidence/__init__.py a lightweight, explicitly deprecated re-export facade. No competing evidence.py remains. It exposes the exact original objects, including existing constants/imported names, without duplicating hashing logic. The other three old files are explicit deprecated re-export modules. Detection initialization is empty. Retire these compatibility paths only after a separate review of external consumers.

Internal imports, analyst hashing dependencies, Wazuh sync, FastAPI main and affected tests use canonical paths. Existing database-backed tests received import repairs only and were not executed. Audit implementation, persistence/lineage logic, ORM definitions, sessions, configuration, scripts and Alembic were not restructured. Test locations and shared fixtures are unchanged. Plain re-exports preserve object identity but do not forward assignments to legacy module bindings; monkeypatches target canonical owners.

Dependency direction is acyclic: hashing is pure standard-library code; security_events depends on hashing and Wazuh timestamp parsing; rules depends on normalized-event contracts; correlation depends on those contracts and rules. Wazuh sync and analysts depend on hashing without importing HTTP or ORM code through that package. Existing analyst/Ollama function-local dependencies remain unchanged.

New evidence hash/serialization helpers belong in evidence/hashing.py; event normalization and its contracts in detection/security_events.py; detection conditions/matching in detection/rules.py; existing correlation policies/grouping in detection/correlation.py. Do not add persistence, new rules, incident/campaign features or cross-domain authority during placement changes. Existing evidence persistence/lineage handlers remain in main pending the API batch.

Verification: the 1,812-case selected offline baseline passed before editing. Four independently tested batches (hashing, normalization, rules, correlation) each passed the same 370 focused cases. Eight new fresh-process first-import checks failed before package creation and passed afterwards with filesystem/network/subprocess/HTTP and database/settings access forbidden after third-party initialization. They check every exported object's identity plus shared normalization, rule, correlation and analyst hashing objects. Hashing source is byte-identical to its original; all four implementation ASTs and all changed existing consumer/test ASTs match after excluding imports.

Pre/post snapshots match 17 Pydantic schemas, 41 signatures, public exports and seven deterministic vectors: evidence SHA-256, normalized-event JSON, detection-rule JSON, scalar match JSON, group-rule match JSON, correlation 1.0 JSON and correlation 1.1 JSON. Comparing serialized results preserves existing event/match/group/result identifiers, traces, ordering and fingerprints. Exact OpenAPI and ORM table registration also match. Final selected offline regression on 2026-11-13: 1,820 collected and passed across 41 files in 60.61 seconds, equal to the unchanged 1,812 baseline cases plus eight new import-order/identity checks. No failures, skips or deselections occurred within the selected run. In-memory compilation passed for 139 files. Guarded API registration preserved all 16 routes and 15 OpenAPI paths with exact OpenAPI equality, and API/analyst/Wazuh/legacy hashing identities are shared. Eager dependency analysis, git diff --check and whitespace checks of all 97 untracked text files passed. Database-dependent tests were not executed; no database, Wazuh, Ollama or operational scheduler access occurred.

Security boundaries remain unchanged: observed evidence versus interpretation, content integrity/provenance, tenant-scoped normalization/matching/grouping, strict malformed-input rejection, UTC handling, fixed-window semantics, deduplication and fail-closed behavior. No database-backed evidence, lineage, audit atomicity or concurrency checks were authorized; no new operational capability was introduced. TG-04B and real Ollama execution remain blocked.

## REF-01G completed safe moves: core, audit and database foundations

```text
services/api/app/
├── core/
│   ├── __init__.py
│   └── config.py
├── audit/
│   ├── __init__.py
│   └── integrity.py
├── database/
│   ├── __init__.py
│   ├── models.py
│   └── roles.py
├── db.py                     # retained canonical engine/session/get_db implementation
├── config.py                 # compatibility exports
├── models.py                 # compatibility exports
├── database_roles.py         # compatibility exports
├── provision_api_key.py      # retained CLI; imports repaired only
└── provision_tenant.py       # retained CLI; imports repaired only
```

| Legacy compatibility import | Canonical implementation |
| --- | --- |
| app.config | app.core.config |
| app.audit | app.audit.integrity |
| app.models | app.database.models |
| app.database_roles | app.database.roles |
| app.db | app.db (deliberately retained) |

The audit.py/package collision is resolved by moving its implementation to audit/integrity.py and retaining app.audit exports in an explicit package facade. No competing audit.py remains. Other moved modules retain explicit legacy export files. Core and database initializers are empty; audit initialization consists only of compatibility imports. No implementations or authority are duplicated. Existing patches to shared Settings/model objects remain shared; patches to module-level bindings must target canonical owners as with earlier ordinary re-export facades. No directly affected in-repository patch to legacy audit/config/model module bindings was found; existing Session/class patches remain compatible.

### Import and object-identity dependency map

Pre-move AST inventory recorded 16 direct config imports, 12 audit imports, 33 models imports, three role-generator imports and 21 db imports across application code, tests, scripts and migrations. The per-symbol ledger was captured with the preservation snapshot before mutation. Core identity relationships are:

| Object / consumer | Required identity and verified result |
| --- | --- |
| Settings/settings; Wazuh modules, db, scripts, Alembic | Legacy and canonical class/instance exports are identical. Settings remains eagerly constructed exactly once when its canonical module loads. |
| Base and all eight mapped classes; IAM, audit, API, Wazuh, provisioning | Legacy and canonical exports share the sole Base, registry, mapper classes, Tables and MetaData. No second model execution/registration occurs through compatibility imports. |
| RolePlan and renderers; prepare_database_roles script | Legacy/canonical classes/functions are shared; roles.Base is the same canonical Base. Rendered SQL is unchanged and was never executed. |
| Audit functions; API, Wazuh and provisioning | Legacy/canonical functions share the implementation globals; AuditLog/Tenant references use the shared canonical model classes. |
| Engine, SessionLocal, get_db; auth, API, scheduler and provisioning | Implementation stays at app.db. Consumer identity, original factory arguments, session-generator cleanup and patching db.SessionLocal were checked with fake factories. No actual engine or session was created for these checks. |
| migrations/env.py | Canonical config/model imports and target_metadata bind to the same Settings export, Base, MetaData and eight model classes. Only extracted application imports and metadata assignment were executed; no Alembic environment/migration machinery ran. |

### Deliberately retained modules and scope limits

Session relocation is deferred. get_db reads SessionLocal from its own module globals: a plain re-export from a relocated session implementation would stop assignments/monkeypatches to app.db.SessionLocal from affecting get_db. Keeping the canonical implementation at app.db preserves this behavior without proxies or duplicated factories. Its only change is the config import path. No empty database/session.py wrapper was introduced. Engine/session construction options and timing are unchanged.

Provisioning modules remain at their existing CLI paths, with model/audit imports repaired only. Their guards, transaction bodies and output are unchanged; they were not invoked. Alembic env.py received application-import changes only; all revision files and persisted SQLAlchemy definitions remain unchanged. No schema, ownership, privilege or role change was applied.

Configuration still has its existing environment/dotenv loading behavior. Offline identity/snapshot tests intercept BaseSettings initialization, preventing any real environment/dotenv source read while verifying the class, schema, eager single construction and shared instance. These guards do not claim operational configuration validation. Model import checks deny engine/session construction, connections and metadata create_all/drop_all. Source copies prove models.py and config.py implementations byte-identical before/after; audit, role rendering and retained db ASTs match after excluding imports.

### Verification performed

- Pre-move selected offline baseline: 1,820 collected and passed.
- Three safe batches (models/roles; audit; core configuration): 24 focused pure audit/role cases passed after each batch.
- New foundation checks: twelve passed (eight fresh-process first-import orders, one retained session/factory/patching check, three fake-session audit writer checks). Before package creation the eleven checks requiring new packages failed, while the retained-session check already passed.
- Audit writer fakes retain tenant-lock SQL, sequence/genesis binding, flush/error propagation and caller commit/rollback ownership. They do not establish PostgreSQL locking, rollback or concurrency guarantees.
- Pre/post snapshots match one Settings schema, 22 signatures, all eight table column/constraint/index descriptions and mapper names, deterministic audit hashes and sequence/link/content failure results, role SQL for both supported target names, and exact OpenAPI. Only SQL compilation/rendering occurred, without database access.
- Final selected regression on 2026-11-13: 1,832 collected and passed across 42 files in 68.33 seconds, equal to the unchanged 1,820 baseline plus twelve new checks. No failures, skips or deselections within this selected run. The temporary snapshot harness was repaired to stub both config paths after canonical-only imports; the final comparisons pass.
- Guarded API registration preserves 16 routes and 15 OpenAPI paths, exact OpenAPI equality and shared dependency/engine references. Script imports resolve without running entry points. Eager dependency graph remains acyclic.
- In-memory compilation: 146 Python files passed. git diff --check and explicit whitespace checks of all 105 untracked text files passed. Protected instructions and handoff are unchanged.

Deferred verification includes real engine/session construction, PostgreSQL data/schema parity, audit append-only enforcement, lock contention, transactional rollback/atomicity, role permissions, migrations and operational configuration. No database-dependent test, database connection, Alembic command, provisioning action or live network operation was run. TG-04B and real Ollama execution remain blocked. Stop after REF-01G; do not extract API routes, relocate tests or retire compatibility modules here.

## REF-01H1: safe API route extraction

```text
services/api/app/
├── main.py                    # composition, health, readiness, legacy Wazuh ingestion
├── schemas.py                 # unchanged shared request/response contracts
└── api/
    ├── __init__.py
    └── v1/
        ├── __init__.py
        ├── tenant.py
        ├── evidence.py
        ├── audit.py
        └── wazuh.py
```

Thirteen handlers moved without changing their signatures, annotations, decorator arguments or bodies: one tenant handler, six evidence/lineage handlers, two audit handlers and four Wazuh handlers. Only decorator ownership changes from app to router/sync_router. Package initializers are empty. main.py remains the ASGI entry point and explicitly re-exports moved handler functions, retaining their identity with the registered endpoints. Original main imports remain available during this compatibility window. Schemas, database sessions/models, IAM, audit and integration implementations are untouched.

### Route inventory and authentication

The table follows original effective registration order. T means get_current_tenant plus get_db; P means get_current_principal plus get_db. Both authentication dependencies validate the existing API key and revocation state and reuse the same cached session dependency. Every protected route retains its 401 ApiKey challenge and request-validation 422 behavior. Application-generated errors remain unchanged, including unhandled persistence errors propagating to 500. No new error handlers or OpenAPI response declarations were added.

| Method / path | Endpoint | Response model / status | Tags | Auth | Owner |
| --- | --- | --- | --- | --- | --- |
| POST `/v1/integrations/wazuh/{integration_id}/sync` | `synchronize_wazuh` | `WazuhSyncResponse` / 200 | Wazuh Integrations | P | `wazuh.sync_router` |
| GET `/v1/integrations/wazuh/{integration_id}/sync/status` | `get_wazuh_sync_status` | `WazuhSyncStatusResponse` / 200 | Wazuh Integrations | P | `wazuh.sync_router` |
| GET `/health` | `health` | `implicit JSON` / 200 | System | — | `main` |
| GET `/ready` | `readiness` | `implicit JSON` / 200 | System | — | `main` |
| GET `/v1/tenant` | `get_tenant` | `TenantResponse` / 200 | Tenant | T | `tenant` |
| POST `/v1/evidence` | `ingest_evidence` | `EvidenceResponse` / 201 | Evidence | P | `evidence` |
| GET `/v1/evidence` | `list_evidence` | `EvidenceListResponse` / 200 | Evidence | T | `evidence` |
| GET `/v1/evidence/{evidence_id}` | `get_evidence` | `EvidenceResponse` / 200 | Evidence | T | `evidence` |
| GET `/v1/evidence/{evidence_id}/verify` | `verify_evidence_integrity` | `EvidenceIntegrityResponse` / 200 | Evidence | T | `evidence` |
| POST `/v1/evidence/{parent_evidence_id}/lineage` | `create_evidence_lineage` | `EvidenceLineageResponse` / 201 | Evidence Lineage | P | `evidence` |
| GET `/v1/evidence/{evidence_id}/lineage` | `list_evidence_lineage` | `EvidenceLineageListResponse` / 200 | Evidence Lineage | T | `evidence` |
| GET `/v1/audit-logs` | `list_audit_logs` | `AuditLogListResponse` / 200 | Audit | T | `audit` |
| GET `/v1/audit-logs/verify` | `verify_audit_logs` | `AuditIntegrityResponse` / 200 | Audit | T | `audit` |
| GET `/v1/integrations/wazuh` | `list_wazuh_integrations` | `WazuhIntegrationListResponse` / 200 | Wazuh Integrations | P | `wazuh.router` |
| GET `/v1/integrations/wazuh/{integration_id}` | `get_wazuh_integration` | `WazuhIntegrationResponse` / 200 | Wazuh Integrations | P | `wazuh.router` |
| POST `/v1/integrations/wazuh/{integration_id}/ingest` | `ingest_wazuh_alerts` | `WazuhIngestionResponse` / 200 | Wazuh Integrations | P | `main` |

Canonical handler imports are app.api.v1.{tenant,evidence,audit,wazuh}; request/response types remain app.schemas. Complete OpenAPI equality covers every request/response schema, operation ID, route name, parameter constraint, default, status, tag and documented response. The full ordered dependency tree was compared, with callable identity assertions for get_db, get_current_tenant and get_current_principal. API-key principal mapping, tenant filters, SQL statements and transaction call ordering are preserved.

Request serialization stays in FastAPI/Pydantic with unchanged DTOs. Evidence/audit list pagination remains limit=50 (1..100), offset=0 (>=0); Wazuh sync/ingestion limit remains 50 (1..100), and ingestion offset remains 0 (0..9900). Audit action validation, UUID/body validation, response filtering, evidence integrity and lineage schemas are unchanged. Offline snapshots cover 54 scenarios: all sixteen endpoints, unauthenticated requests to all fourteen protected endpoints, revoked keys, positive writes/reads, absent/foreign resource results, invalid body/pagination/action inputs, integrity mismatch, lineage conflicts, synthetic upstream errors and commit-failure rollback paths. They compare raw response bytes, headers, parsed content, status and recorded fake SQL/session/transaction calls.

Direct application errors retained include tenant_not_found; invalid_evidence_payload; evidence_not_found; evidence_integrity_check_failed; evidence_cannot_reference_itself; evidence_lineage_already_exists; invalid_audit_action_filter; WazuhSyncError's existing status/detail; wazuh_sync_status_unavailable; wazuh_integration_not_found; wazuh_integration_inactive; wazuh_integration_configuration_unavailable; wazuh_indexer_request_failed; wazuh_indexer_invalid_response. Health/readiness stay in main, including the existing database_unavailable readiness error. No persistence operation, error category or authorization rule was added or repaired.

### Router registration and patch compatibility

Registration order is deliberately preserved:

1. wazuh.sync_router: sync, then sync status.
2. main health, then readiness.
3. tenant.router.
4. evidence.router in the original six-handler order.
5. audit.router: list, then verification.
6. wazuh.router: list integrations, then get integration.
7. main legacy Wazuh ingestion.

Two Wazuh router objects preserve the separated positions of the original handlers; neither adds a prefix, global dependency or tag. The installed FastAPI stores include_router branches rather than flattening app.routes. Verification uses fastapi.routing.iter_route_contexts to inspect effective paths, dependencies, response models and endpoint identities; naive raw app.routes counts would miss included handlers. No production workaround or list mutation was added.

Legacy ingest_wazuh_alerts remains in main.py. Three existing database-backed API tests patch app.main.open_wazuh_client; moving its handler behind a normal function re-export would break that global lookup. The handler, namespace and patch target are therefore retained unchanged, with fake-client success and denial/error cases proving interception offline. Existing Session.commit class patches and get_db dependency overrides continue referencing the same objects; no existing test or assertion was changed. The remaining direct main handlers are health, readiness and ingest_wazuh_alerts. Any future ingestion extraction needs a separately approved patch/dependency compatibility decision.

### Verification and limits

- Pre-edit selected offline baseline: 1,832 cases passed. Source copies, per-route method/path/name/response/status/tags/dependency/error inventory and complete OpenAPI/HTTP behavior snapshots were captured before production edits.
- Focused tenant extraction: four tests passed. Evidence/lineage extraction: 21 passed. Audit extraction: five passed. Final Wazuh extraction and complete new API checks: 60 passed. Every batch also compared complete OpenAPI, ordered route/dependency metadata and all 54 behavior/call-order snapshots against the original.
- Five initial structural checks failed before router creation as expected; the main import/OpenAPI check already passed. The first TestClient portal harness hung and was stopped; a bounded diagnostic isolated the sandbox's cross-thread portal problem. HTTP snapshots use in-process httpx ASGITransport with synchronous test callbacks executed inline instead. Production handlers remain synchronous with their original framework scheduling; concurrency/threadpool behavior is outside this verification.
- The installed framework's included-router branches initially exposed a limitation in the new route-inventory walker, while tenant HTTP behavior and OpenAPI already matched. The walker now uses effective route contexts and still requires all sixteen original ordered routes/dependencies. Assertions were not weakened to omit the route.
- Response snapshots additionally include wire bytes and headers. These supplemental values were captured by loading the preserved pre-extraction main.py under the same guards, first proving it reproduced every original non-wire snapshot. Expected values were never derived from relocated handlers. Final wire/header comparisons match across all 54 scenarios.
- Endpoint aliases in main, effective endpoints, dependency callables, response-model classes, operation IDs and router-first import orders are checked. All thirteen extracted ASTs differ only in decorator receiver; all three retained handler ASTs and the FastAPI application construction are unchanged. Every other pre-existing file except main/documentation is preserved by content hashes, including schemas, existing tests, models, sessions, policy implementations, scripts and migrations.
- Final selected offline regression on 2026-11-13: 1,892 collected and passed across 43 files in 77.99 seconds, equal to the unchanged 1,832 baseline plus sixty new API checks (54 HTTP snapshots, five import orders and one endpoint-owner/patch-boundary check). No failures, skips or deselections within this final selection. In-memory compilation passed for 153 files. git diff --check and whitespace checks of all 112 untracked text files passed after removing generated trailing blank lines. All sixteen effective routes and fifteen OpenAPI paths remain present, in original order, with exact document equality. No existing tests were modified or relocated.

Database-backed API suites and live persistence/lineage/audit/sync atomicity/concurrency remain unverified. Readiness, sync and legacy ingestion were exercised only with explicit synthetic collaborators; no real database or Wazuh client was opened. No Ollama, scheduler or live gateway activity occurred. API router placement adds no IAM enforcement, issuer or operational authority. Test relocation and compatibility retirement remain deferred. Stop after REF-01H1.

## Navigation conventions and deferred work

- L1/L2/L3 contracts and evaluation belong in analysts; local inference adapters in analysts/providers.
- IAM contracts, policies and trusted admission belong in iam; tool contracts, disclosure and dispatch in gateway.
- Wazuh-specific clients, normalization and source adapters belong in integrations/wazuh; generic event rules and correlation in detection.
- Hash/provenance helpers belong in evidence; audit hashing/writing in audit/integrity.py; shared ORM metadata and role rendering in database. Canonical engine/session construction remains in app.db.
- HTTP handlers belong in api/v1, shared settings in core. Preserve main as the ASGI composition entry point.
- Use absolute cross-package imports, lightweight initializers and one canonical implementation. Keep compatibility exports documented and temporary.
- Tests now mirror domains under tests/{analysts,iam,gateway,integrations/wazuh,evidence,detection,audit,database,api}. Keep existing provider-module fixtures; use absolute tests.<domain>.test_<name> helper imports. No conftest was introduced. Offline execution must use the reviewed tests/offline-selection.json plus isolated configuration/session stubs and external-I/O guards; the manifest alone is not an I/O guard.
- Deferred: session relocation (app.db deliberately retained), legacy Wazuh ingestion extraction (app.main patch boundary retained), compatibility retirement and separately approved API/schema cleanup. Domain test relocation is complete in REF-01H2 below. IAM-03C still needs authoritative schema, protected provider construction, revocation/freshness design, least-privilege access and migration/recovery planning. Database parity remains separately gated. Stop after REF-01H2; subsequent batches require separate authorization.


## REF-01H2 — domain test organization (2026-11-13)

Completed structural-only relocation of all 61 original test modules. Application implementations, migrations, operational scripts, pyproject.toml, AGENTS.md and development-handoff.md are unchanged from the start of this batch, verified by content hashes. Earlier Git changes and untracked implementations are preserved. No flat test module was deliberately retained; mixed offline/database modules remain intact.

```text
tests/
├── __init__.py
├── offline-selection.json
├── analysts/             # 7 modules: analyst contracts/evaluation/protocol/inference, Ollama
├── iam/                  # 8 modules: authentication, keys, policy, admission, providers
├── gateway/              # 6 modules: tool/disclosure/security/design contracts
├── integrations/
│   └── wazuh/            # 21 modules: client, ingestion, cursor, leases, sync, scheduler
├── evidence/             # 1 module: hashing
├── detection/            # 6 modules: events, rules, grouping, correlation, package identity
├── audit/                # 2 modules: integrity, concurrency
├── database/             # 3 modules: role rendering/integration, foundation identity
└── api/                  # 7 modules: offline contracts and existing HTTP integrations
```

All directories shown contain empty package initializers (11 total, including tests and integrations). Unique test module basenames are preserved. Pytest's existing testpaths/pythonpath/import mode are unchanged. The cross-domain foundation package check lives in database because its central boundary is shared session/model/metadata identity.

### Exact test migration inventory

Every original path was tests/<filename>; the destination below is the complete new path. No implementation or assertion is duplicated.

| Original filename | Destination |
| --- | --- |
| `test_analyst_contracts.py` | `tests/analysts/test_analyst_contracts.py` |
| `test_analyst_evaluation.py` | `tests/analysts/test_analyst_evaluation.py` |
| `test_analyst_inference.py` | `tests/analysts/test_analyst_inference.py` |
| `test_analyst_packages.py` | `tests/analysts/test_analyst_packages.py` |
| `test_analyst_protocol.py` | `tests/analysts/test_analyst_protocol.py` |
| `test_ollama_inference.py` | `tests/analysts/test_ollama_inference.py` |
| `test_ollama_preparation.py` | `tests/analysts/test_ollama_preparation.py` |
| `test_api_routes_offline.py` | `tests/api/test_api_routes_offline.py` |
| `test_audit_api.py` | `tests/api/test_audit_api.py` |
| `test_evidence_api.py` | `tests/api/test_evidence_api.py` |
| `test_health.py` | `tests/api/test_health.py` |
| `test_tenant_isolation.py` | `tests/api/test_tenant_isolation.py` |
| `test_wazuh_ingestion_api.py` | `tests/api/test_wazuh_ingestion_api.py` |
| `test_wazuh_integrations_api.py` | `tests/api/test_wazuh_integrations_api.py` |
| `test_audit.py` | `tests/audit/test_audit.py` |
| `test_audit_concurrency.py` | `tests/audit/test_audit_concurrency.py` |
| `test_database_roles.py` | `tests/database/test_database_roles.py` |
| `test_database_roles_integration.py` | `tests/database/test_database_roles_integration.py` |
| `test_foundation_packages.py` | `tests/database/test_foundation_packages.py` |
| `test_correlation_matches.py` | `tests/detection/test_correlation_matches.py` |
| `test_detection_rule_groups.py` | `tests/detection/test_detection_rule_groups.py` |
| `test_detection_rules.py` | `tests/detection/test_detection_rules.py` |
| `test_event_correlation.py` | `tests/detection/test_event_correlation.py` |
| `test_evidence_detection_packages.py` | `tests/detection/test_evidence_detection_packages.py` |
| `test_security_events.py` | `tests/detection/test_security_events.py` |
| `test_evidence.py` | `tests/evidence/test_evidence.py` |
| `test_disclosure_policy.py` | `tests/gateway/test_disclosure_policy.py` |
| `test_gateway_development_spec.py` | `tests/gateway/test_gateway_development_spec.py` |
| `test_gateway_disclosure_enforcement.py` | `tests/gateway/test_gateway_disclosure_enforcement.py` |
| `test_gateway_packages.py` | `tests/gateway/test_gateway_packages.py` |
| `test_gateway_permission_design.py` | `tests/gateway/test_gateway_permission_design.py` |
| `test_tool_gateway.py` | `tests/gateway/test_tool_gateway.py` |
| `test_api_keys.py` | `tests/iam/test_api_keys.py` |
| `test_auth.py` | `tests/iam/test_auth.py` |
| `test_iam_admission.py` | `tests/iam/test_iam_admission.py` |
| `test_iam_authority_provider.py` | `tests/iam/test_iam_authority_provider.py` |
| `test_iam_contracts.py` | `tests/iam/test_iam_contracts.py` |
| `test_iam_packages.py` | `tests/iam/test_iam_packages.py` |
| `test_iam_policy.py` | `tests/iam/test_iam_policy.py` |
| `test_iam_postgres_authority.py` | `tests/iam/test_iam_postgres_authority.py` |
| `test_wazuh.py` | `tests/integrations/wazuh/test_wazuh.py` |
| `test_wazuh_checkpoint_migration.py` | `tests/integrations/wazuh/test_wazuh_checkpoint_migration.py` |
| `test_wazuh_checkpoints.py` | `tests/integrations/wazuh/test_wazuh_checkpoints.py` |
| `test_wazuh_cursor.py` | `tests/integrations/wazuh/test_wazuh_cursor.py` |
| `test_wazuh_gateway.py` | `tests/integrations/wazuh/test_wazuh_gateway.py` |
| `test_wazuh_integrations.py` | `tests/integrations/wazuh/test_wazuh_integrations.py` |
| `test_wazuh_lease_migration.py` | `tests/integrations/wazuh/test_wazuh_lease_migration.py` |
| `test_wazuh_leases.py` | `tests/integrations/wazuh/test_wazuh_leases.py` |
| `test_wazuh_manifest.py` | `tests/integrations/wazuh/test_wazuh_manifest.py` |
| `test_wazuh_packages.py` | `tests/integrations/wazuh/test_wazuh_packages.py` |
| `test_wazuh_pagination.py` | `tests/integrations/wazuh/test_wazuh_pagination.py` |
| `test_wazuh_recovery.py` | `tests/integrations/wazuh/test_wazuh_recovery.py` |
| `test_wazuh_recovery_policy.py` | `tests/integrations/wazuh/test_wazuh_recovery_policy.py` |
| `test_wazuh_scheduler.py` | `tests/integrations/wazuh/test_wazuh_scheduler.py` |
| `test_wazuh_scheduler_integration.py` | `tests/integrations/wazuh/test_wazuh_scheduler_integration.py` |
| `test_wazuh_service.py` | `tests/integrations/wazuh/test_wazuh_service.py` |
| `test_wazuh_status_migration.py` | `tests/integrations/wazuh/test_wazuh_status_migration.py` |
| `test_wazuh_sync.py` | `tests/integrations/wazuh/test_wazuh_sync.py` |
| `test_wazuh_sync_concurrency.py` | `tests/integrations/wazuh/test_wazuh_sync_concurrency.py` |
| `test_wazuh_sync_policy.py` | `tests/integrations/wazuh/test_wazuh_sync_policy.py` |
| `test_wazuh_sync_status.py` | `tests/integrations/wazuh/test_wazuh_sync_status.py` |

### Fixture, import and path compatibility

Existing fixtures stay in their original provider modules with their scopes and bodies unchanged; dependent tests now import those same objects through absolute package-qualified test paths. No conftest, competing fixture system, fixture renaming, marker or assertion changes were introduced. All monkeypatch target strings and dependency overrides are unchanged, including app.main.open_wazuh_client. Existing subprocess tests still resolve their own relocated __file__ correctly.

Only three gateway artifact checks needed a repository-root anchor repair: test_gateway_development_spec.py, test_gateway_permission_design.py and test_disclosure_policy.py now use parents[2] instead of parents[1]. Their resolved documentation/deployment artifact paths and assertions are unchanged. AST comparisons of all 61 original/destination pairs allow only test-helper import module changes and these three anchors; everything else, including parameter values, decorators, assertion bodies and patch targets, is identical.

### Collection and offline execution verification

Before relocation, guarded full collection found 2,106 cases in 61 modules. After each domain and at completion it still found 2,106. Normalizing only relocated path prefixes preserves every fixture closure, provider origin, scope, fixture base ID, parameter index and marker descriptor. Each source module loads once, avoiding duplicate helper/fixture identities. Default full collection and the separately ordered offline selection exercise different module import orders; existing fresh-process application import-order/security tests also remain in the passing selection. No order, skip or xfail markers were found; existing parameterize markers remain unchanged. No test was added, removed or deselected within the offline selection.

Node IDs intentionally change from tests/test_name.py::... to tests/<domain>/test_name.py::.... One existing Wazuh integration API parameter generates a uuid4 URL at collection time (test_integration_endpoints_reject_unauthenticated_requests); its UUID-bearing ID already varies between fresh processes. Comparison normalizes only that known random UUID in addition to path prefixes; its parameterization and test implementation were not changed. All other node suffixes remain identical.

The explicit ordered allowlist is tests/offline-selection.json: 44 selectors across 43 files, retaining the pre-move execution order. It selects only four pure cases from the mixed Wazuh sync-status module using two node selectors (three parameterized error cases and one schema case). Do not execute whole domain directories indiscriminately: database-backed cases remain alongside pure cases in some modules. Guarded verification injects synthetic settings and an unusable app.db session/engine, blocks engine/session construction and connections, metadata create/drop, socket connections and real HTTP transport, and disables pytest cache writes. Collection never executes database fixtures. No operational environment file or service was needed.

| Domain | Files moved | Focused offline cases passed |
| --- | ---: | ---: |
| Analysts/Ollama | 7 | 408 |
| IAM | 8 | 358 |
| Gateway | 6 | 283 |
| Wazuh | 21 | 369 |
| Evidence | 1 | 6 |
| Detection/correlation | 6 | 372 |
| Audit | 2 | 10 |
| Database/foundation | 3 | 26 |
| API | 7 | 60 |
| Total | 61 | 1,892 |

The pre-move selected baseline passed all 1,892 cases. Final selected regression passed 1,892/1,892 in 75.67 seconds, with no failures, skips or xfails; collection metadata and selected execution order match the baseline after the documented node-ID normalization. In-memory compilation passed for 164 Python files under services/api, tests and scripts (153 previous files plus 11 empty initializers). git diff --check passed; explicit whitespace scanning of all 160 untracked text files found no trailing whitespace, missing final newline or blank EOF issues. Existing fresh-process import-order and API route/OpenAPI checks passed within the selection. Full collection includes 214 additional cases that were collected only, not run: database/migration/concurrency/integration coverage and two legacy health TestClient cases excluded from the prior safe selection because of the documented sandbox portal limitation. The sixty offline API checks still cover health/readiness and exact OpenAPI/route/dependency behavior. No database-backed or live-service equivalence is claimed.

### Remaining structural exceptions

No test relocation is deferred. Shared fixtures deliberately remain in provider modules. Legacy application compatibility modules, canonical app.db, and the legacy Wazuh ingestion handler/patch namespace remain unchanged. Their retirement or relocation requires separate authorization, as do any database-backed verification, live integrations or functional work. Stop after REF-01H2.
