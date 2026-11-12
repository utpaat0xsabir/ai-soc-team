# REF-01A — backend architecture inventory and modular refactoring plan

Planning snapshot: 2026-11-12, branch `master`, latest commit `78e97d5`
(`chore: checkpoint AI SOC development foundations`). **Documentation only. No
application, test, migration, configuration or instruction file is changed by this
milestone.** The working tree includes substantial untracked prior work; the commit
alone does not describe this inventory. Preserve all tracked/untracked files.

## Scope, evidence and current readiness

Inspected AGENTS.md, docs/development-handoff.md, pyproject.toml, every current
backend Python module, its AST imports/declarations, all test/script/migration ASTs,
HTTP handlers, dynamic import/patch strings, Alembic metadata loading, deployment
configuration and command-line entrypoints. Paths and line numbers below refer to
the inspected checkout, including untracked modules. The dated handoff and README
are historical context, not proof of current feature completion.

The backend currently has **40 Python modules, 9,731 source lines**, all directly
under `services/api/app/`; this includes the empty `__init__.py`. It is already one
FastAPI modular monolith in deployment terms. It does not need microservices,
new dependencies, a generic repository framework or another dependency-injection
container. The proposed work changes placement and explicit imports only, followed
by separately reviewed extraction of existing HTTP transaction logic.

IAM-03C is **unfinished**: its last focused run in this session before REF-01A was
**43 passed, 1 failed**. The reload/no-I/O test reuses a pre-reload strict contract
instance and receives TRANSACTION_UNVERIFIED rather than SCHEMA_INCOMPLETE. This is
an observed failure, not a verified fix or an assertion that all IAM-03C behavior is
correct. Preserve `iam_postgres_authority.py` and its test unchanged; resolving that
milestone requires separate authorization. No IAM-03C planning document currently
exists. Do not fold this issue into a mechanical move or advertise the new provider
as usable. Its current provider path is deliberately not IAM-03B eligible.

The active ASGI application mounts no IAM policy, analyst inference or synthetic
Tool Gateway routes. These are offline libraries, not deployed runtime features.
TG-04B live gateway Wazuh and AI-04B-2B real inference remain blocked. Existing
legacy Wazuh ingestion routes and an explicit scheduler exist in code; that does
not approve invoking or activating them. Refactoring must preserve this distinction.

## Current directory tree

Only source files are listed; bytecode caches are excluded. There are no existing
backend domain subpackages to silently rename.

```text
services/api/app/
├── __init__.py
├── analyst_contracts.py
├── analyst_evaluation.py
├── analyst_inference.py
├── analyst_protocol.py
├── api_keys.py
├── audit.py
├── auth.py
├── config.py
├── database_roles.py
├── db.py
├── detection_rules.py
├── disclosure_policy.py
├── event_correlation.py
├── evidence.py
├── gateway_contracts.py
├── iam_admission.py
├── iam_authority_provider.py
├── iam_contracts.py
├── iam_policy.py
├── iam_postgres_authority.py
├── main.py
├── models.py
├── ollama_inference.py
├── ollama_prompt.py
├── ollama_transport.py
├── provision_api_key.py
├── provision_tenant.py
├── schemas.py
├── security_events.py
├── tool_gateway.py
├── wazuh.py
├── wazuh_cursor.py
├── wazuh_gateway.py
├── wazuh_leases.py
├── wazuh_manifest.py
├── wazuh_scheduler.py
├── wazuh_service.py
├── wazuh_status.py
└── wazuh_sync.py
```

## Proposed directory tree

All destinations below are proposals, not files created by REF-01A. Keep the same
`services/api` import root and `app.main:app` ASGI address. Do not create placeholder
packages before moving their first real module. Package initializers are empty
unless a reviewed compatibility/public facade is explicitly described below.

```text
services/api/app/
├── __init__.py
├── analysts/
│   ├── __init__.py
│   ├── contracts.py
│   ├── evaluation.py
│   ├── inference.py
│   ├── protocol.py
│   └── providers/
│       ├── __init__.py
│       ├── ollama.py
│       ├── ollama_prompt.py
│       └── ollama_transport.py
├── api/
│   ├── __init__.py
│   ├── system.py
│   └── v1/
│       ├── __init__.py
│       ├── audit.py
│       ├── evidence.py
│       ├── schemas.py
│       ├── tenant.py
│       └── wazuh.py
├── audit/
│   ├── __init__.py
│   └── service.py
├── core/
│   ├── __init__.py
│   └── config.py
├── db/
│   ├── __init__.py
│   ├── models.py
│   ├── role_plan.py
│   └── session.py
├── detection/
│   ├── __init__.py
│   ├── correlation.py
│   ├── events.py
│   └── rules.py
├── evidence/
│   ├── __init__.py
│   ├── hashing.py
│   └── operations.py
├── gateway/
│   ├── __init__.py
│   ├── contracts.py
│   ├── disclosure.py
│   └── dispatch.py
├── iam/
│   ├── __init__.py
│   ├── admission.py
│   ├── api_keys.py
│   ├── authentication.py
│   ├── authority_provider.py
│   ├── contracts.py
│   ├── policy.py
│   ├── postgres_authority.py
│   ├── provision_api_key.py
│   └── provision_tenant.py
├── integrations/
│   ├── __init__.py
│   └── wazuh/
│       ├── __init__.py
│       ├── client.py
│       ├── cursor.py
│       ├── gateway_adapter.py
│       ├── ingestion.py
│       ├── leases.py
│       ├── manifest.py
│       ├── scheduler.py
│       ├── service.py
│       ├── status.py
│       └── sync.py
└── main.py
```

`api/system.py` and the four `api/v1/*` route files are proposed extractions from
existing main.py handlers, not new endpoint functionality. `evidence/operations.py`
and `integrations/wazuh/ingestion.py` are optional later extractions of existing
transaction bodies (R12), not new persistence systems. No cases, SOAR, agent,
queue or additional provider packages are proposed. The Ollama provider subpackage
has three actual modules; do not add empty vLLM/cloud/adapters directories.

Keep one `db/models.py`, one Base and one Alembic metadata object initially.
Splitting ORM classes across domains adds metadata registration/cycle risk without
helping the first navigation change. Keep one HTTP schemas module initially;
its 209 lines do not justify splitting every request/response DTO into a new file.

## Complete current-to-target file map

All paths in this table are relative to `services/api/app/`. Thus `security_events.py`
means the exact current path `services/api/app/security_events.py`; `detection/events.py`
means the exact proposed path `services/api/app/detection/events.py`. Every current
module occurs exactly once. Detailed import, test and entrypoint impact follows
for each row. Stage numbers are proposals requiring implementation approval.

| Current file | Proposed destination | Stage | Primary responsibility | Risk |
| --- | --- | --- | --- | --- |
| `__init__.py` | `__init__.py` | R0 | Empty application package marker. | low |
| `analyst_contracts.py` | `analysts/contracts.py` | R5 | AI-01 tasks, immutable evidence snapshots, findings and structural evidence validation. | high |
| `analyst_evaluation.py` | `analysts/evaluation.py` | R5 | AI-02 bounded input assembly and narrow deterministic evidence-support evaluation. | high |
| `analyst_inference.py` | `analysts/inference.py` | R5 | Model-independent registry/profiles, inference contracts, fake provider, admission and validation pipeline. | high; lazy-import SCC |
| `analyst_protocol.py` | `analysts/protocol.py` | R5 | AI-03 prompt envelope, strict JSON proposal parsing and adversarial replay. | high |
| `api_keys.py` | `iam/api_keys.py` | R10 | API-key generation and SHA-256 hashing utilities. | medium |
| `audit.py` | `audit/service.py` | R7 | Canonical audit hashing/verification and tenant-locked append-only audit staging in caller transaction. | high; package-name collision |
| `auth.py` | `iam/authentication.py` | R10 | Existing API-key authentication dependency and frozen AuthenticatedPrincipal; no IAM runtime enforcement. | high |
| `config.py` | `core/config.py` | R8 | Pydantic settings and eager settings construction; reads configured environment file on import. | high |
| `database_roles.py` | `db/role_plan.py` | R9 | Pure PostgreSQL role SQL rendering and print-only CLI; does not execute SQL. | medium |
| `db.py` | `db/session.py` | R9 | Configured SQLAlchemy engine, session factory and FastAPI session dependency; import constructs engine. | high |
| `detection_rules.py` | `detection/rules.py` | R1 | Bounded rule contracts, matching and source-backed match trace. | low-medium |
| `disclosure_policy.py` | `gateway/disclosure.py` | R3 | TG-03A pure consent/disclosure assessment, including synthetic Wazuh shape checks. | high |
| `event_correlation.py` | `detection/correlation.py` | R1 | Pure fixed-window tenant-scoped correlation and verified match grouping. | low-medium |
| `evidence.py` | `evidence/hashing.py` | R2 | Canonical evidence SHA-256 hashing; not an evidence repository or retrieval service. | medium; package-name collision |
| `gateway_contracts.py` | `gateway/contracts.py` | R3 | Leaf strict/frozen base contracts, trusted context and exact tool-request binding shared by IAM/AI/gateway. | high fan-in; no cyclic imports |
| `iam_admission.py` | `iam/admission.py` | R4a | IAM-03A synthetic origin/issuer/freshness admission, API-key mapping and IAM-02 delegation. | high |
| `iam_authority_provider.py` | `iam/authority_provider.py` | R4a | IAM-03B read/current-epoch protocol, synthetic provider registration and admission bridge. | high |
| `iam_contracts.py` | `iam/contracts.py` | R4a | IAM-01 immutable identities, scopes, provenance, approval and graph validation contracts. | high |
| `iam_policy.py` | `iam/policy.py` | R4a | IAM-02 pure role/action/classification policy evaluator and non-executable decisions. | high |
| `iam_postgres_authority.py` | `iam/postgres_authority.py` | R4b | Unfinished IAM-03C injected-session read-only skeleton; always fails closed on missing IAM schema. | high; blocked by existing failing test |
| `main.py` | `main.py` | R11 | ASGI object, 16 route handlers, HTTP error mapping and current evidence/Wazuh transactions; retain entrypoint and later extract listed handlers. | high |
| `models.py` | `db/models.py` | R9 | One DeclarativeBase and eight tenant/evidence/audit/Wazuh ORM models; retain shared metadata. | high |
| `ollama_inference.py` | `analysts/providers/ollama.py` | R5 | Strict Ollama chat mapping via injected MockTransport only; mandatory analyst validators. | high; lazy-import SCC |
| `ollama_prompt.py` | `analysts/providers/ollama_prompt.py` | R5 | Deterministic schema-title optimization and estimated wire/context budgeting. | high; lazy-import SCC |
| `ollama_transport.py` | `analysts/providers/ollama_transport.py` | R5 | Disabled-by-default live-capable transport mechanics and gated provider; no operational clearance issuer. | high |
| `provision_api_key.py` | `iam/provision_api_key.py` | R10 | Explicit CLI provisioning and auditing of API keys; must never execute during refactor verification. | high |
| `provision_tenant.py` | `iam/provision_tenant.py` | R10 | Explicit CLI creation of tenant and initial API key; must never execute during refactor verification. | high |
| `schemas.py` | `api/v1/schemas.py` | R11 | HTTP request/response DTOs for tenant, evidence, lineage, audit and Wazuh endpoints. | medium |
| `security_events.py` | `detection/events.py` | R1 | Pure normalized event derivation from explicit hashed Wazuh evidence snapshots. | low-medium |
| `tool_gateway.py` | `gateway/dispatch.py` | R3 | TG-01/TG-03B deterministic authorization/disclosure boundary, explicit synthetic registry and test-only sinks. | high |
| `wazuh.py` | `integrations/wazuh/client.py` | R6a | Existing read-only Indexer HTTP/PIT client, normalization, timestamp parsing and scope fingerprints. | high; operational client exists but will not be invoked |
| `wazuh_cursor.py` | `integrations/wazuh/cursor.py` | R6a | Pure validated stable-sort cursor and serialization. | low |
| `wazuh_gateway.py` | `integrations/wazuh/gateway_adapter.py` | R6a | TG-04A closed synthetic Wazuh adapter, source bindings and fake client. | high; must remain synthetic |
| `wazuh_leases.py` | `integrations/wazuh/leases.py` | R6b | PostgreSQL-clock fenced leases and lock ordering. | high |
| `wazuh_manifest.py` | `integrations/wazuh/manifest.py` | R6a | TG-04B-PRE2 offline source-manifest clearance/query planning with executable=False. | high |
| `wazuh_scheduler.py` | `integrations/wazuh/scheduler.py` | R6b | Explicit disabled-by-default foreground polling worker; no API startup hook. | high |
| `wazuh_service.py` | `integrations/wazuh/service.py` | R6b | Tenant-integration settings/TLS/reference checks and existing client context manager. | high |
| `wazuh_status.py` | `integrations/wazuh/status.py` | R6b | Tenant-owned synchronization status and sanitized safe error categories. | high |
| `wazuh_sync.py` | `integrations/wazuh/sync.py` | R6b | Page-atomic checkpoint/evidence/audit synchronization, source validation and recovery. | high |

main.py remains the composition entrypoint; its route bodies migrate according to
the exact handler table below. No other module is split in the initial file moves.
Existing `scripts/`, `migrations/`, deploy files and tests keep their paths; update
only imports/patch references when their target module moves. This is not approval
to edit historical migration source, regenerate migrations or execute CLI commands.

## Architectural boundaries

- **Composition and HTTP:** main.py creates FastAPI and includes routers. API modules
  own paths, Depends, Query, DTOs and HTTP error/status mapping. Keep the exact
  dependency object identities and endpoint behavior. In the route-only move,
  existing SQL/transaction bodies move intact; do not smuggle a service rewrite
  into a path change. R12 may extract the existing multi-write algorithms, with
  transport errors mapped equivalently. Simple read queries do not need a generic
  repository abstraction merely for layering.
- **IAM:** authentication resolves the existing current API-key identity. Contracts,
  policy, admission and protected authority are separate responsibilities. Neither
  authentication nor a class's new package name grants roles. AuthorityProvider
  remains the read/current-epoch interface; do not make its protocol sufficient for
  provider eligibility or enable the incomplete PostgreSQL provider.
- **Analysts:** immutable evidence/proposal contracts -> assembly/evaluation -> prompt/
  parsing -> inference orchestration of the already allowed fake/mock providers.
  Provider-specific wire shaping belongs under analysts/providers. No provider may
  construct identity, tool permission, approval or verified source truth.
- **Gateway:** contracts are a pure leaf; dispatch is the single approved mocked
  authorization/disclosure boundary. Individual synthetic Wazuh adapter code sits
  under integrations/wazuh/gateway_adapter.py. Keep its source binding, result
  validation, test-only sinks and no-dispatch-on-denial behavior. No auto-discovery,
  dynamic provider loading or package initializer registration.
- **Evidence vs events:** evidence hashing covers the original provenance envelope;
  normalized events are derived snapshots in detection/events.py. Never replace
  original evidence with normalized/AI content or change canonical bytes/IDs.
- **Database:** db/models.py defines ORM mappings only; it does not import engine,
  settings, routes, domain contracts or services. db/session.py retains current
  runtime engine/session behavior and is imported only by existing operational
  consumers. Pure IAM/AI/gateway modules must not acquire it transitively.
- **Audit:** audit/service.py retains the canonical hash/chain and caller-transaction
  writer. Application log messages are diagnostics, not audit records. Do not
  replace append-only records with logging or relocate commit/lock boundaries.
- **Dependency injection:** continue explicit trusted inputs, sessions, fake clients,
  clocks, cancellation and test sinks. Existing operational dependency wiring stays
  at its current composition boundary. No import may issue operational capabilities,
  obtain secrets, connect, start workers or register live providers as a side effect.
- **Public/private interfaces:** preserve existing class/function names and signatures.
  Explicit public paths are full module paths, not giant package re-export lists.
  `_Contract`, `_checked`, `_Stop`, `_parse_search` and other already-used private
  helpers remain compatible internal dependencies during moves. Renaming/promoting
  them is a separate design task. Never create a second validator for convenience.

Cross-domain exceptions already present and deliberately retained: IAM/analysts
share leaf gateway contracts; normalized Wazuh events use the existing client
module's pure timestamp parser; disclosure policy calls synthetic adapter shape
checks; Wazuh status imports the HTTP response DTO. These are visible coupling
points, not new capabilities. Move them without semantic cleanup; consider later
small contract extractions only if dependency evidence justifies them. Do not
silently move TrustedContext into IAM or invent a competing identity contract.

## Import graph and cycle risks

AST analysis includes function-local imports, so it detects both eager and lazy
edges. There is one multi-module strongly connected component:

`analyst_inference -> ollama_inference -> analyst_inference`, with
`analyst_inference <-> ollama_prompt` and `ollama_inference -> ollama_prompt`.

Current break points are the function-local imports at analyst_inference.py:242
and :405 and ollama_prompt.py:89. The eager imports can initialize today because
those reverse edges are deferred. Preserve those execution sites exactly during
R5. Eager provider exports from analysts/__init__.py or providers/__init__.py could
turn the same graph into an import-time failure. No other multi-module cycle was
found in the current static app graph. Static absence does not prove absence of
runtime/plugin cycles; no arbitrary plugin loading was observed.

Additional package-level hazards:

1. **db.py -> db/** collides with an existing module. An eager db/__init__.py
   exporting engine/session would cause *every* db.models import to construct the
   configured engine and read settings. Use an empty db/__init__.py and migrate all
   in-repository `from app.db import ...` consumers to `app.db.session` atomically.
   Preserve app.models via a temporary explicit shim if needed. Do not introduce a
   lazy engine proxy or sys.modules alias to hide this behavior change. Legacy
   external `from app.db import engine` callers need a separately reviewed cutover;
   their existence cannot be ruled out by this repository inventory.
2. **evidence.py -> evidence/** and **audit.py -> audit/** also collide. The package
   initializer can expose the same existing hash/audit functions from the canonical
   implementation because these do not add settings/session dependencies beyond
   current audit imports. Keep classes/functions defined exactly once. Retain only
   the required facade symbols, never a second implementation.
3. **integrations/wazuh/** must have an empty initializer: importing its fake adapter
   or manifest cannot eagerly import the credential-backed service or scheduler.
   gateway/disclosure -> integrations/wazuh/gateway_adapter -> gateway/contracts is
   acyclic only if package initializers stay inert. Manifest's reverse dependency
   on disclosure is safe at module granularity but can cycle through eager facades.
4. **db/models vs authentication/audit:** db/models may not import IAM services,
   api or audit writers. Authentication and audit may depend on models; reversing
   those edges creates cycles and side effects. Keep Alembic registration centralized.
5. **API/core composition:** domain modules cannot import main.py or api routers.
   Router modules must not import the app object from main; expose APIRouter objects
   and include them in main. core/__init__.py must not import settings automatically.
6. **Class identity:** exact `type(...) is ...` checks are security boundaries in
   IAM, gateway and inference. Old/new paths must refer to the same class object.
   Duplicate source copies, reload during live evaluation and mixed shim/canonical
   classes can cause rejection or inconsistent checks. The unfinished IAM-03C
   reload failure demonstrates why compatibility cannot be assumed.

## Test and entrypoint legend

Test IDs below are shorthand for exact file paths, not proposed test renames.
D = direct AST imports of the module. I = full potential transitive impact via
app imports and test/helper imports (including D). I is deliberately conservative:
it identifies files to inspect, not proof every test case executes that dependency.
String/dynamic references are listed separately. No conftest.py was found; many
integration fixtures live inside test modules and are imported by other test files.

| Test ID | Exact current path | Execution classification for this plan |
| --- | --- | --- |
| T01 | `tests/test_analyst_contracts.py` | Reviewed stable offline selection; no operational configuration import |
| T02 | `tests/test_analyst_evaluation.py` | Reviewed stable offline selection; no operational configuration import |
| T03 | `tests/test_analyst_inference.py` | Reviewed stable offline selection; no operational configuration import |
| T04 | `tests/test_analyst_protocol.py` | Reviewed stable offline selection; no operational configuration import |
| T05 | `tests/test_api_keys.py` | Pure utility tests; safe to add after inspecting selected fixtures |
| T06 | `tests/test_audit.py` | Reviewed stable offline selection; no operational configuration import |
| T07 | `tests/test_audit_api.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T08 | `tests/test_audit_concurrency.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T09 | `tests/test_auth.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T10 | `tests/test_correlation_matches.py` | Reviewed stable offline selection; no operational configuration import |
| T11 | `tests/test_database_roles.py` | Reviewed stable offline selection; no operational configuration import |
| T12 | `tests/test_database_roles_integration.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T13 | `tests/test_detection_rule_groups.py` | Reviewed stable offline selection; no operational configuration import |
| T14 | `tests/test_detection_rules.py` | Reviewed stable offline selection; no operational configuration import |
| T15 | `tests/test_disclosure_policy.py` | Reviewed stable offline selection; no operational configuration import |
| T16 | `tests/test_event_correlation.py` | Reviewed stable offline selection; no operational configuration import |
| T17 | `tests/test_evidence.py` | Pure utility tests; safe to add after inspecting selected fixtures |
| T18 | `tests/test_evidence_api.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T19 | `tests/test_gateway_development_spec.py` | Reviewed stable offline selection; no operational configuration import |
| T20 | `tests/test_gateway_disclosure_enforcement.py` | Reviewed stable offline selection; no operational configuration import |
| T21 | `tests/test_gateway_permission_design.py` | Reviewed stable offline selection; no operational configuration import |
| T22 | `tests/test_health.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T23 | `tests/test_iam_admission.py` | Reviewed stable offline selection; no operational configuration import |
| T24 | `tests/test_iam_authority_provider.py` | Reviewed stable offline selection; no operational configuration import |
| T25 | `tests/test_iam_contracts.py` | Reviewed stable offline selection; no operational configuration import |
| T26 | `tests/test_iam_policy.py` | Reviewed stable offline selection; no operational configuration import |
| T27 | `tests/test_iam_postgres_authority.py` | Offline fake-session suite, currently 1 known failure; separate diagnostic run |
| T28 | `tests/test_ollama_inference.py` | Reviewed stable offline selection; no operational configuration import |
| T29 | `tests/test_ollama_preparation.py` | Reviewed stable offline selection; no operational configuration import |
| T30 | `tests/test_security_events.py` | Reviewed stable offline selection; no operational configuration import |
| T31 | `tests/test_tenant_isolation.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T32 | `tests/test_tool_gateway.py` | Reviewed stable offline selection; no operational configuration import |
| T33 | `tests/test_wazuh.py` | Mock HTTP / local CA fixture; inspect fixture path and deny sockets before including |
| T34 | `tests/test_wazuh_checkpoint_migration.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T35 | `tests/test_wazuh_checkpoints.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T36 | `tests/test_wazuh_cursor.py` | Reviewed stable offline selection; no operational configuration import |
| T37 | `tests/test_wazuh_gateway.py` | Reviewed stable offline selection; no operational configuration import |
| T38 | `tests/test_wazuh_ingestion_api.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T39 | `tests/test_wazuh_integrations.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T40 | `tests/test_wazuh_integrations_api.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T41 | `tests/test_wazuh_lease_migration.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T42 | `tests/test_wazuh_leases.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T43 | `tests/test_wazuh_manifest.py` | Reviewed stable offline selection; no operational configuration import |
| T44 | `tests/test_wazuh_pagination.py` | Mock HTTP / local CA fixture; inspect fixture path and deny sockets before including |
| T45 | `tests/test_wazuh_recovery.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T46 | `tests/test_wazuh_recovery_policy.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T47 | `tests/test_wazuh_scheduler.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T48 | `tests/test_wazuh_scheduler_integration.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T49 | `tests/test_wazuh_service.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T50 | `tests/test_wazuh_status_migration.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T51 | `tests/test_wazuh_sync.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T52 | `tests/test_wazuh_sync_concurrency.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T53 | `tests/test_wazuh_sync_policy.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |
| T54 | `tests/test_wazuh_sync_status.py` | Configuration/engine-import or DB integration risk; not in safe unmodified selection |

| Entry ID | Exact path | Existing use / dependency |
| --- | --- | --- |
| E1 | `services/api/app/main.py` | README ASGI target `uvicorn app.main:app --app-dir services/api --reload`; retain target, do not start it. |
| E2 | `services/api/app/provision_tenant.py` | `python -m app.provision_tenant` via main guard; operational write CLI, do not run. |
| E3 | `services/api/app/provision_api_key.py` | `python -m app.provision_api_key` via main guard; operational write/secret-output CLI, do not run. |
| E4 | `services/api/app/database_roles.py` | Print-only role-plan main guard, also imported by scripts/prepare_database_roles.py. |
| E5 | `services/api/app/wazuh_scheduler.py` | Explicit scheduler main guard, also imported by scripts/run_wazuh_scheduler.py; do not run. |
| E6 | `scripts/prepare_database_roles.py` | Adds services/api to sys.path then imports app.database_roles.main; keep script path. |
| E7 | `scripts/provision_wazuh_integration.py` | Direct audit/config/session/models/Indexer imports; provisions integration; do not run. |
| E8 | `scripts/run_wazuh_scheduler.py` | Adds services/api to sys.path then imports app.wazuh_scheduler.main; do not run. |
| E9 | `migrations/env.py` | Adds services/api to sys.path, imports app.config/settings, Base and eight mapped app.models classes; binds Base.metadata; do not execute. |

## Per-module dependency and migration ledger

Application imports include nested/lazy sites. `module:line` gives the current
importer's evidence location. External imports list Python/installed libraries,
not recommendations to install anything. Entrypoints include direct/transitive
reachability and the module's own CLI where applicable. The migration map above
provides the exact destination and risk for each block; stage labels are repeated
here so the dependency ledger can be used independently.

### `app` → `__init__.py` (R0)

- Responsibility / cycle or import risk: Empty application package marker. Risk: **low**.
- Incoming app imports: none found.
- Outgoing app imports: none found.
- Outgoing external imports: none.
- Tests: D = none; I = none.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.analyst_contracts` → `analysts/contracts.py` (R5)

- Responsibility / cycle or import risk: AI-01 tasks, immutable evidence snapshots, findings and structural evidence validation. Risk: **high**.
- Incoming app imports: `app.analyst_evaluation:14`, `app.analyst_inference:15`, `app.analyst_protocol:16`, `app.ollama_inference:14`, `app.ollama_prompt:8`.
- Outgoing app imports: `app.evidence:17`, `app.gateway_contracts:18`.
- Outgoing external imports: `datetime`, `hashlib`, `hmac`, `json`, `pydantic`, `re`, `typing`, `uuid`.
- Tests: D = T01, T02, T04, T29; I = T01, T02, T03, T04, T28, T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.analyst_evaluation` → `analysts/evaluation.py` (R5)

- Responsibility / cycle or import risk: AI-02 bounded input assembly and narrow deterministic evidence-support evaluation. Risk: **high**.
- Incoming app imports: `app.analyst_inference:16`, `app.analyst_protocol:17`, `app.ollama_inference:17`, `app.ollama_prompt:9`.
- Outgoing app imports: `app.analyst_contracts:14`, `app.gateway_contracts:15`.
- Outgoing external imports: `datetime`, `ipaddress`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T02, T03, T04, T29; I = T02, T03, T04, T28, T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.analyst_inference` → `analysts/inference.py` (R5)

- Responsibility / cycle or import risk: Model-independent registry/profiles, inference contracts, fake provider, admission and validation pipeline. Risk: **high; lazy-import SCC**.
- Incoming app imports: `app.ollama_inference:15`, `app.ollama_prompt:89`, `app.ollama_transport:11`.
- Outgoing app imports: `app.analyst_contracts:15`, `app.analyst_evaluation:16`, `app.analyst_protocol:17`, `app.gateway_contracts:18`, `app.ollama_prompt:242` (function-local; preserve deferred site), `app.ollama_inference:405` (function-local; preserve deferred site).
- Outgoing external imports: `dataclasses`, `datetime`, `hashlib`, `pydantic`, `threading`, `typing`, `uuid`.
- Tests: D = T03, T28, T29; I = T03, T28, T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.analyst_protocol` → `analysts/protocol.py` (R5)

- Responsibility / cycle or import risk: AI-03 prompt envelope, strict JSON proposal parsing and adversarial replay. Risk: **high**.
- Incoming app imports: `app.analyst_inference:17`, `app.ollama_inference:16`, `app.ollama_prompt:112`.
- Outgoing app imports: `app.analyst_contracts:16`, `app.analyst_evaluation:17`, `app.gateway_contracts:18`.
- Outgoing external imports: `datetime`, `hashlib`, `json`, `math`, `pydantic`, `typing`, `unicodedata`, `uuid`.
- Tests: D = T04; I = T03, T04, T28, T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.api_keys` → `iam/api_keys.py` (R10)

- Responsibility / cycle or import risk: API-key generation and SHA-256 hashing utilities. Risk: **medium**.
- Incoming app imports: `app.auth:8`, `app.provision_api_key:6`, `app.provision_tenant:6`.
- Outgoing app imports: none found.
- Outgoing external imports: `hashlib`, `secrets`.
- Tests: D = T05, T07, T09, T18, T31, T38, T40, T51; I = T05, T07, T09, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E2, E3, E5, E8; direct script/Alembic imports: none.

### `app.audit` → `audit/service.py` (R7)

- Responsibility / cycle or import risk: Canonical audit hashing/verification and tenant-locked append-only audit staging in caller transaction. Risk: **high; package-name collision**.
- Incoming app imports: `app.main:11`, `app.provision_api_key:7`, `app.wazuh_sync:18`.
- Outgoing app imports: `app.models:11`.
- Outgoing external imports: `datetime`, `hashlib`, `hmac`, `json`, `sqlalchemy`, `uuid`.
- Tests: D = T06, T07, T08, T12, T38, T45, T51, T52; I = T06, T07, T08, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E3, E5, E7, E8; direct script/Alembic imports: `scripts/provision_wazuh_integration.py:7`.

### `app.auth` → `iam/authentication.py` (R10)

- Responsibility / cycle or import risk: Existing API-key authentication dependency and frozen AuthenticatedPrincipal; no IAM runtime enforcement. Risk: **high**.
- Incoming app imports: `app.main:12`, `app.wazuh_scheduler:15`, `app.wazuh_sync:19`.
- Outgoing app imports: `app.api_keys:8`, `app.db:9`, `app.models:10`.
- Outgoing external imports: `dataclasses`, `fastapi`, `sqlalchemy`, `uuid`.
- Tests: D = T09, T51; I = T07, T09, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

### `app.config` → `core/config.py` (R8)

- Responsibility / cycle or import risk: Pydantic settings and eager settings construction; reads configured environment file on import. Risk: **high**.
- Incoming app imports: `app.db:4`, `app.wazuh_leases:10`, `app.wazuh_scheduler:16`, `app.wazuh_service:4`, `app.wazuh_sync:20`.
- Outgoing app imports: none found.
- Outgoing external imports: `pydantic`, `pydantic_settings`.
- Tests: D = T12, T47, T49, T51, T52, T53, T54; I = T07, T08, T09, T12, T18, T22, T31, T34, T35, T38, T39, T40, T41, T42, T45, T46, T47, T48, T49, T50, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E2, E3, E5, E7, E8, E9; direct script/Alembic imports: `migrations/env.py:16`, `scripts/provision_wazuh_integration.py:8`.

### `app.database_roles` → `db/role_plan.py` (R9)

- Responsibility / cycle or import risk: Pure PostgreSQL role SQL rendering and print-only CLI; does not execute SQL. Risk: **medium**.
- Incoming app imports: none found.
- Outgoing app imports: `app.models:7`.
- Outgoing external imports: `argparse`, `dataclasses`, `re`.
- Tests: D = T11, T12; I = T11, T12.
- Runtime/operational entrypoints: E4 (self), E6; direct script/Alembic imports: `scripts/prepare_database_roles.py:8`.

### `app.db` → `db/session.py` (R9)

- Responsibility / cycle or import risk: Configured SQLAlchemy engine, session factory and FastAPI session dependency; import constructs engine. Risk: **high**.
- Incoming app imports: `app.auth:9`, `app.main:17`, `app.provision_api_key:8`, `app.provision_tenant:7`, `app.wazuh_scheduler:17`.
- Outgoing app imports: `app.config:4`.
- Outgoing external imports: `sqlalchemy`.
- Tests: D = T07, T08, T12, T18, T31, T34, T35, T38, T39, T40, T41, T50, T51, T52; I = T07, T08, T09, T12, T18, T22, T31, T34, T35, T38, T39, T40, T41, T42, T45, T46, T47, T48, T50, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E2, E3, E5, E7, E8; direct script/Alembic imports: `scripts/provision_wazuh_integration.py:9`.

### `app.detection_rules` → `detection/rules.py` (R1)

- Responsibility / cycle or import risk: Bounded rule contracts, matching and source-backed match trace. Risk: **low-medium**.
- Incoming app imports: `app.event_correlation:16`.
- Outgoing app imports: `app.security_events:16`.
- Outgoing external imports: `datetime`, `hashlib`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T10, T13, T14; I = T10, T13, T14, T16.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.disclosure_policy` → `gateway/disclosure.py` (R3)

- Responsibility / cycle or import risk: TG-03A pure consent/disclosure assessment, including synthetic Wazuh shape checks. Risk: **high**.
- Incoming app imports: `app.tool_gateway:21`, `app.wazuh_manifest:19`.
- Outgoing app imports: `app.gateway_contracts:18`, `app.wazuh_gateway:19`.
- Outgoing external imports: `datetime`, `hashlib`, `ipaddress`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T15, T20, T32, T37, T43; I = T01, T02, T03, T04, T15, T19, T20, T21, T23, T24, T25, T26, T27, T28, T29, T32, T37, T43.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.event_correlation` → `detection/correlation.py` (R1)

- Responsibility / cycle or import risk: Pure fixed-window tenant-scoped correlation and verified match grouping. Risk: **low-medium**.
- Incoming app imports: none found.
- Outgoing app imports: `app.detection_rules:16`, `app.security_events:17`.
- Outgoing external imports: `datetime`, `hashlib`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T10, T16; I = T10, T16.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.evidence` → `evidence/hashing.py` (R2)

- Responsibility / cycle or import risk: Canonical evidence SHA-256 hashing; not an evidence repository or retrieval service. Risk: **medium; package-name collision**.
- Incoming app imports: `app.analyst_contracts:17`, `app.main:18`, `app.security_events:18`, `app.wazuh_sync:21`.
- Outgoing app imports: none found.
- Outgoing external imports: `datetime`, `hashlib`, `json`, `typing`.
- Tests: D = T01, T02, T08, T17, T18, T30, T51; I = T01, T02, T03, T04, T07, T08, T10, T12, T13, T14, T16, T17, T18, T22, T28, T29, T30, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

### `app.gateway_contracts` → `gateway/contracts.py` (R3)

- Responsibility / cycle or import risk: Leaf strict/frozen base contracts, trusted context and exact tool-request binding shared by IAM/AI/gateway. Risk: **high fan-in; no cyclic imports**.
- Incoming app imports: `app.analyst_contracts:18`, `app.analyst_evaluation:15`, `app.analyst_inference:18`, `app.analyst_protocol:18`, `app.disclosure_policy:18`, `app.iam_admission:10`, `app.iam_contracts:14`, `app.iam_policy:13`, `app.iam_postgres_authority:17`, `app.ollama_inference:18`, `app.ollama_prompt:10`, `app.tool_gateway:18`, `app.wazuh_gateway:16`, `app.wazuh_manifest:20`.
- Outgoing app imports: none found.
- Outgoing external imports: `ipaddress`, `pydantic`, `typing`, `uuid`.
- Tests: D = T01, T20, T25, T27, T43; I = T01, T02, T03, T04, T15, T19, T20, T21, T23, T24, T25, T26, T27, T28, T29, T32, T37, T43.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.iam_admission` → `iam/admission.py` (R4a)

- Responsibility / cycle or import risk: IAM-03A synthetic origin/issuer/freshness admission, API-key mapping and IAM-02 delegation. Risk: **high**.
- Incoming app imports: `app.iam_authority_provider:10`.
- Outgoing app imports: `app.iam_contracts:8`, `app.iam_policy:9`, `app.gateway_contracts:10`.
- Outgoing external imports: `dataclasses`, `datetime`, `pydantic`, `typing`, `uuid`.
- Tests: D = T23, T24; I = T23, T24, T27.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.iam_authority_provider` → `iam/authority_provider.py` (R4a)

- Responsibility / cycle or import risk: IAM-03B read/current-epoch protocol, synthetic provider registration and admission bridge. Risk: **high**.
- Incoming app imports: `app.iam_postgres_authority:16`.
- Outgoing app imports: `app.iam_contracts:8`, `app.iam_policy:9`, `app.iam_admission:10`.
- Outgoing external imports: `dataclasses`, `datetime`, `pydantic`, `typing`, `uuid`.
- Tests: D = T24, T27; I = T24, T27.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.iam_contracts` → `iam/contracts.py` (R4a)

- Responsibility / cycle or import risk: IAM-01 immutable identities, scopes, provenance, approval and graph validation contracts. Risk: **high**.
- Incoming app imports: `app.iam_admission:8`, `app.iam_authority_provider:8`, `app.iam_policy:12`, `app.iam_postgres_authority:14`.
- Outgoing app imports: `app.gateway_contracts:14`.
- Outgoing external imports: `datetime`, `hashlib`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T23, T24, T25, T26, T27; I = T23, T24, T25, T26, T27.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.iam_policy` → `iam/policy.py` (R4a)

- Responsibility / cycle or import risk: IAM-02 pure role/action/classification policy evaluator and non-executable decisions. Risk: **high**.
- Incoming app imports: `app.iam_admission:9`, `app.iam_authority_provider:9`, `app.iam_postgres_authority:15`.
- Outgoing app imports: `app.iam_contracts:12`, `app.gateway_contracts:13`.
- Outgoing external imports: `datetime`, `pydantic`, `typing`, `uuid`.
- Tests: D = T23, T24, T26; I = T23, T24, T26, T27.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.iam_postgres_authority` → `iam/postgres_authority.py` (R4b)

- Responsibility / cycle or import risk: Unfinished IAM-03C injected-session read-only skeleton; always fails closed on missing IAM schema. Risk: **high; blocked by existing failing test**.
- Incoming app imports: none found.
- Outgoing app imports: `app.models:13`, `app.iam_contracts:14`, `app.iam_policy:15`, `app.iam_authority_provider:16`, `app.gateway_contracts:17`.
- Outgoing external imports: `dataclasses`, `datetime`, `pydantic`, `sqlalchemy`, `typing`, `uuid`.
- Tests: D = T27; I = T27.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.main` → `main.py` (R11)

- Responsibility / cycle or import risk: ASGI object, 16 route handlers, HTTP error mapping and current evidence/Wazuh transactions; retain entrypoint and later extract listed handlers. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.audit:11`, `app.auth:12`, `app.db:17`, `app.evidence:18`, `app.wazuh:19`, `app.wazuh_sync:20`, `app.wazuh_status:21`, `app.wazuh_service:22`, `app.models:26`, `app.schemas:33`.
- Outgoing external imports: `datetime`, `fastapi`, `hmac`, `sqlalchemy`, `uuid`.
- Tests: D = T07, T12, T18, T22, T31, T38, T40, T51; I = T07, T12, T18, T22, T31, T38, T40, T42, T45, T48, T51, T52, T54.
- Runtime/operational entrypoints: E1 (self); direct script/Alembic imports: none.

### `app.models` → `db/models.py` (R9)

- Responsibility / cycle or import risk: One DeclarativeBase and eight tenant/evidence/audit/Wazuh ORM models; retain shared metadata. Risk: **high**.
- Incoming app imports: `app.audit:11`, `app.auth:10`, `app.database_roles:7`, `app.iam_postgres_authority:13`, `app.main:26`, `app.provision_api_key:9`, `app.provision_tenant:8`, `app.wazuh_leases:11`, `app.wazuh_service:5`, `app.wazuh_status:7`, `app.wazuh_sync:22`.
- Outgoing app imports: none found.
- Outgoing external imports: `datetime`, `sqlalchemy`, `uuid`.
- Tests: D = T07, T08, T12, T18, T31, T34, T35, T38, T39, T40, T41, T42, T45, T48, T50, T51, T52, T54; I = T06, T07, T08, T09, T11, T12, T18, T22, T27, T31, T34, T35, T38, T39, T40, T41, T42, T45, T46, T47, T48, T49, T50, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E2, E3, E4, E5, E6, E7, E8, E9; direct script/Alembic imports: `migrations/env.py:17`, `scripts/provision_wazuh_integration.py:10`.

### `app.ollama_inference` → `analysts/providers/ollama.py` (R5)

- Responsibility / cycle or import risk: Strict Ollama chat mapping via injected MockTransport only; mandatory analyst validators. Risk: **high; lazy-import SCC**.
- Incoming app imports: `app.analyst_inference:405`, `app.ollama_transport:12`.
- Outgoing app imports: `app.analyst_contracts:14`, `app.analyst_inference:15`, `app.analyst_protocol:16`, `app.analyst_evaluation:17`, `app.gateway_contracts:18`, `app.ollama_prompt:19`.
- Outgoing external imports: `dataclasses`, `datetime`, `hashlib`, `httpx`, `pydantic`, `typing`.
- Tests: D = T28, T29; I = T03, T28, T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.ollama_prompt` → `analysts/providers/ollama_prompt.py` (R5)

- Responsibility / cycle or import risk: Deterministic schema-title optimization and estimated wire/context budgeting. Risk: **high; lazy-import SCC**.
- Incoming app imports: `app.analyst_inference:242`, `app.ollama_inference:19`.
- Outgoing app imports: `app.analyst_contracts:8`, `app.analyst_evaluation:9`, `app.gateway_contracts:10`, `app.analyst_inference:89` (function-local; preserve deferred site), `app.analyst_protocol:112`.
- Outgoing external imports: `hashlib`, `json`, `pydantic`, `typing`.
- Tests: D = T29; I = T03, T28, T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.ollama_transport` → `analysts/providers/ollama_transport.py` (R5)

- Responsibility / cycle or import risk: Disabled-by-default live-capable transport mechanics and gated provider; no operational clearance issuer. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.analyst_inference:11`, `app.ollama_inference:12`.
- Outgoing external imports: `dataclasses`, `httpx`, `math`.
- Tests: D = T29; I = T29.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.provision_api_key` → `iam/provision_api_key.py` (R10)

- Responsibility / cycle or import risk: Explicit CLI provisioning and auditing of API keys; must never execute during refactor verification. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.api_keys:6`, `app.audit:7`, `app.db:8`, `app.models:9`.
- Outgoing external imports: `argparse`, `sqlalchemy`, `sys`.
- Tests: D = none; I = none.
- Runtime/operational entrypoints: E3 (self); direct script/Alembic imports: none.

### `app.provision_tenant` → `iam/provision_tenant.py` (R10)

- Responsibility / cycle or import risk: Explicit CLI creation of tenant and initial API key; must never execute during refactor verification. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.api_keys:6`, `app.db:7`, `app.models:8`.
- Outgoing external imports: `argparse`, `sqlalchemy`, `sys`.
- Tests: D = none; I = none.
- Runtime/operational entrypoints: E2 (self); direct script/Alembic imports: none.

### `app.schemas` → `api/v1/schemas.py` (R11)

- Responsibility / cycle or import risk: HTTP request/response DTOs for tenant, evidence, lineage, audit and Wazuh endpoints. Risk: **medium**.
- Incoming app imports: `app.main:33`, `app.wazuh_status:8`.
- Outgoing app imports: none found.
- Outgoing external imports: `datetime`, `pydantic`, `typing`, `uuid`.
- Tests: D = T54; I = T07, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

### `app.security_events` → `detection/events.py` (R1)

- Responsibility / cycle or import risk: Pure normalized event derivation from explicit hashed Wazuh evidence snapshots. Risk: **low-medium**.
- Incoming app imports: `app.detection_rules:16`, `app.event_correlation:17`.
- Outgoing app imports: `app.evidence:18`, `app.wazuh:19`.
- Outgoing external imports: `datetime`, `hmac`, `ipaddress`, `math`, `pydantic`, `re`, `typing`, `uuid`.
- Tests: D = T30; I = T10, T13, T14, T16, T30.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.tool_gateway` → `gateway/dispatch.py` (R3)

- Responsibility / cycle or import risk: TG-01/TG-03B deterministic authorization/disclosure boundary, explicit synthetic registry and test-only sinks. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.gateway_contracts:18`, `app.disclosure_policy:21`, `app.wazuh_gateway:22`.
- Outgoing external imports: `hashlib`, `hmac`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T01, T02, T03, T04, T15, T20, T21, T23, T24, T25, T26, T28, T29, T32, T37, T43; I = T01, T02, T03, T04, T15, T20, T21, T23, T24, T25, T26, T27, T28, T29, T32, T37, T43.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.wazuh` → `integrations/wazuh/client.py` (R6a)

- Responsibility / cycle or import risk: Existing read-only Indexer HTTP/PIT client, normalization, timestamp parsing and scope fingerprints. Risk: **high; operational client exists but will not be invoked**.
- Incoming app imports: `app.main:19`, `app.security_events:19`, `app.wazuh_service:6`, `app.wazuh_sync:23`.
- Outgoing app imports: `app.wazuh_cursor:13`.
- Outgoing external imports: `contextlib`, `datetime`, `hashlib`, `httpx`, `json`, `pathlib`, `re`, `ssl`, `typing`, `uuid`.
- Tests: D = T10, T30, T33, T38, T44, T46, T51, T53; I = T07, T10, T12, T13, T14, T16, T18, T22, T30, T31, T33, T38, T40, T42, T44, T45, T46, T47, T48, T49, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E7, E8; direct script/Alembic imports: `scripts/provision_wazuh_integration.py:11`.

### `app.wazuh_cursor` → `integrations/wazuh/cursor.py` (R6a)

- Responsibility / cycle or import risk: Pure validated stable-sort cursor and serialization. Risk: **low**.
- Incoming app imports: `app.wazuh:13`.
- Outgoing app imports: none found.
- Outgoing external imports: `dataclasses`, `json`, `re`, `uuid`.
- Tests: D = T36; I = T07, T10, T12, T13, T14, T16, T18, T22, T30, T31, T33, T36, T38, T40, T42, T44, T45, T46, T47, T48, T49, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E7, E8; direct script/Alembic imports: none.

### `app.wazuh_gateway` → `integrations/wazuh/gateway_adapter.py` (R6a)

- Responsibility / cycle or import risk: TG-04A closed synthetic Wazuh adapter, source bindings and fake client. Risk: **high; must remain synthetic**.
- Incoming app imports: `app.disclosure_policy:19`, `app.tool_gateway:22`.
- Outgoing app imports: `app.gateway_contracts:16`.
- Outgoing external imports: `hashlib`, `hmac`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T37, T43; I = T01, T02, T03, T04, T15, T19, T20, T21, T23, T24, T25, T26, T27, T28, T29, T32, T37, T43.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.wazuh_leases` → `integrations/wazuh/leases.py` (R6b)

- Responsibility / cycle or import risk: PostgreSQL-clock fenced leases and lock ordering. Risk: **high**.
- Incoming app imports: `app.wazuh_sync:24`.
- Outgoing app imports: `app.config:10`, `app.models:11`, `app.wazuh_status:12`.
- Outgoing external imports: `dataclasses`, `datetime`, `sqlalchemy`, `uuid`.
- Tests: D = T42, T48, T54; I = T07, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

### `app.wazuh_manifest` → `integrations/wazuh/manifest.py` (R6a)

- Responsibility / cycle or import risk: TG-04B-PRE2 offline source-manifest clearance/query planning with executable=False. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.disclosure_policy:19`, `app.gateway_contracts:20`.
- Outgoing external imports: `datetime`, `hashlib`, `hmac`, `json`, `pydantic`, `typing`, `uuid`.
- Tests: D = T19, T43; I = T19, T43.
- Runtime/operational entrypoints: none found; direct script/Alembic imports: none.

### `app.wazuh_scheduler` → `integrations/wazuh/scheduler.py` (R6b)

- Responsibility / cycle or import risk: Explicit disabled-by-default foreground polling worker; no API startup hook. Risk: **high**.
- Incoming app imports: none found.
- Outgoing app imports: `app.auth:15`, `app.config:16`, `app.db:17`, `app.wazuh_status:18`, `app.wazuh_sync:19`.
- Outgoing external imports: `argparse`, `fastapi`, `logging`, `os`, `pydantic`, `signal`, `sqlalchemy`, `threading`, `time`, `uuid`.
- Tests: D = T47, T48; I = T47, T48.
- Runtime/operational entrypoints: E5 (self), E8; direct script/Alembic imports: `scripts/run_wazuh_scheduler.py:8`.

### `app.wazuh_service` → `integrations/wazuh/service.py` (R6b)

- Responsibility / cycle or import risk: Tenant-integration settings/TLS/reference checks and existing client context manager. Risk: **high**.
- Incoming app imports: `app.main:22`, `app.wazuh_sync:28`.
- Outgoing app imports: `app.config:4`, `app.models:5`, `app.wazuh:6`.
- Outgoing external imports: `contextlib`, `pathlib`.
- Tests: D = T49; I = T07, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T49, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

### `app.wazuh_status` → `integrations/wazuh/status.py` (R6b)

- Responsibility / cycle or import risk: Tenant-owned synchronization status and sanitized safe error categories. Risk: **high**.
- Incoming app imports: `app.main:21`, `app.wazuh_leases:12`, `app.wazuh_scheduler:18`, `app.wazuh_sync:29`.
- Outgoing app imports: `app.models:7`, `app.schemas:8`.
- Outgoing external imports: `sqlalchemy`, `typing`.
- Tests: D = T54; I = T07, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

### `app.wazuh_sync` → `integrations/wazuh/sync.py` (R6b)

- Responsibility / cycle or import risk: Page-atomic checkpoint/evidence/audit synchronization, source validation and recovery. Risk: **high**.
- Incoming app imports: `app.main:20`, `app.wazuh_scheduler:19`.
- Outgoing app imports: `app.audit:18`, `app.auth:19`, `app.config:20`, `app.evidence:21`, `app.models:22`, `app.wazuh:23`, `app.wazuh_leases:24`, `app.wazuh_service:28`, `app.wazuh_status:29`.
- Outgoing external imports: `dataclasses`, `datetime`, `hashlib`, `hmac`, `json`, `pydantic`, `sqlalchemy`, `threading`, `time`, `uuid`.
- Tests: D = T12, T45, T46, T47, T48, T51, T52, T53, T54; I = T07, T12, T18, T22, T31, T38, T40, T42, T45, T46, T47, T48, T51, T52, T53, T54.
- Runtime/operational entrypoints: E1, E5, E8; direct script/Alembic imports: none.

## Literal import, monkeypatch and guard updates

A simple `from app.old import ...` search is insufficient. The following exact
string references must move with their defining modules. Keep patches aimed at the
new module that actually owns the function globals, not an inert re-export shim.
Security-denied import checks must cover both old and new paths during transition
and protect submodules/prefixes, not just the old exact string. Do not weaken the
no-I/O tests to accommodate an unsafe eager initializer.

| Current source | Literal reference | Required handling |
| --- | --- | --- |
| `tests/test_analyst_contracts.py:150` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_contracts.py:150` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_evaluation.py:164` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_evaluation.py:164` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_inference.py:223` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_inference.py:223` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_protocol.py:188` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_analyst_protocol.py:188` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_admission.py:181` | `app.auth` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_admission.py:181` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_admission.py:181` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_authority_provider.py:187` | `app.auth` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_authority_provider.py:187` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_authority_provider.py:187` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_contracts.py:221` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_contracts.py:221` | `app.auth` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_contracts.py:221` | `app.audit` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_contracts.py:221` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_policy.py:279` | `app.auth` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_policy.py:279` | `app.audit` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_policy.py:279` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_policy.py:279` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_postgres_authority.py:180` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_postgres_authority.py:180` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_iam_postgres_authority.py:180` | `app.auth` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_ollama_inference.py:150` | `app.db` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_ollama_inference.py:150` | `app.config` | Extend forbidden-import guards to canonical new paths and their relevant prefixes; retain old names while shims exist. |
| `tests/test_ollama_preparation.py:57` | `app.analyst_protocol` | Use `app.analysts.protocol` for `_OUTPUT_SCHEMA`; same schema object and canonical bytes. |
| `tests/test_wazuh_ingestion_api.py:151` | `app.main.open_wazuh_client` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_ingestion_api.py:305` | `app.main.open_wazuh_client` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_ingestion_api.py:336` | `app.main.open_wazuh_client` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_recovery.py:17` | `app.wazuh_sync.retry_wait` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_recovery.py:28` | `app.wazuh_sync.retry_wait` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_recovery.py:88` | `app.wazuh_sync.retry_wait` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_recovery.py:98` | `app.wazuh_sync.retry_wait` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_scheduler.py:125` | `app.wazuh_scheduler.run_scheduled_job` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_scheduler.py:133` | `app.wazuh_scheduler.run_scheduled_job` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_scheduler.py:152` | `app.wazuh_scheduler.run_scheduled_job` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_scheduler.py:168` | `app.wazuh_scheduler.signal.signal` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_scheduler.py:174` | `app.wazuh_scheduler.WazuhScheduler` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_service.py:154` | `app.wazuh_service.WazuhIndexerClient` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync.py:124` | `app.wazuh_sync.open_wazuh_client` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync.py:125` | `app.wazuh_sync.utcnow` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync.py:357` | `app.wazuh_sync.utcnow` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync.py:184` | `app.wazuh_sync.store_alert` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync.py:186` | `app.wazuh_sync.record_audit_event` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync_status.py:153` | `app.wazuh_sync.open_wazuh_client` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync_status.py:172` | `app.wazuh_sync.utcnow` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |
| `tests/test_wazuh_sync_status.py:222` | `app.wazuh_sync.release_lease` | Update patch target to the canonical new defining module; preserve patch effect and invocation counts. |

Also inspect module-object monkeypatches and helper imports in the D/I test sets.
Examples include module aliases in test_correlation_matches.py, module-object
patches of tool_gateway.execute in security tests, and importlib.reload in the
unfinished IAM-03C test. Do not move test helpers into conftest.py automatically:
that could import database/engine fixtures during collection of every pure test.

## Exact API extraction map (R11, then optional R12)

All current route functions are in services/api/app/main.py. Keep function names,
paths, methods, parameter/default constraints, dependencies, DTOs, tags, statuses,
registration order and OpenAPI operation IDs equivalent. `/health` and `/ready`
remain outside `/v1`. Preserve the current order below when including routers
(the Wazuh sync handlers currently register before system routes).

| Current handler:line | Method and path | Proposed route module |
| --- | --- | --- |
| `synchronize_wazuh:61` | `POST /v1/integrations/wazuh/{integration_id}/sync` | `api/v1/wazuh.py` |
| `get_wazuh_sync_status:75` | `GET /v1/integrations/wazuh/{integration_id}/sync/status` | `api/v1/wazuh.py` |
| `health:94` | `GET /health` | `api/system.py` |
| `readiness:103` | `GET /ready` | `api/system.py` |
| `get_tenant:129` | `GET /v1/tenant` | `api/v1/tenant.py` |
| `ingest_evidence:157` | `POST /v1/evidence` | `api/v1/evidence.py` |
| `list_evidence:238` | `GET /v1/evidence` | `api/v1/evidence.py` |
| `get_evidence:280` | `GET /v1/evidence/{evidence_id}` | `api/v1/evidence.py` |
| `verify_evidence_integrity:312` | `GET /v1/evidence/{evidence_id}/verify` | `api/v1/evidence.py` |
| `create_evidence_lineage:373` | `POST /v1/evidence/{parent_evidence_id}/lineage` | `api/v1/evidence.py` |
| `list_evidence_lineage:467` | `GET /v1/evidence/{evidence_id}/lineage` | `api/v1/evidence.py` |
| `list_audit_logs:528` | `GET /v1/audit-logs` | `api/v1/audit.py` |
| `verify_audit_logs:588` | `GET /v1/audit-logs/verify` | `api/v1/audit.py` |
| `list_wazuh_integrations:619` | `GET /v1/integrations/wazuh` | `api/v1/wazuh.py` |
| `get_wazuh_integration:654` | `GET /v1/integrations/wazuh/{integration_id}` | `api/v1/wazuh.py` |
| `ingest_wazuh_alerts:686` | `POST /v1/integrations/wazuh/{integration_id}/ingest` | `api/v1/wazuh.py` |

To preserve exact registration ordering, the Wazuh route module may expose two
APIRouter objects (sync first, legacy listing/ingestion later); do not duplicate
handlers or change path matching to make a single include convenient. Capture an
ordered route/OpenAPI baseline before deciding whether exact registration order
can be relaxed. No new paths or startup/lifespan hooks.

R12, only after the route-only stage is validated: extract ingest_evidence and
create_evidence_lineage transaction bodies into evidence/operations.py; extract
the existing ingest_wazuh_alerts algorithm into integrations/wazuh/ingestion.py.
Route wrappers retain request validation and HTTP mappings. Preserve atomicity,
commit/rollback/refresh ownership, duplicate handling, tenant filters, collection
provenance and hashing. Do not merge the legacy ingestion algorithm with sync_wazuh
or replace either with Tool Gateway dispatch. Split extraction by domain/substage;
no generic repository layer or new transactional semantics.

## Incremental stages and implementation gates

Each stage is a separate proposed approval boundary. Exact file lists come from
the migration table and are repeated below. Import updates for a stage are the
union of its modules' incoming app imports, direct script/Alembic consumers, D/I
tests and the literal-reference table. Use the current-to-target map mechanically:
`from app import old as alias` becomes an import from the named new package/module;
`from app.old import symbol` becomes `from app.package.module import symbol`.
Preserve aliases and function-local sites. Re-scan before each stage because this
inventory is a snapshot, not a permanent guarantee.

Common acceptance for every stage: no behavioral/security/configuration changes;
one canonical implementation; deterministic contract/schema/hash golden values
unchanged; focused D/I tests appropriate to their safety classification; the stable
offline security suite passes; memory compilation and whitespace checks pass; no
new cycle or eager configuration/engine import. Missing separately authorized DB
checks are explicit validation limits, not a reason to claim full operational
parity. Do not run those tests to unblock a move without approval.

Common rollback: preserve an exact before-stage file manifest and import/patch
changes; reverse only that stage's moves and references if verification fails,
including its newly created package initializers and temporary shims. Do not use
`git reset --hard`, `git clean`, checkout-all, or delete unrelated untracked work.
This tree is not fully committed, so HEAD is not a complete recovery artifact.
Never run migrations or change data to reverse a source-layout stage.

| Stage | Exact current files / change | Compatibility, tests and acceptance beyond common rules |
| --- | --- | --- |
| R0 | No moves. Record current files, contract/hash examples, route metadata and import graph. | Establish selected offline baseline; explicitly quarantine unfinished IAM-03C. Do not fix its failure as part of the inventory. No migration/provisioning commands. |
| **R1 (recommended first)** | security_events.py → detection/events.py; detection_rules.py → detection/rules.py; event_correlation.py → detection/correlation.py; add only detection/__init__.py. | Update imports within these three modules and all test/alias references in their ledger. Explicit temporary old-path re-exports may preserve external imports. Run test_security_events.py, test_detection_rules.py, test_detection_rule_groups.py, test_event_correlation.py, test_correlation_matches.py, then stable offline security suite. Same normalized IDs, condition traces and tenant/window grouping; no new normalization/correlation behavior. |
| R2 | evidence.py → evidence/hashing.py; evidence/__init__.py exposes the existing hash function. | Package collision handled atomically; no simultaneous evidence.py and evidence/ ambiguity. Update analyst contracts, normalized events, main, sync and related tests per ledger. Hash golden vectors and analyst snapshot digests unchanged. No persistence extraction yet. |
| R3 | gateway_contracts.py → gateway/contracts.py; disclosure_policy.py → gateway/disclosure.py; tool_gateway.py → gateway/dispatch.py; add inert gateway/__init__.py. | Preserve exact class identity across temporary old-path shims; explicitly re-export used private helpers. Keep imports of the unmoved synthetic Wazuh adapter at their old path until R6a. Run all gateway/disclosure/design/manifest and IAM/AI tests. Every denial still causes zero adapter calls; consent assessment never becomes execution permission. |
| R4a | iam_contracts.py → iam/contracts.py; iam_policy.py → iam/policy.py; iam_admission.py → iam/admission.py; iam_authority_provider.py → iam/authority_provider.py; add inert iam/__init__.py. | Update imports in incomplete iam_postgres_authority.py only if separately approved as a mechanical caller update; otherwise keep a temporary canonical class-identical compatibility shim. No changed issuer trust, current epoch checks or provider eligibility. Existing IAM-01/02/03A/03B tests and all gateway/analyst tests. |
| R4b (blocked) | iam_postgres_authority.py → iam/postgres_authority.py. | Only after its current failure and incomplete verification are resolved under separate authorization. Keep fail-closed schema gap and no bridge eligibility. Never use a path move to claim real PostgreSQL support. Its test remains a named diagnostic until green. |
| R5 | analyst_contracts.py → analysts/contracts.py; analyst_evaluation.py → analysts/evaluation.py; analyst_protocol.py → analysts/protocol.py; analyst_inference.py → analysts/inference.py; ollama_inference.py → analysts/providers/ollama.py; ollama_prompt.py → analysts/providers/ollama_prompt.py; ollama_transport.py → analysts/providers/ollama_transport.py. | Add inert analysts/ and analysts/providers/ initializers. Preserve lazy imports exactly, patch/dynamic-schema targets and exact type checks. Run all seven analyst/Ollama suites plus IAM/gateway tests. No real HTTPTransport construction, inference, fallback, tool use or capability issuance. Contract/schema/prompt accounting unchanged. |
| R6a | wazuh.py → integrations/wazuh/client.py; wazuh_cursor.py → integrations/wazuh/cursor.py; wazuh_gateway.py → integrations/wazuh/gateway_adapter.py; wazuh_manifest.py → integrations/wazuh/manifest.py. | Add only inert integrations/ and integrations/wazuh/ initializers; no adapter registration. Update gateway and normalized-event cross-domain imports. Run cursor, fake gateway, manifest, disclosure, normalized/detection/correlation suites. Add mocked client/pagination suites only with reviewed local CA fixture and denied sockets. No live Wazuh probe. |
| R6b | wazuh_service.py → integrations/wazuh/service.py; wazuh_sync.py → integrations/wazuh/sync.py; wazuh_leases.py → integrations/wazuh/leases.py; wazuh_status.py → integrations/wazuh/status.py; wazuh_scheduler.py → integrations/wazuh/scheduler.py. | Update scripts/run_wazuh_scheduler.py and scripts/provision_wazuh_integration.py import paths, never execute them. Preserve lease/integration/checkpoint/tenant lock ordering, retries, timestamps, transaction/fence behavior and scheduler disabled state. Fake-session/mock tests require guarded config imports; DB concurrency/recovery tests require separate test-DB authorization. Do not claim full parity from compilation alone. |
| R7 | audit.py → audit/service.py; audit/__init__.py exposes only existing functions required by callers. | Update main/sync/provisioning scripts and tests; no hash serialization or tenant lock change. Run pure test_audit.py and all stable security tests. DB atomicity/concurrency/mutation tests are deferred pending separate authorization; never invoke audit writes in import checks. |
| R8 | config.py → core/config.py; add inert core/__init__.py. | Old config shim may temporarily expose the same Settings/settings objects. Update runtime consumers and migrations/env.py import only; never run Alembic. Update security guards for app.core.config and old config names. Do not change defaults, env_file loading or settings instantiation timing of existing runtime callers. |
| R9 | models.py → db/models.py; db.py → db/session.py; database_roles.py → db/role_plan.py; add empty db/__init__.py. | Atomic app.db collision cutover. Update auth, main, provisioning, Wazuh modules, scripts, migrations/env.py and all affected tests. Do not eagerly re-export session from db/__init__.py. One Base.metadata object, same table/constraint/index/FK definitions and migration revisions. Role renderer still prints only. Obtain acceptance of any external app.db import-path break before implementation. No model split, schema diff, migration or PostgreSQL access. |
| R10 | auth.py → iam/authentication.py; api_keys.py → iam/api_keys.py; provision_tenant.py → iam/provision_tenant.py; provision_api_key.py → iam/provision_api_key.py. | Preserve AuthenticatedPrincipal and get_db object identity for Depends/overrides; no actual IAM runtime wiring. Keep temporary old python -m wrappers with guarded main if needed, never execute provisioning. Run pure key tests; fake auth tests only in no-I/O/config-stub harness. Existing DB tenant isolation remains separately gated. |
| R11 | Keep main.py composition; schemas.py → api/v1/schemas.py; extract 16 functions to api/system.py and api/v1/{tenant,evidence,audit,wazuh}.py according to exact handler map. | Add only required API initializers, preserve DTO identities and ordered router registration. Update all app.main patch targets to the owning routers, while preserving app.main:app. Source-to-AST checks and guarded no-DB FastAPI route/OpenAPI registration checks are mandatory. Do not invoke readiness, ingestion or dependency DB sessions. API DB regression parity remains unverified until separately authorized. |
| R12a / R12b (optional separate approvals) | Existing evidence transaction bodies → evidence/operations.py; existing legacy Wazuh ingestion body → integrations/wazuh/ingestion.py. | One domain per substage. Keep wrappers/HTTP errors and commit ownership equivalent; add fake-session atomicity/error tests before extraction. Do not combine with schema/logic fixes or real gateway integration. Full database transaction guarantees need separately authorized isolated DB tests. |
| R13 | Retire only explicitly listed temporary legacy-path shims whose incoming imports, script/CLI clients and dynamic references have migrated. | Re-scan in-repository imports; communicate external compatibility window and document exact removals. No permanent duplicate source implementations, eager package aggregators, sys.modules aliases or silent CLI breaks. Do not delete untracked unrelated files. |

R1 does not depend on finishing IAM-03C; its three pure modules form a contained
navigation improvement. Preserve the known IAM-03C failure separately. The full
refactor is not one blanket implementation authorization. Later high-risk DB/API
moves can remain gated while the earlier offline domains become easier to navigate.

## Backward compatibility and test organization

Use temporary explicit old-path re-exports only when they preserve the *same*
class/function object. Star imports omit private helper symbols and are unsuitable.
Do not load the same source under two module names. Shims must import only toward
the canonical implementation; canonical modules must not import their own shim.
Package initializers should not aggregate subpackages or register adapters.

For non-colliding paths, annotate the shim retirement stage in the implementation
review. Existing CLI wrappers need the same guarded `if __name__ == '__main__'`
behavior while their paths are supported; a plain re-export would silently stop
`python -m app.provision_*`. No CLI invocation belongs in offline verification.
For db.py collision, the safe empty package initializer takes precedence over an
eager compatibility facade; approval must explicitly cover the coordinated import
cutover and unverified external clients. evidence/audit public facades can expose
existing functions without duplicate implementations.

Keep test file locations unchanged during all application moves; update imports,
helper references and patch targets in the same stage. This avoids pytest module
name/path and fixture-discovery changes obscuring application regressions.
Proposed later organization, not created now: tests/unit/{iam,analysts,gateway,
detection,evidence,audit,integrations/wazuh} for reviewed pure/fake suites, and
explicitly gated tests/integration/ for PostgreSQL/API concurrency/migration tests.
Do not put engine/config fixtures in global conftest. If separately approved,
move shared test builders into a lightweight, import-safe support package and
update every `from test_* import ...` caller atomically, without duplicating fixtures.
Test_auth, test_health, Wazuh scheduler and several tests described as unit-like
currently import config/db transitively; names alone do not make collection safe.

## Verification plan and execution boundaries

Do not run bare pytest or `pytest --collect-only` over the entire tree: test imports
can instantiate settings/engine and use database-backed fixtures. The pyproject
uses `pythonpath = ["services/api"]` and `testpaths = ["tests"]`; retain that import
root throughout. Disable bytecode and pytest cache for reversible offline checks.
The current reviewed stable command is:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider -o addopts='' -q \
  tests/test_iam_authority_provider.py \
  tests/test_iam_admission.py \
  tests/test_iam_policy.py \
  tests/test_iam_contracts.py \
  tests/test_audit.py \
  tests/test_ollama_preparation.py \
  tests/test_ollama_inference.py \
  tests/test_analyst_inference.py \
  tests/test_analyst_protocol.py \
  tests/test_analyst_evaluation.py \
  tests/test_analyst_contracts.py \
  tests/test_security_events.py \
  tests/test_detection_rules.py \
  tests/test_detection_rule_groups.py \
  tests/test_event_correlation.py \
  tests/test_correlation_matches.py \
  tests/test_tool_gateway.py \
  tests/test_gateway_permission_design.py \
  tests/test_disclosure_policy.py \
  tests/test_gateway_disclosure_enforcement.py \
  tests/test_wazuh_gateway.py \
  tests/test_wazuh_manifest.py \
  tests/test_gateway_development_spec.py \
  tests/test_wazuh_cursor.py \
  tests/test_database_roles.py
```

This selection intentionally excludes unfinished tests/test_iam_postgres_authority.py.
Its separate safe fake-session diagnostic command is:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider -o addopts='' -q tests/test_iam_postgres_authority.py --tb=short
```

Do not suppress its failure, relabel the stable selection as the full regression
suite or change its test to fit a move. Review/reset class identities in an approved
IAM-03C continuation if that is the actual root cause; no fix is authorized here.

For R1, use the same pytest options with exactly test_security_events.py,
test_detection_rules.py, test_detection_rule_groups.py, test_event_correlation.py
and test_correlation_matches.py as the focused set, then the stable suite above.
Use the per-module D/I ledger to select later stage tests; classify their fixtures
before importing them. No operational database tests are authorized by this plan.

Additional checks for an approved implementation stage:

1. **Import smoke tests:** fresh subprocesses, PYTHONDONTWRITEBYTECODE, synthetic
   config/session stubs where needed, socket/subprocess/engine creation forbidden.
   Import each new pure module and both legacy/canonical class paths, assert object
   identity and no provider registration. Never run all modules with runpy: that
   would execute provisioning/scheduler main guards.
2. **Compilation:** in-memory `compile(path.read_bytes(), str(path), 'exec')` over
   services/api, tests and scripts. This avoids compileall bytecode writes. Syntax
   success does not verify import order, source authority or DB transaction parity.
3. **API registration without DB:** first capture the 16 source-declared routes
   and DTO/default/dependency metadata by AST. For a future dynamic check, install
   fake config and db.session modules in a fresh subprocess *before* importing
   main/routers, with an engine whose connect raises and session factory/get_db
   that raise if invoked. Import and inspect app.routes/OpenAPI only; do not request
   /ready or resolve real DB dependencies. Assert exact route methods, paths,
   statuses/tags, dependency callable identities and schema/operation IDs. Existing
   test_health.py is not safe as-is because app.main imports the configured engine.
4. **Cycle checks:** resolve Import, ImportFrom, from-package aliases and literal
   dynamic imports against the proposed file map. Maintain separate eager and
   all-call-site graphs. Compare SCCs and test fresh-process import orders around
   the known inference cycle. Do not "fix" cycles by arbitrary lazy loading that
   changes validation timing or bypasses the provider allowlist.
5. **Security regression:** preserve canonical evidence/audit bytes, IAM decision
   reasons and exact type checks, context construction, issuer/provider origins,
   snapshot/epoch freshness, prompt/schema/result validation, input/output ceilings,
   synthetic provenance and denial invocation counters. Extend no-I/O guards to
   the new package prefixes; do not let path changes make them vacuous.
6. **Diff/whitespace:** git diff --check plus explicit checks of moved/untracked
   Python/Markdown/JSON files; regular git diff omits this checkout's many untracked
   modules. Compare a content-hash manifest to prove unrelated work unchanged.
7. **Database parity (not authorized):** later separately approved isolated ai_soc_test
   checks for tenant constraints, Base.metadata registration, evidence/audit/checkpoint
   atomicity, audit sequence/locks, leases/concurrency/recovery and route isolation.
   No Alembic command is safe merely because it is called offline: env.py reads
   configured settings and migration code can execute SQL during generation/setup.

## Alembic, deployment and operations

migrations/env.py is the only migration-side app import consumer found; it imports
settings, Base and all eight mapped ORM classes and uses Base.metadata. Update only these import
paths during approved R8/R9; do not alter revision/down_revision, table names,
constraints, indexes, lock semantics or existing revision bodies. Nine revision
files were statically inspected; none imports application modules. Alembic's sys.path
addition and pyproject import root remain services/api.

The only active deployment Compose file found is deploy/compose/compose.yaml,
which defines PostgreSQL, not an API container. No services/api/Dockerfile or .github
workflow exists in this checkout. Do not invent CI/Docker import consumers or
propose changing live Compose configuration. The deploy/gateway-dev/*.review.json
files are inactive reviewed development specifications, not provisioned services.
README's ASGI command stays app.main:app; its broad pytest/setup instructions are
not permission to install dependencies, start services or run the whole suite here.

scripts/prepare_database_roles.py and scripts/run_wazuh_scheduler.py explicitly add
services/api to sys.path; retain wrapper paths and only change their module imports.
scripts/provision_wazuh_integration.py depends directly on runtime config/session/
models/client/audit and retains its current operational guards. Never run it for
refactor verification. Existing tenant/API-key provisioning CLIs can output secrets
and write state, so test import structure/main guards statically instead of invoking
those commands. No service activation, model call, Wazuh query, migration, credential
read, dependency install, commit or push is part of REF-01A.

## Completion and first approval recommendation

This document is the sole REF-01A repository addition. All proposed trees, packages,
shims and service extractions remain plans. Current source import evidence is static;
transitive impact is conservative and external consumers cannot be fully discovered
from this repository. Tests and file-preservation results for this planning turn
are recorded below after verification.

Recommend separate approval of **REF-01B / R1 detection package only**: move the
three normalization/rules/correlation modules, update their exact incoming imports
and test patch aliases, preserve temporary class-identical old-path exports if
needed, and run focused plus stable offline regressions. No API, database, IAM,
inference or gateway semantic change; no live systems. STOP after REF-01A.

## Verification performed for REF-01A

- Complete migration-map check: all 40 current backend modules mapped once; 40
  distinct primary destinations, with main.py handler extractions separately listed.
- Stable selected offline suite: **1,529 passed** (25 explicitly selected files).
  This is not the full repository suite.
- Separate unfinished IAM-03C diagnostic: **43 passed, 1 failed**; unchanged known
  reload/no-I/O failure at tests/test_iam_postgres_authority.py:185. No fix attempted.
- In-memory compilation: **97 Python files passed** across services/api, tests
  and scripts; no bytecode generated.
- Content-hash preservation: **all 140 pre-existing repository files unchanged**.
  Only this planning document was added.
- git diff --check and explicit new/untracked text-file whitespace checks passed.
- No database, Wazuh, Ollama, API startup, migration or provisioning execution.
  No dependencies installed; no runtime settings, instructions, handoff, source,
  tests or deployment files changed. Operational/database-backed parity remains
  unverified. No refactoring implementation began.
