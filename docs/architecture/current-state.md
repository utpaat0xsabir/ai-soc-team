# Current state

Baseline 2026-11-22. The documentation review inspected the working tree and reachable Git history. Status terms and historical results are recorded in [project status](../project/current-status.md). Tests cited here are coverage evidence from source inspection.

| Subsystem | Status and scope |
|---|---|
| API, identity and storage | Implemented, live deployment unverified. FastAPI routes expose process health, database readiness, current tenant, evidence creation/read/verification/lineage, audit listing/verification and Wazuh ingestion/synchronization/status. Tenant API keys resolve the principal. Tenant qualification is applied in API queries and relevant relational constraints. |
| Evidence and audit | Implemented, restricted production privileges unverified. PostgreSQL models store tenant-owned evidence and lineage. Audit has per-tenant sequence and linkage, append-only triggers and hash verification. Application scoping is distinct from database RLS. |
| Wazuh | Implemented, operational rollout gated. The client and service support bounded collection and checkpoint-aware PIT synchronization. The optional scheduler is separate and default-off. Shared Wazuh tenant/source mapping and live least-privilege permissions remain open. |
| Detection and correlation | Implemented as deterministic libraries. Wazuh evidence normalization, rule matching and bounded event grouping are represented in code and tests. A deployed detection service, campaign workflow and persistent case management are proposed. |
| IAM and Tool Gateway | Partially implemented as reviewed contracts, deterministic policy and controlled gateway paths. Development mock tools and authority boundaries exist. Production trust composition, external enrichment rollouts and response execution remain gated. |
| AI analyst team | Partial. L1 synthetic orchestration enforces a fake provider, evidence snapshot, bounded inference contract and review binding. L2/L3 protocol and handoff concepts exist. Production L2/L3 runtimes, Ollama orchestration on incident data and tool-driven response are proposed. |
| Source registry and B4 | Blocked. A disabled schema migration, observer, launcher, authority, controller and fixture exist in the working tree. Independent approval and live enforcement are pending. |
| Knowledge and response | Planned. No deployed RAG, vector index, graph service, SOAR response adapter, or analyst workbench was established by inspected evidence. |
| Earlier prototype | Historical research. The separate project was outside review. Equivalent full campaign investigation and Qwen-assisted runtime were not established here. |

## Concrete entry points

`GET /health` checks process liveness. `GET /ready` attempts a PostgreSQL query. Evidence routes under `/v1/evidence` include integrity verification and lineage; audit routes are under `/v1/audit-logs`. Wazuh operations under `/v1/integrations/wazuh` have bounded manual ingestion, synchronization, and status endpoints. [Application entry point](../../services/api/app/main.py) · [API route modules](../../services/api/app/api/v1)

See the [evidence index](../project/documentation-evidence-index.md) for source, tests and migration evidence.
