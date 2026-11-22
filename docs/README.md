# AI SOC Team documentation

Baseline 2026-11-22. Start with the [project status](project/current-status.md), [architecture overview](architecture/overview.md), or [contributor guide](../CONTRIBUTING.md).

| Area | Guides |
|---|---|
| Architecture | [Current state](architecture/current-state.md), [target](architecture/target-architecture.md), [data flow](architecture/data-flow.md), [analyst orchestration](architecture/agent-orchestration.md), [evidence and audit](architecture/evidence-and-audit.md), [multi-tenancy](architecture/multi-tenancy.md), [connector framework](architecture/integration-framework.md), [deployment models](architecture/deployment-models.md) |
| AI engineering | [Vision](ai/ai-engineering-vision.md), [RAG](ai/rag-architecture.md), [knowledge graph](ai/knowledge-graph.md), [agent design](ai/agent-design.md), [evaluation](ai/model-evaluation.md), [research backlog](ai/ai-research-backlog.md) |
| Integrations | [Overview](integrations/overview.md), [SIEM](integrations/siem.md), [SOAR](integrations/soar.md), [threat intelligence](integrations/threat-intelligence.md), [EDR/XDR and cloud](integrations/edr-xdr-cloud.md) |
| Delivery | [Roadmap](../ROADMAP.md), [completed work](project/completed-work.md), [known gaps](project/known-gaps.md), [next milestones](project/next-milestones.md), [decision log](project/decision-log.md), [evidence index](project/documentation-evidence-index.md) |
| Existing specifications | [Wazuh incremental ingestion](architecture/wazuh-incremental-ingestion.md), [audit integrity](security/audit-log-integrity.md), [gateway threat model](security/gateway-threat-model.md), [IAM authority threat model](security/iam03c-authority-threat-model.md), [database roles](security/database-roles.md), [B4 migration gates](security/source-registry-migration-gates.md), [B4 runbook](security/b4-gate1-provisioning-runbook.md), [production rollout](deploy/production-rollout.md) |

## Maintenance

Current-state claims belong in the current-state and status pages, with traceability in the evidence index. Keep requirements and proposed mechanisms in the target and subsystem designs. Treat security gate records as the authoritative approval sources. Preserve dated handoffs and reviewer evidence.

Domain contributors update their guide with the change. The maintainer checks status, provenance and navigation during review. For each verification claim, record the date, artifact or revision, environment scope, result and exclusions. Use a proposal label until the implementation and required tests exist.
