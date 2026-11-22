# Target architecture

This reference design is proposed. The [current state](current-state.md) defines deployed and offline boundaries.

```mermaid
flowchart TD
    Data["SIEM, EDR, XDR, cloud, identity and network sources"] --> Adapters["Proposed connector adapters"]
    Adapters --> Ingress["Proposed ingestion gateway"]
    Ingress --> Normalize["Versioned normalization and validation"]
    Normalize --> Registry["Tenant-owned evidence and source registry"]
    Registry --> Detection["Correlation and detection engine"]
    Detection --> Cases["Incident and case management"]
    Cases --> Orchestrator["AI analyst orchestrator"]
    Orchestrator --> L1["L1 triage"]
    Orchestrator --> L2["L2 investigation"]
    Orchestrator --> L3["L3 hunting and response planning"]
    Orchestrator --> Retrieval["Tenant-safe RAG and optional evidence graph"]
    Orchestrator --> Intel["Governed threat intelligence"]
    L3 --> Policy["Deterministic policy and independent human approval"]
    Policy --> SOAR["Scoped response adapter"]
    SOAR --> Verify["Independent outcome verification"]
    Verify --> Registry
```

| Plane | Responsibility |
|---|---|
| Collection | Authenticate connector identity and tenant scope before acquisition. Persist raw evidence and provenance, then normalize and advance durable cursors under a consistent acceptance rule. |
| Investigation | Build case timelines from qualified evidence, maintain alternatives and handoffs, and support deterministic correlation when AI is unavailable. |
| Knowledge | Version source rights, metadata, tenant access and freshness; expose bounded retrieval and independently verifiable citations. |
| Execution | Validate typed proposals with policy and approval. Dispatch only through least-privilege adapters and reconcile outcomes. |
| Platform | Authentication and authorization, tenant boundaries, audit and custody, model/version management, observability, backups, evaluation and configuration review. |

Keep the backend contracts stable before building a workbench. A single organization can operate a smaller deployment. Shared service and MSSP deployments require independently verified isolation across databases, queues, indexes, credentials and operator workflows. [Deployment models](deployment-models.md)
