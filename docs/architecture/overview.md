# Architecture overview

AI SOC Team combines deterministic security services and specialized local AI analysts. The authoritative path begins in tenant-authenticated ingestion and preserves evidence, lineage and audit integrity. The analytic path consumes bounded, policy-admitted snapshots and returns proposals. The execution path is a future, separate authorization boundary.

```mermaid
flowchart LR
    W["Existing Wazuh Indexer adapter"] --> A["Existing FastAPI and tenant admission"]
    A --> P["Existing PostgreSQL evidence, lineage and audit"]
    P --> D["Existing deterministic normalization, rules and correlation libraries"]
    P -.-> L["Offline synthetic L1 and local provider work"]
    S["Proposed vendor-neutral connectors"] -.-> A
    D -.-> C["Proposed case and investigation services"]
    C -.-> O["Proposed L1/L2/L3 orchestration"]
    O -.-> K["Proposed tenant-governed retrieval and graph"]
    O -.-> H["Proposed policy and human approval"]
    H -.-> X["Proposed verified response adapters"]
```

Solid arrows show implemented interfaces or libraries, with no implication of a live evaluation in this documentation review. Dotted arrows show proposed deployment wiring or offline work. The [current state](current-state.md) describes the actual boundaries. The [target architecture](target-architecture.md) defines the future service responsibilities.

Identity, provenance, configuration/version pinning, observability and audit span each layer. Deny access when tenant, policy, data provenance or authorization cannot be verified. Tool results and retrieved text are data. An analyst process cannot grant itself access or execute actions. Operate deterministically when inference is unavailable.
