# AI SOC Team

AI SOC Team is a backend-first project for a self-hosted, multi-tenant security operations center. It helps security teams collect and verify evidence, apply deterministic detection and correlation, and prepare evidence-linked analyst assessments. Specialized analysts are the long-term interface to that workflow. The platform retains value when a model is unavailable because ingestion, integrity checks, audit and detection are independent of inference.

A SIEM chatbot can summarize a query result. AI SOC Team is designed to retain the source evidence, enforce a tenant and policy boundary on every request, and let a reviewer verify the basis for a claim or proposed action. Local inference is required. The initial engine design uses Ollama, and every model output remains a proposal. Deterministic code and authorized humans control sensitive actions.

## What is available

- A FastAPI and PostgreSQL foundation for tenant API keys, evidence ingestion and verification, lineage, and hash-chained audit records.
- An initial read-only Wazuh Indexer integration with manual ingestion, checkpoint-aware synchronization, and a separately configured scheduler.
- Deterministic event normalization, detection and correlation building blocks, plus an offline synthetic L1 workflow and bounded local-model adapter work.
- A B4 migration rehearsal candidate and containment tooling under development. Gate 1 read-only preflight and Gate 2 migration execution remain blocked.

This is a development-stage backend. Live L1 orchestration, L2/L3 run loops, a case workbench, RAG, and SOAR execution are proposed. Wazuh is the implemented integration family. Other SIEM, EDR/XDR, cloud, SOAR and intelligence products are candidates in the [integration designs](docs/integrations/overview.md). See [current state](docs/architecture/current-state.md) for the evidence behind each claim.

## Start here

Use Python 3.10 and an isolated virtual environment. The project’s dependency file is [requirements.txt](requirements.txt). The [contribution guide](CONTRIBUTING.md) describes safe offline checks and the separate approval needed for disposable PostgreSQL tests, service activation and migrations.

- [Documentation index](docs/README.md)
- [Architecture overview](docs/architecture/overview.md) and [target architecture](docs/architecture/target-architecture.md)
- [Project status](docs/project/current-status.md) and [roadmap](ROADMAP.md)
- [AI engineering opportunities](docs/ai/ai-engineering-vision.md) and [starter projects](docs/ai/ai-research-backlog.md)
- [Contributor guide](CONTRIBUTING.md) and [repository instructions](AGENTS.md)
