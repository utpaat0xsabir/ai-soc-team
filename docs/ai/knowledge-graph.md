# Knowledge graph and Graph RAG

Proposed. Model hosts, users, addresses, processes, files, domains, alerts, incidents, indicators, ATT&CK techniques and campaigns as tenant-qualified entities. Treat relationships as qualified assertions. A process-to-host edge can be a direct observation, while an inferred campaign link remains a hypothesis.

Every node and edge carries tenant, source evidence ID, transformation version, observed and effective times, confidence and status. Record conflicting facts independently. Bound entity resolution by stable identifiers and ownership over time. Keep aliases distinct when identifiers are ambiguous. Restrict path traversal at every hop and preserve edge provenance in exports and retrieval. Enforce retrospective revocation and deletion across derived projections.

Start with a relational adjacency projection and deterministic timeline reducer using an existing correlation group fixture. Evaluate graph engines only after identifying a traversing query and proving that added storage has an independent tenancy, backup and restore model. Tenant-private edges never cross into shared reference knowledge as facts.

Graph RAG combines authorized paths and bounded text retrieval. Compare it with lexical/hybrid retrieval and deterministic joins on the same frozen cases. Measure correct entity resolution, supported edges, useful path recall, unsupported links, timeline consistency, query cost and confidentiality. Keep Graph RAG only where it improves a held-out investigation metric without citation or isolation regressions. [Research milestones](ai-research-backlog.md)
