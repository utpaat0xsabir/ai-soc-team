# SIEM connectors

Wazuh supports tenant-scoped bounded ingestion and incremental read-only collection in the current tree. Treat actual shared source-to-tenant mapping and operational role verification as open. Future candidates include Elastic Security, Splunk, Microsoft Sentinel, IBM QRadar, Google Security Operations, Graylog and OpenSearch-based SIEM deployments. Prioritize a second connector that exercises different pagination and authentication semantics. [Wazuh implementation](../../services/api/app/integrations/wazuh) · [Incremental specification](../architecture/wazuh-incremental-ingestion.md)

## Proposed normalized envelope

| Field group | Contract |
|---|---|
| Scope and identity | Trusted tenant ID and source integration ID from policy, source system and scoped native event ID. Declare whether native IDs are unique per tenant, integration, index or stream. |
| Time and classification | Original event timestamp and precision, collection timestamp, timezone normalization, event type, severity, detection/rule ID and available rule revision. Preserve native values alongside mappings. |
| Entities and attributes | Tenant-qualified host and user refs, source and destination endpoints, network indicators, bounded typed common attributes, namespaced vendor attributes. Explicit unknowns and validation errors. |
| Evidence and trust | Original raw evidence ID and digest, source identity and provenance, integrity metadata, normalization and schema versions, classification and trust decision reference. A vendor severity is an observation, not a trust grant. |

Map [OCSF](https://schema.ocsf.io/) categories or [ECS](https://www.elastic.co/docs/reference/ecs) fields at the adapter boundary. Keep a small internal envelope and version each mapping. Preserve unknown native fields as bounded extensions and keep raw evidence for reprocessing.

Authenticate with the least-privilege read identity and approved TLS trust, scoped per tenant/integration. Rotate credentials independently of cursor identity. Enforce stable ordering, time bounds and cursor ownership. On duplicate batches, use source identity and digest to distinguish retry from conflict. Persist progress with accepted data and audit. Treat incomplete shards or revoked access as failed coverage; retry recoverable throttles with bounded backoff and isolate outages. Apply per-integration rate/concurrency limits and tenant backpressure.

Acceptance includes fixture tests for pagination, replay, deduplication, malformed data, partial-outage recovery, credential rotation and schema-version changes. Verify one connector outage cannot move another cursor, expose another tenant or block unrelated ingestion.
