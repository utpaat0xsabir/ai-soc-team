# EDR, XDR and cloud integrations

Proposed. Prioritize a read-only alert or finding connector with stable resource IDs and reliable scope attribution. Example families include endpoint EDR/XDR alerts, cloud posture and workload findings, identity sign-in feeds and asset inventory. [Connector contract](../architecture/integration-framework.md) · [Normalized events](siem.md)

Bind each integration to an authorized tenant and provider organization, account, subscription or project before collection. Validate account hints against trusted inventory and distinguish stable provider IDs from reusable labels. Retain region and organization provenance. Correlate identities over time and flag ambiguous ownership. Store opaque pagination state per tenant and source. Test eventual consistency, out-of-order events, partial regions, webhook signature verification where applicable, schema evolution and independent quota failure.

Use a collection identity for minimum required reads. Keep response actions such as endpoint isolation, account suspension and cloud policy changes behind the [separate SOAR contract](soar.md). Treat provider success messages as receipts and verify the resulting state independently. Start with two synthetic accounts, one read-only adapter and denied cross-account cases before evaluating a live integration.
