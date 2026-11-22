# Integrations

[Wazuh](siem.md) is the existing connector family. The vendor-neutral [framework](../architecture/integration-framework.md) is a design target. Additional adapters are proposed and require separate security and operational qualification.

- [SIEM ingestion](siem.md) defines normalized alert and event contracts and connector behavior.
- [SOAR and response](soar.md) defines the proposal, approval, execution and independent verification lifecycle.
- [Threat intelligence](threat-intelligence.md) defines disclosure, provenance, caching and expiration.
- [EDR/XDR and cloud](edr-xdr-cloud.md) defines account binding, scoped read ingestion and future action separation.

A connector ships after its version/capability manifest, credential scope, fixture contract tests, partial failure cases and isolation results are reviewed. Establish authorized outbound reachability and input/output minimization separately. Use mock transports so reviewer tests do not depend on customer systems.
