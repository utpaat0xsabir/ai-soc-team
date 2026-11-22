# Threat Intelligence Gateway

Proposed. Sources to evaluate include MISP, OpenCTI, VirusTotal, AbuseIPDB, AlienVault OTX, urlscan.io, STIX/TAXII servers and internal feeds. Current Tool Gateway and disclosure contracts are a foundation. No live provider is implied. [Gateway model](../security/gateway-threat-model.md)

Normalize IOC type and value with stable representation, preserving the provider observation and exact source. Track reliability, caller scope, classification, confidence, license, collection time, first/last seen, validity expiry and contradictory scores. Keep cached answers scoped by tenant and disclosure policy. A reputation observation can go stale or relate to shared infrastructure. It cannot independently justify blocking an entity.

Check outbound target and payload against policy before network access. Send only approved indicators. Private domains, internal asset names, artifact bytes and incident context require explicit authorization. Apply provider quotas, rate limits, retries and audited denial outcomes. Parse feeds as untrusted data and quarantine malformed records. Record correction and retraction history. Offline mode uses approved local snapshots with freshness flags and abstains when required facts are unavailable.

First milestone uses two synthetic conflicting feed responses and one offline snapshot. Tests cover policy-denied disclosure, tenant cache isolation, expiry, quotas and source citations. A verifier can reconstruct the lookup result from input scope, source versions and observation digests.
