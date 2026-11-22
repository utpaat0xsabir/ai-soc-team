# Offline AI evaluation and threat coverage

The repository has offline [analyst evaluation contracts](../security/analyst-ai02-evaluation.md) and [tests](../../tests/analysts/test_analyst_evaluation.py). The benchmark and release criteria below are proposed. Code or fixture coverage in the evidence index does not establish live operational behavior.

## Reproducible evaluation

Pin synthetic or rights-reviewed datasets by version, fixture digest, tenant, labeler and adjudication history. Split by incident/campaign, source and time to prevent leakage. Keep a held-out evaluation set, a benign near-match set and a redacted adversarial set. Retain exact model and prompt digests, decoding, local engine, retrieval settings, hardware and failure reasons. Verify labels from evidence and reviewer decisions; a model conclusion is not training truth.

| Evaluation | Measure and release rule |
|---|---|
| Triage | Per-class precision/recall, false-positive rate, severity confusion and escalation quality. Report coverage-versus-risk and abstention calibration separately. Compare to deterministic baselines. |
| L2/L3 | Evidence-supported finding precision, correct timeline ordering and scope, unsupported claims, alternative-hypothesis coverage and ATT&CK mapping precision. Review disagreements. |
| Retrieval and attribution | Recall@k, nDCG@k, source freshness, exact locator/digest resolution, citation precision and unsupported-output rate. Any wrong-tenant retrieval or authorization bypass fails the run. |
| Governance | Verify role, tenant, workflow, tools and approval rules. Measure denial and action replay behavior. Require every tested forbidden action to be denied and audited. |
| Dependability | Record latency and resource usage, structured-output failures, timeouts and recovery, unavailable-model behavior, and repeatability. Require a working deterministic path under model exhaustion. |

## Security test strategy

| Threat | Current evidence and proposed extension |
|---|---|
| Prompt injection, hallucinations and retrieval poisoning | Current bounded task/output evidence tests. Add poisoned-document, arbitrary instruction, missing-citation and contradictory-evidence fixtures. Test calibrated abstention and exact citations. |
| Cross-tenant leakage | Current API and offline boundary tests. Extend to caches, queue claims, retrieval, graph traversals, dumps and restores. Test same-looking IDs in two tenants and revoked access. |
| Tool abuse, malicious intelligence and unsafe automation | Current gateway policy/disclosure tests. Add fake malicious provider, stale IOC, unauthorized request, expired/replayed approval and independent verifier failure. Test no network or action after denial. |
| Connector compromise and credential disclosure | Current Wazuh client and integration tests. Expand injection, schema drift, partial pages, identity rotation and failure-isolation tests. Require sanitized evidence and no uncontrolled retry. |
| Evidence tampering and audit manipulation | Existing integrity, lineage and audit tests. Add staged commit/rollback faults, chain truncation detection with external anchors, and isolated restore drills. |
| Resource exhaustion and supply-chain compromise | Current inference bounds and scoped manifests. Future tests pin model, tokenizer and dependency hashes, limit memory and concurrency, reject unsigned artifacts and test offline model exhaustion. |

Use [evidence index](../project/documentation-evidence-index.md) for current coverage and [known gaps](../project/known-gaps.md) for live evidence. Production thresholds for quality metrics require owner agreement against a representative reviewed dataset. Scope or integrity violations remain hard failures.
