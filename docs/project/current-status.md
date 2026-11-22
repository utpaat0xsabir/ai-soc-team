# Project status

**Documentation baseline 2026-11-22.** Reviewed reachable HEAD `c231f54` and the existing working tree. B4 source, tests and review artifacts are present as uncommitted work. Treat the working tree as engineering evidence with no release or execution authority.

| Status | Meaning |
|---|---|
| Implemented and verified | Evidence ties a specific run and its scope to the implementation. Live claims require live evidence and authorization. |
| Implemented, verification limited | Present in source with inspectable tests or historical evidence. Current deployment or complete behavior was not reverified. |
| Partial or prototype | Some functions or contracts exist. Runtime integration or independent release review remains incomplete. |
| Planned | Proposed work without equivalent implementation evidence. |
| Blocked or unknown | A missing dependency, authorization or evidence prevents a stronger claim. |

The [current-state map](../architecture/current-state.md) classifies subsystems. The [evidence index](documentation-evidence-index.md) records source-level coverage. This documentation review did not rerun backend or live tests.

## Latest reported bounded results

| Area | Historical evidence supplied for this baseline |
|---|---|
| B4 fixture | 47 focused offline tests passed. The implicit slice and empty invocation ID handling are present in the reviewed runner. |
| Guarded B4 regression | 952 passed, 1 failed, 28 deselected. The failure was the comparison against the preserved approved manifest. This result does not transfer approval to the working tree. |
| Host precheck | The supplied handoff reports reaching a missing custodian-window record after systemd checks. No independently verified privileged fixture execution or live preflight is established. |
| Earlier ingestion | The November 10 handoff reports 467 passed and 3 destructive audit tests deselected, with separate historical PostgreSQL revision and Wazuh observations. |

See [earlier handoff](../development-handoff.md), [fixture runner](../../review-output/b4-systemd249-fixture.py), and [B4 runbook](../security/b4-gate1-provisioning-runbook.md). Historical host status and operational versions are not current deployment verification.

## B4 gate status

- **Gate 1 blocked and unapproved for the current artifact.** The intended operation is a controlled, read-only PostgreSQL 16 preflight on an independently designated disposable `ai_soc_test`. Production admission, administrative freeze, complete authenticated session evidence and independent teardown still require implementation or verified enforcement. The current controller denies readiness.
- **Gate 2 blocked and unapproved.** Staged migration `e4b2b2000001` follows `d93c6e4fb132` in the working tree. The preserved manifest and the [77-file review candidate](../security/source-registry-execution-manifest.autonomous-b4.candidate.json) record the `0fc91f8d…` DDL pin. Historical `0eafe3f3` provenance remains unresolved. A live rehearsal needs separate approval and independent disposition.
- Verified file identities during this documentation pass. The [preserved approved manifest](../security/source-registry-execution-manifest.json) has SHA-256 `d829b2916ab5b1fd54fe9113fa7ef3784744aff68675cdd7b29b2338de008de5`. The 77-file candidate JSON has SHA-256 `fb7c30d28d4a8da4987a7dea4d9507062dfe10bab39d72fdb9d6f6de6fcef0a1`. These are file hashes. Reproduction and authorization remain separate checks.

[Gate requirements](../security/source-registry-migration-gates.md) · [Sign-off scope](../security/b4-gate1-signoff.md) · [Next milestones](next-milestones.md)
