# Architecture decision references

This index links existing records. It does not substitute for signed approvals or change their scope.

| Decision area | Authoritative reference |
|---|---|
| Backend-first development and scoped repository work | [Repository instructions](../../AGENTS.md), [modular refactor](../architecture/backend-modular-refactoring-ref01.md), [development handoff](../development-handoff.md) |
| Wazuh bounded read and incremental reliability | [Incremental ingestion](../architecture/wazuh-incremental-ingestion.md), [rollout](../deploy/production-rollout.md) |
| Secure evidence and append-only audit | [Audit integrity](../security/audit-log-integrity.md), [database roles](../security/database-roles.md) |
| IAM scope, trust and independent decision boundaries | [Policy](../security/iam02-policy.md), [admission](../security/iam03a-admission.md), [authority threat model](../security/iam03c-authority-threat-model.md), [owner approval register](../security/iam03c-owner-approval-register.md) |
| Local-only inference and immutable evidence context | [Analyst contracts](../security/analyst-ai01-contracts.md), [handoffs](../security/analyst-ai03-protocol.md), [inference](../security/analyst-ai04a-inference.md), [Ollama preparation](../security/analyst-ai04b2a1-preparation.md) |
| Scoped tools and disclosure | [Gateway threat model](../security/gateway-threat-model.md), [permission inventory](../security/gateway-permission-matrix.v1.json), [verification](../security/gateway-tg02-verification.md) |
| B4 gates and approved artifacts | [Migration gates](../security/source-registry-migration-gates.md), [sign-off](../security/b4-gate1-signoff.md), [runbook](../security/b4-gate1-provisioning-runbook.md) |

New proposals belong in the [target architecture](../architecture/target-architecture.md) and relevant subsystem guide. A new decision record should include owner, date, scope, alternatives, evidence, recovery and prerequisites. Link it here and update the current state only after verifying the implementation supports the claim.
