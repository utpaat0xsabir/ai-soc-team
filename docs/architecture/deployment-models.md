# Deployment models

Production readiness has not been established. The existing Compose definition describes a local PostgreSQL 16 service. The [rollout guide](../deploy/production-rollout.md) and [B4 runbook](../security/b4-gate1-provisioning-runbook.md) retain their own scope and approval requirements.

| Deployment | Boundary and acceptance |
|---|---|
| Offline development | Python 3.10, a reviewed dependency environment, synthetic fixtures and denied external I/O. Use fixture-backed API and model tests. The integration harness requires explicit authorization for disposable `ai_soc_test`. |
| Single organization, proposed | Pinned PostgreSQL 16, local inference, scoped secrets, minimal service identities, read-only connector egress, backups and recovery. Verify database roles and evidence/queue recovery before activation. |
| Shared multi-tenant, proposed | Add per-tenant limits, logical and physical isolation where appropriate, independently tested RLS and index/queue/cache boundaries, and dedicated credential custody. Require adversarial isolation and independent backup/restore tests. |
| MSSP, proposed | Prefer separate trust domains for high-sensitivity tenants. Add time-limited delegated access, separate key custody and explicit reporting permissions. Verify export and restore boundaries and administrator separation per tenant. |

Keep deployment local-first. Treat model availability as optional for evidence and deterministic detection. Separate integration network access through approved gateways. Pin model and dependency artifacts. Track sanitized health and slow/error counts with tenant-safe access. Test backups, restore, secret rotation, rollback and reindexing in a separately approved environment. Provisioning and tool activation are distinct from code review.
