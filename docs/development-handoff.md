# Development handoff

Prepared 2026-11-10. Read alongside `AGENTS.md`. This is a documentation checkpoint, not production rollout authorization.

## Current phase and authorization

Phase 1.4, reliable incremental Wazuh ingestion: implementation through subphase 1.4.7 and PostgreSQL rollout preparation were previously reported tested. Current work is approved continuity documentation following read-only rollout review. Stop after documenting and verifying; further implementation requires approval.

Current authorized changes: only `AGENTS.md` and this file. No application, test, migration, database, role, credential, Wazuh, scheduling, deployment, commit, or push changes are authorized by this task.

## Checks performed for this documentation task

- Inspected Git status: nine tracked files modified, with numerous untracked implementation, migration, test, script, and documentation files. Existing changes were preserved; this is not a clean release artifact.
- Confirmed both documentation targets were absent before creation. Only these two documents were added by this task.
- Verification uses content review, `git diff --check`, and explicit whitespace checks of both new untracked files. See the accompanying completion report for results.
- No tests, database connections, migrations, or live configuration checks were performed for this documentation task.

## Historical verification, not revalidated here

- Features previously inspected/tested: cursor validation and deterministic PIT pagination; tenant-owned checkpoints; atomic ingestion/deduplication; fenced leases, recovery and rollover; safe status API; optional disabled-by-default scheduler; offline restricted-role SQL generator and rollout documentation.
- Last recorded full regression result: **467 passed, 3 deselected**. The three audit mutation cases (UPDATE/DELETE/TRUNCATE) were excluded under the destructive-operation restriction. Compile and whitespace checks previously passed. Test execution time is not recorded in this handoff; these are prior-session results, not a fresh baseline.
- Last observed live `ai_soc` revision: `013505dd4ffd`; `ai_soc_test`: `d93c6e4fb132`. The three pending live revisions are:
  - `b71a4c2d9e10`: tenant-owned checkpoints and integration ownership uniqueness; validation and schema-lock risk.
  - `c82b5d3ea021`: fenced leases and nullable source identity; existing progress requires verified adoption.
  - `d93c6e4fb132`: safe attempt metadata and constraints.
- These migrations were previously applied only to `ai_soc_test`. They are additive, acquire schema locks, and deliberately refuse automatic downgrade; retain state during application rollback and require an approved recovery plan.
- Last readiness inspection found the configured database identity was a superuser/core-table owner; Wazuh UUID metadata returned 403, sort mappings 200; scheduling was disabled with no jobs or source scopes. These observations can become stale.

## Limitations and review finding

- Migration capability test checks membership flags but switches directly from administrator to owner. It does not exercise the intended deployment membership chain. Real non-superuser login verification also remains pending.
- Runtime isolation relies on authenticated application tenant filters, not database row-level security. The restricted profile deliberately allows updates to two metadata timestamp columns for locking; owner/migration identities can alter audit protections. External audit anchoring remains future work.
- Finite overlap cannot capture arbitrarily late alerts. Retention gaps and removed indices require operational reconciliation. Serial scheduling can delay jobs; cooperative shutdown waits for in-flight I/O.
- Production migrations, least-privilege login cutover, trustworthy source mapping, and Wazuh metadata access remain prerequisites for activation. Review `docs/security/database-roles.md` and `docs/deploy/production-rollout.md` before proposing rollout actions.

## Next action and outstanding gates

Next recommended task: propose a focused test plan to exercise deployment-to-migrator-to-owner access on `ai_soc_test`, without production login changes; obtain approval before implementation.

Separate explicit approvals remain required for live migrations, PostgreSQL roles/logins, credential cutover, Wazuh permissions/configuration, live ingestion, production scheduling, deployment, commits, and pushes. No such approval is implied by this handoff.
