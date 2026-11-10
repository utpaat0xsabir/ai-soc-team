# Repository instructions

## Scope and architecture

- Work exclusively in this `ai-soc-team` repository. Never access or modify the separate `ai-soc-agent` project.
- Preserve existing architecture and functionality: Python 3.10, FastAPI/SQLAlchemy API in `services/api`, Alembic revisions in `migrations`, pytest tests in `tests`, operational helpers in `scripts`, and documentation in `docs`.
- Reuse established naming and utilities. Avoid unnecessary dependencies, infrastructure, destructive refactors, and unrelated changes.
- At session start, read this file and `docs/development-handoff.md`. Historical findings are not proof of current state.

## Development workflow

- Inspect Git status and only relevant files; preserve existing changes. Establish the relevant test baseline.
- Present objective, expected files, database/security implications, tests, acceptance criteria, and recovery plan. Obtain approval before a new subphase; work autonomously within its approved scope.
- Use incremental TDD: positive, negative, invalid-input, tenant-boundary, and regression cases before implementation; demonstrate initial failures where practical.
- Make the smallest safe change. Use targeted tests during development. For implemented phases run phase tests, `python3 -m compileall -q services/api tests scripts`, `python3 -m pytest -v`, and `git diff --check`, subject to safety restrictions. Report exclusions explicitly; never hide failures.
- Review authorization, validation, secret handling, atomicity, integrity, retries, concurrency, and compatibility. Audit changes require integrity, concurrency, and rollback regression coverage where applicable.
- Report changed files, test counts, database changes, limitations, and next phase; stop for approval before continuing.

## Database and security invariants

- All database-dependent tests must use `ai_soc_test`; verify the target without exposing credentials. Routine tests must not depend on live Wazuh or production data.
- Before migration work, review schema, indexes, constraints, dependencies, ownership, audit/evidence effects, and recovery feasibility. Test migrations only on `ai_soc_test`.
- Enforce authenticated tenant ownership for integrations, evidence, lineage, checkpoints, leases, and audit records. A shared database role does not replace application authorization.
- Preserve evidence provenance, hashes, and lineage; distinguish AI interpretations from observed evidence.
- Preserve append-only audit records, per-tenant sequence numbers, SHA-256 hash chains, locking, and transaction atomicity. Keep evidence, audit, and checkpoint changes consistent; never advance progress for failed processing.
- Never expose environment values, credentials, API keys, or secrets in output, logs, responses, documents, or command arguments. Never weaken TLS, authentication, authorization, audit protections, or database permissions to pass tests.
- Wazuh access stays read-only with TLS verification, tenant-scoped ownership, deduplication, and safe recovery. Shared installations require trustworthy enforced source-to-tenant mapping before distributing alerts.

## Approval gates and continuity

- Obtain separate explicit approval for live `ai_soc` access that changes data/schema, production migrations, PostgreSQL role/login changes, credential changes, Wazuh permissions/configuration, destructive operations, background scheduling, deployment, commits, or pushes. Broad project approval does not authorize these actions; respect sandbox approvals.
- Do not run destructive database operations. Do not overwrite or delete existing work without explicit approval.
- Do not create or modify handoff documents or these instructions without explicit approval. Keep approved handoffs concise and secret-free: phase, Git state, changed files, pending migrations, dated verification, limitations, approvals, and one next task.
- Prefer targeted searches and bounded output; reuse unchanged verified findings. Avoid simultaneous heavy suites and persistent processes. Summarize successful checks and distinguish checks performed now from historical results.
