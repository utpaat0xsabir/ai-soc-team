# B4 read-only preflight approval packet

## Purpose and authorization boundary

Obtain an independent decision on the inputs for one bounded PostgreSQL 16
predecessor preflight on `ai_soc_test`. The operator previously authorized
this read-only scope. Connection readiness depends on the decisions below.
This packet is unsigned and supplies no migration authority. Exclude `ai_soc`,
the guarded migration runner, Alembic execution, DDL, DML, SET ROLE,
privilege changes, credential changes, and Docker changes. Use only approved
catalog and observation reads and transaction-local setup, followed by rollback.

## Evidence and status

**Observed** means directly recorded. **Independently verified** means
reproduced or compared with a named artifact. Neither label grants approval.
**PROPOSED** means a concrete unapproved value exists. **APPROVED** requires
an explicit scoped operator or independent reviewer decision. **MISSING**
means required evidence or delivery is unavailable. **INCONSISTENT** means
available evidence disagrees or cannot satisfy the current contract.
**REJECTED** is a recorded negative reviewer decision. **NOT APPLICABLE**
means the input has no role in this preflight.

- Working tree inspected on `master` at `c231f54` with B4 uncommitted.
- Historical offline result was 686 passed, one expected manifest comparison
  failure, and 28 deselected. The suite was not rerun for this packet.
- Expected predecessor `d93c6e4fb132` and proposed revision `e4b2b2000001`.
  The live predecessor remains unverified.
- Candidate manifest SHA-256
  `ea26b6009f972e1b7329b65ba6abd6afc05e0b021d8400dc4256b59b32219a3a`.
  The prior review reproduced the candidate and checked its 45-file inventory.
  This packet rechecks both file hashes. [Candidate](source-registry-execution-manifest.candidate.json)
- Existing approved manifest SHA-256
  `d829b2916ab5b1fd54fe9113fa7ef3784744aff68675cdd7b29b2338de008de5`.
  It is preserved and its digest cannot satisfy capture against the current
  generated candidate. [Approved manifest](source-registry-execution-manifest.json)
- The previously verified 67 rendered DDL statements hash to
  `0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4`,
  matching the migration pin. Historical `0eafe3f3` remains unresolved and
  blocks migration execution approval until traced or explicitly dispositioned
  by an authorized independent reviewer. [Revision](../../migrations/versions/e4b2b2000001_stage_source_registry.py)

## Observed Docker identity and proposed pin

| Field | Prior observation and proposed pin |
|---|---|
| Daemon and state | Local Docker socket, running `ai-soc-postgres` |
| Full container ID | `26a6fd80267c7e3fdcbee4afaf950f63e3dec02ea5454ccf67f31723fed8b50e` |
| Image tag | `postgres:16` |
| Immutable image ID | `sha256:f9a7b9ebf6f56201f949db745e47bc423c0f0f8294bafe991cc10bf74b029657` |
| Publication | Only `127.0.0.1:5432` to `5432/tcp` |
| Network and address pair | Only `compose_default`, server `172.18.0.2`, client gateway `172.18.0.1` |
| Immutable network ID | Missing from prior observation. Obtain and independently pin the full ID. |

An independent reviewer must establish the expected tuple, and the caller
must compare fresh inspection before connection and after capture. The
adapter verifies the container ID, publication, and address pair through
the target helper. Compare the immutable image ID and network name separately.
The image tag alone cannot establish the actual server version.
[Target helper](../../services/api/app/database/test_target.py)

## Database, identities, and secret delivery

The database custodian must designate `ai_soc_test` disposable and attest
the CONNECT boundary for the approved logins using independent provisioning
evidence or a scoped catalog check from the authorized test session once
connection gates pass. Check effective CONNECT for `ai_soc` from test-side
catalogs without attempting an `ai_soc` login. Stop on scope ambiguity.

Use the existing restricted `ai_soc_test_migrator` LOGIN and the
`ai_soc_test_owner` NOLOGIN owner. Require the reviewed SET-only membership
edge with SET enabled and INHERIT and ADMIN disabled, no extra paths or
elevated flags, and the reviewed ownership and least-privilege grants.
Inspect the membership without switching roles. The owner has no login secret.
The observer must be a distinct independently named login with no membership
or owner path, no elevated flags, TEMP, CREATE, mutation or unexpected routine
privileges, and complete SELECT visibility for the approved scope.

The documented migrator input is `AI_SOC_MIGRATION_DATABASE_URL`. An approved
secret launcher supplies the existing URL to the separately reviewed
read-only caller process only. The URL must select `postgresql+psycopg`,
`ai_soc_test_migrator`, `127.0.0.1:5432`, and `ai_soc_test`, with a password
and no query options. Supply the observer secret independently to that caller.
The B4 adapter has no observer environment variable or credential loader.
The guarded migration runner documents the migrator input and is outside this
approval. Keep secrets out of arguments, chat, shell history, files, logs and
the packet. Record only the custodian, delivery reference and availability.
[Credential contract](../../scripts/run_guarded_migration.py) ·
[Role checks](../../services/api/app/database/migration_guard.py)

## Manifest, application isolation, and query inventory

Independently reproduce and sign the candidate digest for this preflight
against the frozen tree and reviewed dependencies. Supply the approved
`application_isolation_sha256` for evidence that the same build preserves
application isolation and keeps the staged authority and trust projection
disabled. The reviewer must verify the artifact and its build binding
outside the adapter. The adapter checks digest syntax and binds the value
to capture evidence. It does not authenticate the supporting artifact.

The observer inventory approval is pending. The verified code pin for
47 queries is
`03a782227e4bf8cebb5052008f5ec037d51379ec22c622e767f1c8110922193a`.
Authorize only the 21 predecessor-eligible names and reviewed transaction
setup. Any separate migrator or connection-identity catalog reads require
their own reviewed allowlist.

- Session and access checks — `identity`, `snapshot`, `privileges`,
  `roles`, `revision_relation`, `revision`, `history_relations`,
  `history_visibility`.
- History — `tenants`, `evidence`, `lineage`, `audit`.
- Catalog — `namespace`, `shadow_routines`, `public_owners`, `keys`, `lineage_keys`,
  `audit_routine`, `audit_triggers`, `audit_mutators`, `reserved_history`.

The fixed inventory binds SQL, parameters, phase, width, cardinality and
visibility scope. The snapshot query is repeated to confirm continuity.
Report digests and counts with sanitized rejection codes.
[Observer inventory and capture](../../services/api/app/database/source_registry_observer_adapter.py)

## Proposed resource budgets

All limits below are **PROPOSED** and require independent approval.

| Limit | Proposal and rationale | Enforcement |
|---|---|---|
| Statement timeout | 5 seconds. Bounds each catalog or history scan on the disposable target. | Caller sets it transaction-locally. Adapter verifies a positive effective timeout no greater than the approved value at both snapshot checks. |
| Lock timeout | 1 second. Fail quickly when another session holds conflicting locks. | Caller sets and verifies it. Adapter has no explicit check. |
| Rows per query | 1,000. Bounds a small fixture capture while retaining completeness. | Adapter rejects overflow using the lower of this cap and each inventory query maximum, reading up to one extra row. This bounds accepted result rows. Driver buffering, row byte size, and server work need separate caller consideration. |
| Overall deadline | 60 seconds across identity inspection, both sessions and cleanup. | Caller watchdog and bounded cleanup required. Adapter has no overall timer. |
| Connection timeout | 5 seconds per connection. Bounds endpoint or handshake stalls. | Caller configures the driver deadline. Adapter receives an open connection. |
| Recovery deadline | 5 seconds after worker exit or termination. Bounds teardown and final target verification. | Launcher enforces admission and result deadlines. The protected monitor and target provider must apply their own bounded I/O. |
| Sessions | At most two sequential sessions, one migrator and one observer, with one open at a time. | Caller must enforce it. Adapter has no session counter or pool control. |

Do not sample or silently raise limits when the result is incomplete.
Review the evidence and obtain approval for a revised budget before retrying.

## Operator decision matrix

| ID and approval input | Status | Evidence | Required reviewer | Acceptance and remaining action |
|---|---|---|---|---|
| A01 Read-only scope for `ai_soc_test` | APPROVED | Explicit operator instruction in this workflow | Operator | Preserve the read-only scope and prohibitions. |
| A02 Container and immutable image pin | PROPOSED | Observed Docker tuple above | Independent target reviewer | Approve exact identity after independent inspection. |
| A03 Endpoint and address-pair pin | PROPOSED | Observed Docker tuple above | Independent target reviewer | Approve exact loopback publication, network and pair. |
| A04 Disposable target and CONNECT boundary | MISSING | B4-01 pending | Database custodian and security reviewer | Provide designation and effective CONNECT evidence. |
| A05 Migrator LOGIN and owner NOLOGIN configuration | MISSING | Role names and attributes in guard | Database custodian and security reviewer | Supply provisioning evidence and confirm by authorized catalog reads. |
| A06 Migrator secret delivery | MISSING | Documented process input, unavailable at prior inspection | Credential custodian | Securely inject existing scoped credential and attest availability. |
| A07 Observer login approval | MISSING | Adapter target contract | Database custodian and independent reviewer | Name a distinct restricted login and approve its read scope. |
| A08 Observer secret delivery | MISSING | No B4 credential loader or delivery record | Credential custodian | Inject existing observer credential into the approved caller only. |
| A09 Candidate manifest pin | PROPOSED | Verified candidate SHA-256 above | Independent artifact reviewer | Reproduce and pin candidate for this preflight. |
| A10 Use of existing approved manifest pin for current capture | INCONSISTENT | Approved bytes differ from candidate | Independent artifact reviewer | Retain approved record and use a separately approved candidate pin. |
| A11 Application-isolation evidence and pin | MISSING | Adapter approval field, approved artifact unavailable | Application security reviewer | Supply and verify same-build artifact and digest. |
| A12 Query scope and inventory | PROPOSED | Pinned predecessor inventory and caller allowlist requirement | PostgreSQL security reviewer | Approve digest and exact supplement, including transaction setup. |
| A13 Resource budgets | PROPOSED | Budget table above | Operator and PostgreSQL security reviewer | Approve values and verify enforcement in the caller. |
| A14 Approval of dedicated read-only caller and launcher | MISSING | Proposed implementation in the remediation plan | PostgreSQL security reviewer | Independently review the caller and its trusted launcher, including hard deadline and cleanup. |
| A15 Successor reference and emptiness approvals | NOT APPLICABLE | Successor capture contract | Independent execution reviewer | Defer to separately authorized successor work. |
| A16 Historical `0eafe3f3` disposition | NOT APPLICABLE | Unresolved historical digest prefix | Independent migration reviewer | Resolve separately before migration execution approval. |

## Risk register

| Risk | Severity | Stop or control |
|---|---|---|
| Wrong container, endpoint, database, or login | High | Require independent pin and verify live identity before application reads. Recheck pin afterward. |
| Secret disclosure or privileged fallback | High | Use restricted process-local credentials and sanitized diagnostics. Abort on missing delivery or wrong login. |
| False absence from filtered or incomplete history | High | Require complete observer visibility, stable snapshot and bounded full results. Reject drift, RLS or overflow. |
| Artifact drift or unsupported isolation claim | High | Freeze inputs, verify both approved pins, and stop on mismatch or missing evidence. |
| Long scans, lock waits or lingering sessions | Medium | Enforce approved limits, roll back and close on every exit, and treat incomplete capture as a failure. |
| Historical DDL digest provenance | High for migration execution | Track separately and block execution approval until independently resolved or dispositioned. |

## Approval checklist and sign-off

- [ ] Independently confirm A02–A04 and the approved scope in A01.
- [ ] Confirm A05 and A07 provisioning evidence and A06 and A08 secure delivery.
- [ ] Approve A09 and A11 and document the A10 disposition.
- [ ] Approve A12–A14, including caller enforcement gaps and cleanup.
- [ ] Record the decision in the trusted approval channel without secrets.

| Record | Decision entry |
|---|---|
| Operator, database custodian and credential custodian | Pending |
| Independent target, artifact, application and PostgreSQL security reviewers | Pending |
| Request ID, approval date, validity window and evidence references | Pending |
| Approved digests, exact limits and caller identity | Pending |
| Final decision and reviewer signature or trusted approval reference | Pending |

**GO** only when A01–A09 and A11–A14 are explicitly authorized for this
preflight, A10 is resolved for this capture by the approved candidate pin,
and the caller can enforce the scope, prerequisites and limits. **NO-GO**
for any missing, inconsistent, rejected, expired or unverified required
input, any target drift, or any inability to enforce the read-only caller
contract. Sign-off authorizes the scoped preflight only. The current status
is NO-GO for connection and ready for independent approval review.
[Remediation plan](b4-preflight-remediation-plan.md)
