# B4 preflight missing-input remediation plan

This plan accompanies the unsigned [approval packet](b4-readonly-preflight-approval-packet.md).
The operator already authorized bounded read-only preflight exclusively on
`ai_soc_test`. The remaining steps collect and verify the inputs needed to
use that authority. This document authorizes no connections, provisioning,
migration execution, or changes to either manifest.

## Remediation register

“Database access” distinguishes offline evidence recovery from a later check
inside the authorized test session. Delivery means the existing trusted
approval channel or process-local secret delivery where specified. Escalate
missing live configuration for a separate provisioning decision and stop the
affected check.

| Input and purpose | Repository contract and current evidence | Operator action, independent verification, and secure delivery | Acceptance and failure conditions | Required authority and access |
|---|---|---|---|---|
| A02–A03 Docker pin and endpoint prevent target substitution | Target helper requires full ID, a single network in local mode, and exact loopback publication. The prior tuple is observed and unapproved. | Compare fresh projected Docker metadata with independent inventory or custodian records. Have the target reviewer bind full ID, immutable image ID, network, publication and address pair in the approval channel. Recheck before connection and after observations. | Exact match and approved tuple. Stop for missing independent evidence, drift, ambiguous topology or inaccessible daemon. | Target reviewer approval and read-only local Docker access. Docker socket access is privileged. No database access. |
| A04 Disposable designation and CONNECT boundary protect development | B4-01 is pending. The workflow authorizes only `ai_soc_test`. | Custodian supplies the disposable target and ownership record plus effective CONNECT evidence for the two restricted logins, including grants via PUBLIC and memberships. Reviewer checks the record and, after connection prerequisites pass, corroborates it through catalog reads from `ai_soc_test`. Deliver a secret-free attestation. | Target designation and expected test CONNECT are supported, and the protected database is outside the permitted CONNECT boundary. Stop on ambiguity or unexpected grant. | Custodian and security reviewer. Records can be checked offline. Live corroboration uses the restricted test session. No admin login or connection to `ai_soc`. |
| A05–A06 Existing migrator and secret availability establish authenticated identity | Guard names `ai_soc_test_migrator` and checks an explicit URL for the loopback test target. No approved delivery was recovered. | Custodian identifies the existing LOGIN and its provisioning record. Supply the existing scoped URL through the approved secret launcher. Reviewer checks the sanitized target fields and later verifies both session and current user and effective permissions. | Existing restricted login and exact URL contract. Stop on missing credential, target mismatch, unexpected authority or auth failure. No retry with a different privilege level. | Credential custodian and PostgreSQL reviewer. Secret delivery needs authorized secret access. Authentication verification needs the restricted test session. |
| A05 Existing owner configuration protects the ownership boundary | Guard names `ai_soc_test_owner` and expects NOLOGIN with the exact SET-only edge from the migrator. Actual owner configuration is unverified. | Custodian supplies a role and object ownership record. Reviewer corroborates role flags, graph, owners and default ACLs from the approved catalog scope. Deliver only role and object metadata. | Reviewed owner and sole approved edge with SET only. Stop on missing owner, unexpected role reachability, ownership or ACL drift. | Custodian and reviewer. Offline record review, followed by restricted test catalog reads. No owner credential, SET ROLE or provisioning. |
| A07–A08 Independent observer and secret enable independent visibility checks | Adapter requires exact login in `Target` and a separately authenticated connection. Its contract rejects owner and membership paths and incomplete visibility. No approved B4 identity or secret was recovered. | Custodian names the existing observer and supplies approved column visibility and privilege evidence. Reviewer checks separation and later verifies actual login, ownership, memberships, grants and no active row filtering. Deliver credential directly to the authorized caller and approval metadata separately. | Distinct approved restricted LOGIN with full required visibility and no excess privileges. Stop on missing identity or secret, filtered results or excess privilege. | Custodian and independent reviewer. Secret access required for delivery. Live validation requires a restricted test session. |
| A09–A10 Candidate manifest pin binds capture to the reviewed artifacts | Adapter compares approval digest to generated bytes. Candidate matches current generation from prior verification. The approved manifest pin differs. | Reproduce the candidate in the frozen environment and sign its exact digest in the approval channel. Reviewer checks the 45-file inventory, runtime, graph, rendered DDL pin and expected file hash differences. Preserve both files. | Exact byte reproduction and independently approved candidate pin. Stop on drift or an attempt to use the old digest for current capture. | Independent artifact reviewer. Offline and unprivileged. |
| A11 Application-isolation evidence binds the external isolation claim | Adapter requires a lowercase 64-hex digest and binds it to the capture. No approved evidence artifact or pin was recovered. | Application security reviewer obtains the same-build evidence and verifies disabled authority/trust projection and isolation. Hash the exact bytes and supply the approved digest and artifact reference via trusted channel. | Verifiable artifact, scope and exact build binding. Stop on missing or stale evidence, mismatched digest or unsupported assertion. | Independent application security reviewer. Offline. Restricted evidence access only if the artifact custodian requires it. |
| A12 Query inventory and caller supplement bound permitted reads | Adapter pins 47 queries, with 21 predecessor-eligible names. Independent approval and an approved caller supplement were unavailable. | Recompute the inventory digest and review exact SQL, binds, phase, widths and allowed results. Approve predecessor scope and the exact supplemental identity, connection setup, CONNECT, privilege and migrator checks needed by the caller. Record approval in the trusted channel. | Verified digest, explicit predecessor scope, and a reviewed non-mutating supplemental allowlist. Stop on new SQL, unknown routine behavior, or an unreviewed fallback. | PostgreSQL reviewer. Offline and unprivileged for review. |
| A13 Query and transaction budgets prevent runaway capture | Adapter verifies statement timeout and caps accepted rows. The other safeguards require the caller. Approved values were unavailable. | Compare the packet proposals with independently available fixture sizing and the operational window. Approve limits and confirm enforcement against the reviewed caller before supplying credentials. Record bounds in the approval channel. | Approved finite values and enforceable ceilings. Stop on oversize results, timeout, missing enforcement or incomplete data. | Operator and PostgreSQL reviewer. Offline review. Live enforcement is verified only during the authorized preflight. |
| A14 Dedicated caller enforces the connection boundary | Adapter is injected and the repository search found no dedicated read-only entry point. The migration runner is excluded. | Identify an existing approved caller, or separately authorize review and implementation of one. Reviewer verifies the contract below and records its identity and approved version. | Reviewed caller enforces all prerequisites and ends with rollback and cleanup. Stop if any limit or identity assertion is unavailable. | PostgreSQL reviewer and separate implementation approval if needed. Offline for design and review. |
| A16 Historical DDL discrepancy protects migration execution approval | The current migration embeds the verified `0fc91f8d…` digest. No available source was attributed to `0eafe3f3`. | Recover the historical full digest with its source snapshot, toolchain or rendered SQL. Independently reproduce both digests and document the delta, or record an explicit authorized risk disposition through the approval channel. | Provenance reconciled or signed disposition with rationale. Until then, migration execution approval remains blocked. | Independent migration reviewer. Offline and unprivileged unless historical evidence is access-controlled. |

[Gate definitions](source-registry-migration-gates.md) ·
[Target validator](../../services/api/app/database/test_target.py) ·
[Migration credential and role contract](../../services/api/app/database/migration_guard.py) ·
[Observer adapter](../../services/api/app/database/source_registry_observer_adapter.py)

## Observer interface and missing caller contract

- **Inputs.** `capture(connection, root=..., approval=..., container=...,
  successor=False)` expects a live SQLAlchemy-style PostgreSQL/Psycopg
  connection, repository `Path`, `Approval`, and matching
  `ContainerEvidence` from `verify_container(Target(...))`. `Target` binds the
  full container ID, ordered IPv4 server/client pair, and exact observer
  login. `Approval` binds that target, manifest digest, application-isolation
  digest, and positive integer statement and row budgets. The optional
  expression reference digest is for successor verification.
- **Target and transaction.** Before any connection, validate signed inputs,
  freeze and reproduce the artifact, and verify Docker. Use explicit pinned
  loopback address, test database and restricted identity, with no ambient
  redirection. Establish one outer read-only REPEATABLE READ transaction
  per connection and a trusted search path that resolves to
  `pg_catalog`. Confirm PostgreSQL 16, expected database, server and
  client addresses and identities, origin trigger mode, transaction mode,
  and effective timeouts before application reads. The adapter accepts a
  repeatable-read or serializable snapshot and requires autocommit off,
  no nested transaction, and a valid active connection.
- **Scope and budgets.** Execute only the approved predecessor inventory and
  separately reviewed setup and supplemental reads. Enforce connection,
  statement, lock, overall and cleanup limits and open-session limits.
  Validate row budgets and account for client buffering and large row
  payloads. Abort on any breach, including inability to collect complete
  evidence within budget.
- **Snapshots and acceptance.** The adapter validates identity first, checks
  complete history visibility, binds capture to the approved inputs, and
  compares database OID, backend PID, transaction and server timestamps,
  MVCC snapshot and effective statement timeout before and after reads.
  Run `accept_predecessor` on a successful capture. Require a fresh
  independent Docker match after observations before accepting the report.
  The adapter does not perform that final Docker recheck.
- **Errors and lifecycle.** The adapter closes query results and reports
  stable rejection codes for query errors, timeouts, visibility failures,
  malformed results and drift. The caller owns all connections and
  transactions. Roll back and close on success, rejection, timeout,
  cancellation, and exceptions. Sanitize driver diagnostics and keep
  credentials, raw evidence and audit payloads out of operational logs.
  Record counts, digests, identities and failure codes only.
- **Execution boundary.** No migrations, DDL, DML, SET ROLE, migration
  advisory lock acquisition, or mutation probes. No database caller was
  created or run to prepare this packet.

## Minimal operator sequence

1. Have the custodian and independent target reviewer approve the target,
   endpoint and disposable/CONNECT evidence together.
2. Have the independent reviewers approve the candidate, isolation evidence,
   predecessor query scope, and budgets. Identify and approve the read-only
   caller with the controls above, including any required supplemental reads.
3. Confirm existing role and observer records. Have the credential custodian
   inject the two existing restricted secrets into the authorized caller
   process only after the other prerequisites pass. Record the scoped
   preflight sign-off in the trusted approval channel.
4. Keep the historical DDL discrepancy open for the separate execution
   decision until provenance or independent disposition is recorded.

## Remediated caller and launcher awaiting review

A14 has a proposed [worker](../../services/api/app/database/source_registry_preflight.py)
and [supervisor](../../services/api/app/database/source_registry_preflight_launcher.py).
There is no deployed CLI, approval store, certificate configuration, worker
bootstrap, or monitoring provider in this change. The trusted bootstrap
must come from a reviewed, immutable deployment and expose only a decision
ID to the requester.

The protected integration supplies distinct packet and authenticated pin
retrieval methods. The latter must read from an independently authenticated
approval channel. It must never compute a digest from submitted packet bytes
and use that as authorization. It verifies the frozen worker executable,
interpreter, dependencies and source snapshot before import and launch.
The typed packet binds the decision ID, reviewer, scope, validity window,
target, artifacts, inventories, login references and budgets. Use a protected
transport for secret references and process-local credential delivery.
The worker library assumes only that trusted bootstrap can supply its inputs.
It has no independent trust anchor of its own.

The operator must independently provision a durable local replay directory
owned by the supervisor UID with mode 0700 and protected ancestors.
The launcher atomically creates a decision marker, records the unique run
tag, and fsyncs the file and directory before launch. A marker is consumed
even if execution subsequently fails. Retain these records across restarts
and backup recovery. An incomplete marker is consumed too. Resolve interrupted
runs using the recorded tag and approved monitoring. Any retry needs a new
independent decision.

The worker requires an independently approved PostgreSQL CA artifact whose
bytes match the packet digest. The certificate must verify the approved IP
identity `127.0.0.1` against that CA, with a valid lifetime. The worker uses
`verify-full`, the pinned host address, the explicit CA path, and required
SCRAM channel binding. No trust store or TLS fallback is used. If the existing
server or libpq cannot meet these conditions, stop for a separate operator
decision. No certificate or server configuration was changed.

The approval also binds authenticated change-freeze evidence. The protected
provider must hold the change freeze for the exact target throughout both
sessions and reconciliation, covering DDL, role, ACL and default-privilege
changes. The worker compares catalog security digests and server identity
between independent snapshots. Equal digests cannot detect a change that
was reverted between observations. A provider unable to attest and hold the
freeze must fail before worker launch. The catalog-only search path and
reviewed SQL and bind inventories apply to both sessions.

The launcher caps the execution and success window at approval expiry. The
protected provider must prove separate recovery authority through the bounded
reconciliation deadline. It persists the freeze and registers closed-by-default
containment under the reserved run tag before startup. Scope closure revokes
future admission, terminates any remaining worker descendants, and confirms
emptiness even if startup timed out or produced no process handle. The provider
must bound its startup, transport, containment, freeze and monitoring calls.
After scope closure, independently confirm backend disappearance by run tag
and both approved identities, plus PIDs when available. Independently recheck
Docker even after ambiguous startup. Release the durable freeze only after
process, backend and target reconciliation. An uncertain release requires
separate reconciliation. No privileged database termination is in scope.
The launcher retains the approval-bound evidence digest only on verified
success. A strictly validated worker result and verified release must both
arrive before the capped success deadline.

Catalog and application reads use bounded row counts, statement and lock
timeouts, and a verified idle transaction timeout. The independent process
deadline protects against delayed Python signal handling. Row counts cannot
bound the size of a single row or every server-side operation. The monitored
target, authenticated approval sources, independent freeze mechanism,
protected credential delivery and the isolated worker bootstrap remain
deployment gates. Live TLS and PostgreSQL semantics were not exercised.

Use the [Gate 1 independent-review packet](b4-gate1-independent-review.md)
for the current candidate, fresh target observation, provider readiness,
and protected launcher admission and evidence-storage procedure.


## Gate 1 provisioning follow-up

Use the [provisioning runbook](b4-gate1-provisioning-runbook.md) and
[unsigned sign-off](b4-gate1-signoff.md) for the current candidate and
protected evidence sink. Earlier verification records retain their
historical digests.
