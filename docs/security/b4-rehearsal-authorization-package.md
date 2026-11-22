# B4 rehearsal authorization package

**Gate 1 blocked. Gate 2 blocked.** This is an unsigned request for independent
review. It supplies no PostgreSQL, migration, provisioning, or recovery
authority. Scope is exclusively the independently designated disposable
`ai_soc_test` on the exact approved local PostgreSQL 16 target. `ai_soc` is
excluded throughout. A previous read-only decision cannot authorize this
changed worker, launcher, transport, or artifact.

## Gate 1 inputs and decisions

| Requirement | Approving authority | Evidence and status | Operator action |
|---|---|---|---|
| Exact Docker target and publication | Independent target reviewer | Fresh projected Docker metadata matches the prior tuple and gives the full network ID. Independent approval of the complete tuple is missing. | Record fresh trusted metadata and approve full container, immutable image and network IDs, one network, server/gateway pair, and exclusive `127.0.0.1:5432` publication. |
| Disposable target designation | Database custodian | `ai_soc_test` is expected. Independent disposition and permitted mutation scope are missing. | Establish isolation, ownership and disposability. Record separate read-only and future fixture/mutation scopes. |
| Effective CONNECT boundary | Database security reviewer | Worker checks denial of effective CONNECT on `ai_soc` from the test session. No live evidence was collected. | Attest provisioning evidence and approve test-side corroboration. Never attempt a connection to `ai_soc`. |
| Restricted identities | Database and identity custodians | Contract names `ai_soc_test_migrator` and NOLOGIN `ai_soc_test_owner`. Actual role graph and independent observer login are unverified. | Name the approved observer and attest the restricted login, owner, exact SET-only membership, ACL and visibility expectations. |
| Protected approval channel | Independent approval authority | Launcher accepts a protected provider interface. No production trust anchor or provider is provisioned. | Install authenticated approval retrieval. Expose only the decision ID to requesters. Bind scope, target, identities, evidence and validity window. |
| Independent digest delivery | Independent artifact reviewer | Packet and expected digest use separate interfaces. | Deliver the authenticated digest from reviewer-controlled storage independently of the packet. Do not derive authorization from requester-supplied bytes. |
| Durable replay store | Platform security custodian | One-use marker records run tag with file and directory fsync. Real deployment path is missing. | Provision one authoritative supervisor-owned mode-0700 local directory with protected ancestors and recovery policy. Preserve consumed and incomplete decisions. |
| Frozen bootstrap and containment | Platform security reviewer | Frozen-source and protected process interfaces exist. No deployed bootstrap. | Pin the launcher, worker, interpreter, modules, dependencies and Git/Docker executables. Restrict entry and transport. Register durable closed-by-default containment before startup, including partial startup. Revoke admission and confirm all descendants gone on timeout. |
| TLS trust and identity | PKI and database custodians | Worker and guarded B4 transport require `verify-full`, explicit CA and SCRAM channel binding. No live TLS evidence. | Approve CA bytes and SHA-256, valid certificate with IP SAN `127.0.0.1`, and compatible libpq and server settings. |
| Administrative-change freeze | Database custodian and independent reviewer | Worker compares catalog digests between snapshots. No authenticated freeze or durable hold is provisioned. | Authenticate and hold the freeze for the exact decision and target through reconciliation. Persist the hold after crash, uncertain containment or teardown. Prevent automatic release under uncertainty. |
| Independent backend monitor and recovery authority | Database security reviewer and operator | Launcher requires confirmed process containment, backend disappearance, and final target match. Monitoring provider and recovery authorization are missing. | Approve bounded read-only monitoring on the pinned server keyed by run tag, both restricted identities, and backend PIDs/start times where known. Separately authorize needed post-expiry reconciliation. |
| Query inventories | PostgreSQL security reviewer | Worker pins predecessor observer inventory and supplemental SQL, binds and protocol. | Recompute and independently approve both exact digests and authorized monitor scope. No unreviewed SQL. |
| Resource budgets | Operations and database security reviewers | Prior packet contains proposals. No production limits approved. | Approve connection, query, lock, idle, row, session, worker and recovery ceilings, plus provider I/O and process containment. Cap execution at approval expiry. |
| Application isolation evidence | Application security reviewer | Worker binds exact supplied artifact bytes. No approved same-build evidence. | Review isolation and disabled-authority evidence for the frozen build. Authenticate its SHA-256 and deliver the artifact. |
| Current manifest candidate | Independent artifact reviewer | [Separate candidate](source-registry-execution-manifest.rehearsal-closure.candidate.json), unapproved. | Reproduce its bytes, compare against the prior 49-file candidate, review changed hashes and record the new aggregate pin. Preserve approved and prior manifests. |
| Historical DDL digest | Independent migration reviewer | `0eafe3f3` appears in issue records. Repository source and reachable history did not establish its provenance. | Before Gate 2, recover the full digest and source/toolchain or rendered SQL, or sign an explicit risk disposition tied to the rehearsal. |
| Restricted credentials | Credential custodian | No real secrets were obtained. | Deliver the existing two scoped credentials process-locally through protected bootstrap after approval. No secrets in chat, arguments, files, or logs. |
| Rehearsal scope and recovery | Operator, database custodian, independent migration reviewer | Desk plan below. No backup, isolated restoration, preflight, or rehearsal has been authorized for the current artifact or performed. | Approve Gate 1 first. Obtain distinct backup/restore and Gate 2 decisions after evidence review. |

### Exact Gate 1 request

Issue **B4 READ-ONLY PREFLIGHT ON ai_soc_test** with the independently
approved exact target, current manifest and authenticated approval pin, scoped
identities, approved TLS CA and certificate identity, query inventories, same-build
isolation evidence, held freeze and authorized monitor, enforced budgets,
execution window, expiry, and durable one-use policy. Include recovery authority
for containment and read-only monitoring after expiry. The requester supplies
only a decision ID. Credential delivery is out of band. Stop before opening a
connection if any input is missing, stale, or ambiguous.

## Gate 2 desk plan, pending a successful Gate 1

1. Reconcile the Gate 1 run, then revalidate the exact target, predecessor
   `d93c6e4fb132`, artifact, roles, freeze and writer quiescence. Record
   sanitized baseline inventory, revision, role/ACL state, evidence and
   lineage digests, tenant counts, and audit heads and chain verification.
2. Obtain separate approval for a complete database-scoped backup and isolated
   restore verification. Record backup hash, tool versions, custody, role/ACL
   prerequisites, and restored revision, schema, counts and integrity digests.
   Do not restore over an existing database. A backup without a verified
   isolated restoration does not satisfy recovery readiness.
3. Request **B4 MIGRATION REHEARSAL ON DISPOSABLE ai_soc_test** for exactly
   `e4b2b2000001`, the approved artifact and DDL pins, the historical digest
   disposition, the approved transport and execution identity, the reviewed
   SQL and mutation scope, lock and time budgets, the recovery evidence,
   permitted failure handling, post-migration probe scope, and explicit
   disposition of downgrade or restore authority. Require independent sign-off.
   The standard CLI does not supply the B4 transport capability. A separately
   reviewed execution bootstrap must inject the approved exact pin and CA into
   the guarded API, and only after this decision.
4. Expect only the disabled source-registry stage, its nine tables, reviewed
   indexes and constraints, RLS and deny-write protections, the reserved audit
   fence, and the Alembic successor entry. Verify exact catalogs, ownership,
   effective ACLs, FORCE RLS, validated tenant FKs, audit enforcement and
   unchanged historical integrity. Compare independent before/after observations
   and require the approved snapshot-bound emptiness evidence. Separately
   approved negative probes use disposable fixtures with confirmed rollback.
5. Stop on any failure or ambiguous acknowledgment. Preserve the first result,
   reconcile rollback, revision, catalog and backends using authorized
   observation, and recheck Docker. No automatic retry, downgrade, cleanup,
   or restore. The staged downgrade deliberately refuses automatic removal.
   Any destructive recovery requires its own explicit scope and authorization.

**PASS criteria** require approved records, successful guarded execution, exact
successor and expected schema, complete independent observer and probe evidence,
tenant isolation, audit and evidence integrity, confirmed teardown, final
target match, and verified recovery readiness. An omitted or unverified
required check prevents PASS.

## Manifest decision request

- Candidate SHA-256
  `8927aabc96955fb1db4dd4215a6ec94ac12f8c2e66c5c08fbcc5829015d5b099`.
- Same 49-file inventory. Seven hashes differ from the
  [prior candidate](source-registry-execution-manifest.preflight-remediation.candidate.json).
  Review the guarded runner and guard, worker and launcher, and their three
  regression modules. The revision graph, embedded pin and rendered DDL
  are identical.
- Exactly 67 statements with DDL SHA-256
  `0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4`.
- Observer inventory SHA-256
  `03a782227e4bf8cebb5052008f5ec037d51379ec22c622e767f1c8110922193a`.
  Supplemental inventory SHA-256
  `203c6f946d7a047835096cd23f9d959fa387a1de68aa8a62f9eb69abc311e38c`.
- Independently reproduce the bytes from the frozen build, review the seven
  changed inputs and transport/containment contracts, and record a scoped
  decision through the protected channel. See the
  [prior target observations](b4-readonly-preflight-approval-packet.md)
  and [implementation contract](b4-preflight-remediation-plan.md).

The [Gate 1 independent-review packet](b4-gate1-independent-review.md) records
the fresh Docker observation, current offline evidence, and the protected
launcher handoff. All current Gate 1 inputs still await independent sign-off.


## Gate 1 provisioning follow-up

Use the [provisioning runbook](b4-gate1-provisioning-runbook.md) and
[unsigned sign-off](b4-gate1-signoff.md) for the current candidate and
protected evidence sink. Earlier verification records retain their
historical digests.
