# B4 Gate 1 independent sign-off

**UNAPPROVED.** Complete through the protected approval channel. Blank or
pending entries grant no authority. This file is a review form and carries
no signature, trusted digest, credentials, or authorization.

Use the [existing authorization package](b4-rehearsal-authorization-package.md)
and [provisioning runbook](b4-gate1-provisioning-runbook.md). The
[prior target observation](b4-gate1-independent-review.md#proposed-exact-target-pin)
provides the exact comparison tuple, including the full Docker network ID.
Confirm it independently. Reconcile drift before recording a decision.

## Artifact decision

The [unapproved 49-file candidate](source-registry-execution-manifest.gate1-provisioning.candidate.json)
has SHA-256
`f363e8cd585411834bf66ac0fb3c00862947fbaa40a1082c919fdbfca9086fc7`.
The 67-statement DDL digest remains
`0fc91f8d8b76cf7e978603c5b998682a27bd77f4127516d1d85971439e880bf4`.
The predecessor is `d93c6e4fb132` and the proposed successor is
`e4b2b2000001`. Both files below changed relative to the prior candidate.
The prior candidate and approved manifest remain preserved.

| File | Candidate SHA-256 |
|---|---|
| `services/api/app/database/source_registry_preflight_launcher.py` | `1941a05d7caa2b19f64b79b1e50b6c8183933a3e9410c9ab372b0250e6ddc88a` |
| `tests/database/test_source_registry_preflight_launcher.py` | `4a03fd74f18028c5a07cc88c2f1021b13248dfbbb4e731baf0af7bf20c61c037` |

Focused offline evidence was **307 passed, 1 failed, 27 deselected**.
The enabled approved-manifest comparison was the sole failure.
The immutable worker bootstrap and all real protected provider instances
remain unprovisioned or unevidenced. Live PostgreSQL and TLS behavior
remain unverified.

## Reviewer decision matrix

Record a reviewer identity, explicit decision, approval timestamp and expiry,
and any unresolved risk for every requirement. Attach independently verified
evidence references through the protected channel. All entries remain pending.

| Requirement | Evidence reference and reviewer verification | Reviewer | Decision | Timestamp and expiry | Unresolved risk |
|---|---|---|---|---|---|
| Manifest candidate | Candidate above. Reproduce bytes and verify all 49 hashes and unchanged DDL. | — | Pending | — | — |
| Source integrity | Candidate inventory and exact checked-out files. Verify two changed files, dependencies and revision chain. | — | Pending | — | — |
| Exact Docker target | Prior tuple and fresh projected Docker evidence. Verify full container, image and network IDs, exact publication, and server/gateway pair. | — | Pending | — | — |
| Disposable database | Custodian designation and isolation evidence for `ai_soc_test`. Confirm the permitted read-only scope separately from mutation scope. | — | Pending | — | — |
| Restricted logins | Provisioning evidence for LOGIN `ai_soc_test_migrator`, NOLOGIN `ai_soc_test_owner`, and distinct observer. Verify protected credential delivery references. | — | Pending | — | — |
| Effective CONNECT | Custodian ACL and reachability evidence. Account for PUBLIC and memberships. Authorize test-side verification only. | — | Pending | — | — |
| TLS CA and server identity | PKI-attested CA digest, public chain and server certificate. Verify IP SAN, expiry, `verify-full` and required channel binding. | — | Pending | — | — |
| Approval channel and independent pin | Deployment trust-anchor and custody evidence. Verify separate authenticated packet and digest intake, revocation and requester boundary. | — | Pending | — | — |
| Durable replay store | Supervisor path, ownership and recovery records. Verify protected ancestry, mode 0700 and persistence of consumed and incomplete decisions. | — | Pending | — | — |
| Frozen worker and containment | Immutable build and executable evidence. Verify isolated worker, protected transport, admitted process scope, hard stop and recovery. | — | Pending | — | — |
| Administrative freeze | Authenticated target-specific evidence and durable hold. Verify retention through crash or uncertain cleanup. | — | Pending | — | — |
| Independent backend monitor | Approved read-only monitor and recovery authority. Verify complete coverage by identities, run tag, PIDs and backend start times when known. | — | Pending | — | — |
| Query inventory | Observer `03a782227e4bf8cebb5052008f5ec037d51379ec22c622e767f1c8110922193a`, supplemental `203c6f946d7a047835096cd23f9d959fa387a1de68aa8a62f9eb69abc311e38c`. Approve predecessor-only queries and separate monitor scope. | — | Pending | — | — |
| Application isolation | Independent same-build evidence and exact digest. Verify disabled authority and application isolation before approving its pin. | — | Pending | — | — |
| Resource limits | Budget record from the runbook and existing proposal. Verify provider, connect, SQL, row, session, execution and recovery enforcement. | — | Pending | — | — |
| Execution window and expiry | Protected decision and separate recovery record. Verify trusted clock, exact validity and one-use decision policy. | — | Pending | — | — |
| Evidence retention and cleanup | Protected sink acceptance, authenticated receipt, bounded I/O, retention policy, and incident procedure. Verify no PASS under unconfirmed storage or teardown. | — | Pending | — | — |

## Exact scope to authorize after independent closure

Issue **B4 READ-ONLY PREFLIGHT ON ai_soc_test** for the independently
reobserved and approved `ai-soc-postgres` Docker tuple and sole endpoint
`127.0.0.1:5432`, PostgreSQL 16, exact credential identities and approved IP
certificate identity. Bind the current candidate, source and same-build
isolation evidence, query inventories, approved resource ceilings, execution
start and expiry, protected credential references, authenticated freeze,
monitoring and containment, evidence storage, and bounded cleanup/recovery
authority. Specify a fresh one-use decision ID. Explicitly exclude
`ai_soc`, migrations, mutation, provisioning, and privileged recovery.

- Decision reference and authenticated digest: **pending**.
- Independent reviewer identity and signature/reference: **pending**.
- Operator decision, timestamp, window and expiry: **pending**.
- Separate recovery decision and permitted scope: **pending**.

Historical `0eafe3f3` remains a migration-execution blocker. It requires
independent provenance or explicit risk disposition at the separate Gate 2.

## Linux provisioning follow-up

The earlier 49-file artifact remains historical. The
[53-file Linux provisioning candidate](source-registry-execution-manifest.linux-provisioning.candidate.json)
has SHA-256
`ef2a34a42cfc0c65c44e095e66400e753a871a93bfcbff7c46523324e736869c`.
The [runbook](b4-gate1-provisioning-runbook.md#linux-provisioning-automation)
lists the new source inputs, local provider contracts and exact five-operation
plan. Candidate approval, host apply approval, runtime activation and Gate 1
are all pending and separate.
