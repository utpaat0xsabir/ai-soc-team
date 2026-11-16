# IAM-03C authority persistence threat model

Design only, 2026-11-14. Proposed controls are **not implemented** by this document.
Primary specification: [authority schema design](iam03c-authority-schema-design.md).
Future cases: [isolated verification plan](iam03d-isolated-verification-plan.md).
Operational IAM remains NO-GO; current adapter denies all authoritative reads and
currency checks. SEC-02 files and IAM safeguards are unchanged.

## Assets, adversaries and limits

Assets: exact tenant/principal identity, finite explicitly issued permissions,
approval separation, issuer/root provenance, current authority revision, evidence
integrity and consistent append-only authority/audit history. Test each boundary
against an unauthenticated request/model, an authenticated tenant actor without a
grant, another tenant's actor, a compromised shared runtime, a stale worker, a
malformed provider and a privileged database operator.

Proposed root verifier/operator and signed identity delivery are outside ordinary
request, LLM, DB-row and runtime-reader control. They do not yet exist operationally
(D01/D02). Compromise of that root/signer or trusted application process is not
prevented by Pydantic immutability, RLS or database digests. Infrastructure owners
can deny availability; fail closed is preferred to cached allowance.

Severity describes impact if future persistence/enforcement omits the control,
not a demonstrated bypass through today's deliberately denying adapter.

| ID | Threat / consequence | Required mitigation and fail-closed behavior | Future test |
| --- | --- | --- | --- |
| T01 | Cross-tenant role injection or assignment FK (Critical) | Composite tenant FKs for every persisted reference; fixed-tenant RLS/login; authenticated tenant predicates; no cross-tenant control command | V03: tenant A cannot reference B's principal/role/scope/issuer/resource even with colliding UUIDs |
| T02 | Forged issuer row/key/source/provenance (Critical) | Independently pinned root manifest and authenticated issuer identity; signed canonical receipt/event; exact source/purpose/role ceilings; no trust from ACTIVE/verified labels | V05: replacing row public key, source, issuer, policy or root digest without external approval denies |
| T03 | API-key ownership treated as permission (Critical) | Key maps only to key-service principal; no migration default role; explicit current assignments/resource scopes + IAM-02 intersection | V04: valid same-tenant key with no explicit role denies every protected action |
| T04 | Replay of an old valid snapshot (Critical) | Fresh committed head comparison and approved incarnation; final execution gate reassembles/revalidates exact state under common lock; no bearer ALLOW | V08/V10: replay old epoch/time/request/operation after revision change denies |
| T05 | Concurrent role/key revocation after allowance (Critical) | Common tenant lock for every authority writer and final DB action through commit; re-read after waiting. Revocation completion never precedes a conflicting already-held gate's commit | V09/V10: deterministic barriers exercise both operation-first and revocation-first ordering; no post-revocation stale commit |
| T06 | Untrusted runtime modifies grants or revision directly (Critical) | No authority DML/owner privileges; tenant-bound restricted command EXECUTE, scoped issuer signature, policy/human intent checks and deferred audit/revision consistency | V06/V07: real nonowner logins cannot UPDATE/INSERT/DELETE authority, change tenant or call another tenant/root command |
| T07 | DBA disables constraints/RLS/audit or restores old signed rows (Critical) | Signatures detect fabricated changed content; root-controlled restore/incarnation and external rollback/completeness policy required. RLS/hash chains alone cannot stop owner. D01 BLOCKED until threat boundary or external witness protocol approved | V15: restore/replay and omission tests must deny under approved protocol; without it record failed acceptance, never claim prevention |
| T08 | Partial joins, missing receipts or silently truncated graphs (High) | Exact row schemas; full relevant closure and observed approval absence; cap+1 overflow detection; no defaults; signed values still need completeness/source trust | V11: remove any principal/receipt/team/scope/revision component, exceed every cap, or omit relevant tombstone -> deny |
| T09 | Audit omitted while authority change commits (Critical) | Same transaction, revision->tenant/audit-sequence FK, restricted commands, deferred row/event/audit checks; existing writer unchanged | V12: fail audit insert/flush/command/deferred checks; no authority/revision/audit-success persists |
| T10 | Rollback leaves incremented revision or effective grant (Critical) | Transactional head/ledger/tombstones/graph/audit updates; no process counter; retained operation ID with reconciled outcome | V12/V13: injected failure at each stage restores original state; uncertain commit cannot be assumed failed |
| T11 | Malformed roles/actions/revisions or duplicate assignments (High) | Exact existing literal catalogs and CHECKs; tenant FKs/typed registry; partial uniqueness and graph revalidation; unsupported versions deny | V02/V11: wildcard/unknown action/role, wrong UUID/columns, NULL required values, conflicting grants and impossible windows reject |
| T12 | Default-role escalation during migration/backfill (Critical) | Only suspended revision-0 heads, no implicit issuer/policy/grant; key enrollment explicitly approved and no authority derived from row existence | V01/V04: existing tenants/keys retain no IAM permissions after upgrade |
| T13 | Issuer or requester self-escalates via valid signing key (Critical) | Exact tenant/source/record types and explicit role ceiling; issuer!=assignment subject; independent human roles.assign authority/approval; root trust changes not ordinary grants | V05/V16: valid signer outside ceiling, self-assignment, API service control-plane substitution or forged human approval denies |
| T14 | Same UUID used for unrelated object kinds poisons revocation (High) | Tenant-wide typed object registry, deferred subtype consistency; only explicit key/principal alias; no ID reuse | V03: principal/resource/epoch collision rejected; revoking one unrelated object cannot be interpreted as another |
| T15 | Cached or replica-lagged currency passes old authority (Critical) | Independent primary/fresh committed read; exact tenant/source/incarnation/epoch; observer/time never substitutes for persistent revision | V08: repeatable-read observer remains stale; separate fresh currency detects changed head; unavailable current proof denies |
| T16 | Pool, role switching or attacker-set tenant GUC leaks rows (Critical) | Fixed-tenant policy/login; no cross-role membership; no request-controlled DB role/GUC identity; verify session binding after pooling | V06: malicious tenant parameters/GUC/SET ROLE and reused connections cannot read or mutate B's authority |
| T17 | Altered resource/approval/policy scope or model-produced permission (Critical) | Signed normalized scope, pinned policy digest; complete resource/operation/approver canonical binding; proposal != consent != execute; unknown backing resolver denies | V16: change one parameter, classification, owner, team, approval, resource or policy byte and deny; metadata never implies raw/export |
| T18 | Outbox/remote effect continues after revocation or rollback (Critical) | No operational external actions until separately reviewed IAM-04 dispatch/fencing/idempotency and in-flight semantics. DB revision alone cannot undo remote work | V18: stale queued work denies on dispatch; unsupported remote execution remains disabled; no false atomicity claim |
| T19 | Serialization retry or lost commit creates duplicate authority (High) | Abort whole transaction; bounded retry reauthorizes immutable intent; unique operation_id and digest conflict; UNKNOWN outcome reconciliation before retry | V13/V14: retryable errors, lost commit acknowledgement and changed-intent operation reuse never create duplicate grants/revisions |
| T20 | Secret/raw evidence leaks through audit/errors/signature metadata (High) | Project IDs/digests/public verification keys only; sanitized errors/details; no keys/passwords/prompts/raw evidence/private signing material in graph or diagnostic output | V17: canary exceptions and invalid payloads produce stable categories with no confidential input echo |
| T21 | Expiry/root revocation not included in ordinary grant checks (Critical) | Validate finite windows at trusted final gate/start; include issuer/provider/policy/root revocation and trust-manifest changes in invalidation protocol | V08/V16: expired actor/issuer/receipt/approval and revoked root/source deny despite unchanged role name |
| T22 | Deadlock or unbounded gate blocks emergency revocation (High) | Tenant-first consistent lock order; bounded statement/lock/transaction lifetime; no external I/O while holding gate; cancellation/connection failure aborts | V09/V14: inverse/interleaved work cannot commit out of order; timeouts deny and release locks without partial audit |

## Revocation guarantee and residual risk

The proposed guarantee is commit-linearized for compliant authority writers and
same-database execution gates on a trusted primary. An operation that already owns
the tenant gate is ordered before revocation; revocation waits until it completes
or aborts. After revocation commits, a subsequent gate cannot use the old grant.
This is not instantaneous cancellation of running work, expiry-time rollback,
network delivery atomicity or immunity to privileged database rollback.

All key/principal/issuer/provider/resource/policy/approval changes must participate
in the common protocol. A single remaining raw revocation/provisioning writer
invalidates the guarantee. Unavailable signatures, root mapping, current revision,
identity source, complete graph or audit capability means deny, never stale fallback.

Signatures protect integrity/origin only under authentic independent keys. They do
not prove that a query included every required revocation or that the entire DB
was not reverted. Audit hash chains detect inconsistency relative to a trusted
anchor, not an owner who can rewrite the whole unanchored history. D01 explicitly
blocks any stronger administrator-compromise guarantee until that trust decision
or witness protocol is approved and tested. No external anchoring service is
implemented or contacted in this milestone.

## Acceptance and blockers

Every T row maps to at least one V case in the isolated plan; those V cases are
future requirements, not passed tests. D01–D04 remain BLOCKED as defined in the
schema design. Existing synthetic test results prove only unchanged offline
contracts and denial boundaries. No new vulnerability in the current denying
adapter is asserted by this proposed-system threat analysis.

**Operational IAM authority: NO-GO.** Resolve trust/identity/privilege/production
contract decisions before implementing or testing persistence on any database.
