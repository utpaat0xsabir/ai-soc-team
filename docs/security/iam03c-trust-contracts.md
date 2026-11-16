# IAM-03C offline trust contracts

IAM-03C-TRUST-01, 2026-11-14. **Design only. A01–A05 PENDING; D01–D04 PROPOSED.**
No class, validator, cryptography, key, session service, database or gate is implemented
by this document. The candidate choices and limits below require owner approval.

References: [exact owner register](iam03c-owner-approval-register.md),
[future verification matrix](iam03c-trust-verification-matrix.md),
[decision package](iam03c-d01-d04-decision-package.md),
[minimum schema review](iam03c-minimum-authority-schema-review.md).

## 1. Scope, statuses and administrative gate

Separate four categories throughout:

- **EXISTING:** implemented immutable IAM records, synthetic source/admission and
  deterministic policy; actual symbols listed below.
- **PROPOSED:** RootManifest/v1 and related proof interfaces from the decision
  package, made more precise here. New details are approval candidates under A04,
  not silently approved architecture or a replacement set of duplicate IAM records.
- **UNAPPROVED:** threshold/custody, identity service, disposable target, production
  proofs/gate and MVA-1 profile. A01–A05 must be explicitly accepted in their scope.
- **UNAVAILABLE:** production issuer authentication, root crypto, complete-state
  verifier, durable human sessions, real observer/currency and execution gate.
  Today's PostgreSQL reader always denies; is_current remains False.

The owner approval register is an administrative implementation gate, not a runtime
trust token. Its PENDING cells do not become APPROVED by parsing, hashing or signing
a DB record. Future code authorization must name accepted decisions and exact file/
test scope. It cannot be inferred from this design's COMPLETE status. A06 still
requires separate execution authorization for code, credentials, service/DB setup,
migrations, roles, destructive teardown and deployment/commit/push operations.

No cryptographic private material or bearer token is a field of any proposed
record below. Public keys/signature bytes may be proof inputs in a future approved
verifier; none is generated or supplied here. No proof object is executable.

## 2. Existing contracts to reuse, not reimplement

All abbreviated code paths in this document are under `services/api/app/`.

| Existing module/symbol | Reuse / hard boundary |
| --- | --- |
| `iam/contracts.py:IAMContract`, `TenantBound`, `TenantReference`, `Digest`, `Validity` | Strict/frozen/unknown-field rejection, tenant UUIDs, SHA-256 form, finite aware validity and paired revocation; executable=False |
| `iam/contracts.py:PrincipalIdentity`, `AuthenticationReference`, `RoleAssignment`, `PermissionScope`, `Resource`, `IAMSnapshot` | Existing kind/method/catalog/scope/graph semantics and limits; no extra root/IdP flags in these records |
| `iam/contracts.py:canonical_bytes`, `contract_digest`, `validate_snapshot`, `validate_approval` | Exact existing canonical IAM hashes and graph/approval checks, not source authentication |
| `iam/policy.py:AuthorizationRequest`, `AuthorizationPolicy`, `TrustedVerification`, `evaluate` | Explicit policy and independently verified input; exact permissions/approval; no fallback or new role/action vocabulary |
| `iam/admission.py:IssuerAuthority`, `APIKeyState`, `RevocationState`, `AuthoritySnapshot`, `admit` | Runtime representations/windows; synthetic origin only, key UUID=service principal UUID; cannot accept a new human/source by relabeling |
| `iam/authority_provider.py:ComponentEpoch`, `ProviderSnapshot`, `ProviderAuthority`, `AuthorityProvider`, `ProtectedAuthorityBridge` | Ten coherent components; exact SyntheticProvider gate and pre/post epoch checks; all current output classifications synthetic-only |
| `iam/postgres_authority.py:TransactionObservation`, `InjectedReadSession`, `read`, `is_current` | Existing projected tenant/key fields, strict supplied read_only flag, Mapping/UUID checks, dedicated rollback/caller close, unsupported request rejection; observation is not provenance |
| `iam/auth.py:AuthenticatedPrincipal`, `get_current_principal`, `get_current_tenant` | Existing API-key ownership/unrevoked authentication; no human/MFA/session or independently approved credential-binding proof |
| `database/models.py:Tenant`, `TenantAPIKey`, `AuditLog`; `database/roles.py:RolePlan`; `app/db.py` | Eight existing tables, no authority graph/session/journal schema; current role-plan target whitelist and eager configured engine cannot substitute for lab isolation |

There is no existing RootManifest, trusted signature verifier, session-generation
store, Checkpoint or production VerifiedAuthorityRead implementation. An IssuanceEvidence
origin label and TrustedVerification booleans are not substitutes. Current snapshots
stay SYNTHETIC / TEST ONLY. New proof envelopes carry their own version; pure IAM
contracts remain 1.0. Compatibility exports, public auth dependencies and validators
remain unchanged.

## 3. TC-C01 — common signed envelope and deterministic inputs

This is a proposed reusable framing convention, not another permission engine.
Reuse IAM primitives above; do not create alternative tenant/digest/time types.
A new envelope body includes protocol_version, canonicalization_id, purpose,
exact tenant/source, payload ID, finite validity where relevant, and its listed
purpose-specific fields. Unknown fields/versions and missing mandatory fields deny.
Signature entries are outside the signed body and contain only signer key ID,
algorithm and signature bytes. No signature/hash includes itself.

Candidate new framing under A04: canonical ASCII JSON with sorted object keys,
explicit NULL, no floats, sorted unique set-valued tuples, strict integers (bool
is not an integer), lowercase UUID/digest strings, new-envelope timestamps in UTC
with six fractional digits and explicit offset. For binary proof fields use
lowercase hex with exact decoded lengths. OIDC subject/issuer strings retain exact
pinned/opaque values without semantic normalization. New string fields are bounded:
IAM Identifier for IDs/codes; candidate issuer URI <=512 characters, opaque subject
<=256 UTF-8 bytes. No discovery URL, pathname or code is executed from a payload.

The proposed signed frame is ASCII domain label + NUL + eight-byte unsigned
big-endian body length + canonical body bytes. Domain labels distinguish root,
issuance, recovery, state, checkpoint and identity proofs. Signature covers those
exact frame bytes; payload_sha256 hashes them. The algorithm is fixed by independently
approved trust configuration, not negotiated by a claimant. Candidate Ed25519 has
32-byte public keys/64-byte signatures; alternate algorithms need renewed approval.

**Existing IAM record digests remain exactly contract_digest(record)**. They are
nested claims in the new frame, never recomputed using this new encoding. Existing
audit hashes are untouched. Time/frame refinements above are proposals requiring
A04 acceptance; no existing serialization is changed.

Candidate bounds: <=65,536 serialized bytes per new envelope; <=262,144 combined
verification bytes and complete-state bytes; <=64 references using existing reference
bounds; <=3 root signatures for the proposed three-custodian set. Individual graph
caps remain IAM-01's caps. Enforce cap+1/oversize rejection before expensive work;
never truncate, merge duplicates or silently increase limits. A complete-state
stream has a deadline and byte cap even when a request graph is small. All time,
observations and verifier dependencies are explicit protected inputs, never default
current time or implicit I/O. No timestamps/counters alone establish authenticity.

## 4. D01 interfaces — root, rotation and recovery

### TC-R01 — independent anchors and RootManifest/v1

| Record / interface | Exact candidate fields or behavior | Trust and denial boundary |
| --- | --- | --- |
| IndependentAnchorView/v1 | Deployment/tenant scope; owner decision/pin evidence reference; root-set ID/version/digest; authorized custodian ID -> key ID/public-key/algorithm binding; required threshold; current manifest pin; validity/revoked root references | Comes only from independently authenticated operator-controlled storage, outside DB/request/Git. It is not constructed from candidate manifest keys. Candidate 2-of-3 applies only after A01 approval |
| RootManifest/v1 | Envelope + root generation, source/provider/incarnation, schema/profile/policy digests, root-set identity, authorized issuer/verifier/checkpoint public keys, record-purpose/role ceilings, validity and custodian signatures | Candidate keys describe the intended authorization but never provide their own verifying anchor. Exact tenant/source/purpose and current independent generation/pin required |
| SignatureVerifier port | Given the independently selected key/algorithm and exact frame, returns a bound valid/invalid result through protected composition; no network/key lookup URL from the envelope | Future approved production implementation performs real cryptography. A test stub is classification TEST_ONLY, not a production verifier or a caller-provided verified=True flag |
| assess_root(envelope; anchors, verifier, at) | Bounded strict parse; tenant/version/algorithm/key scope; unique signer identities; all supplied signatures valid over the same frame; count distinct authorized custodians >= approved threshold | Output is an immutable assessment bound to frame/anchor/time. No arbitrary constructor/Protocol conformance or object identity establishes production trust |

Root identity is the protected custodian/key binding, not a runtime IAM role or a
DB issuer row. A person's second key does not count as a second custodian.
Duplicate key or custodian identities deny, rather than deduplicating into quorum.
Missing signatures, unknown signer, unsupported algorithm, invalid extra signature
or insufficient distinct quorum deny. Do not ignore a bad supplied signature merely
because two others pass. Root-set mismatch, expired/revoked root or old manifest
pin denies; the body cannot choose a lower threshold or a wildcard tenant scope.

### TC-R02 — root lifecycle and RecoveryAuthorization/v1

Reuse the common root frame with a bounded operation kind: bootstrap, rotate,
revoke, recover or approve-profile. These are control-plane protocol purposes,
not new IAM Permission values. Required fields: tenant/source, exact old manifest/
checkpoint/root-set digests, proposed new digests/generation/incarnation where
applicable, exact operation/intent digest, reason code, authorized custodian IDs,
finite window and quorum signatures. No free-form recovery instructions or secrets.

Rotation requires valid current old-set quorum over the exact transition and
new-set acknowledgement over the same intent; the old-set signatures and
new-set acknowledgement signatures are separate bounded arrays outside the body,
each binding the identical transition-frame digest; independently pin the new version
only through a separately approved ceremony. Retain old proof history; do not
accept an old generation after activation. Compromised issuer/root revocation
references exact IDs, dependent authority invalidation and revision/checkpoint
transition. Revocation is not undone by key replacement or changing validity times.

Recovery requires independent quorum and preserved checkpoint/intent/audit evidence,
not a token issued by the authority under recovery. Unknown/compromised current
root cannot bless its own replacement. If independent recovery evidence cannot be
established, quarantine; there is no automatic self-healing trust path. New incarnation
never resets counters, restores deleted audit as trusted, reuses IDs or regrants
revoked rights. These ceremonies remain unavailable and unapproved.

### TC-R03 — AuthorityState/v1, Checkpoint/v1 and pending journal

| Record | Required fields / comparison |
| --- | --- |
| AuthorityState/v1 | Tenant/source/provider/incarnation; schema/profile/canonicalization IDs; approved policy/root digests and versions; persisted BIGINT revision and UUID epoch; complete-state digest; revision-event digest; audit prefix sequence/hash |
| Checkpoint/v1 | Exact AuthorityState binding; checkpoint generation/previous checkpoint digest; root-authorized checkpoint signer key ID/signature; observation/validity; authenticated independent storage evidence |
| PendingRecoveryJournal/v1 | Tenant/source; immutable intent ID/digest; expected committed checkpoint/revision; intended next revision/epoch; journal generation/previous digest; PREPARED/COMMIT_UNCERTAIN/COMMITTED_UNPUBLISHED/RECOVERY_REQUIRED evidence; authenticated signer and finite recovery authorization reference when applicable |
| JournalObservation | Independently verified current checkpoint and pending observation: CLEAR, PRESENT, CONFLICT or UNAVAILABLE; storage/run/source proof and observed generation. A missing/unreadable file is not implicitly CLEAR |
| assess_checkpoint(fresh_state; checkpoint, journal, anchors, at) | Exact bindings, signatures, current root pin, monotonic counter/epoch and complete-state digest. Produces comparison assessment only; no DB read or journal write |

Complete state covers all authority records and retained tombstones, typed registry,
source receipts/credential-binding digests and required projected existing tenant/
key/resource ownership/revocation facts, not only the requested graph. Exclude audit
rows, ledger signatures/self-digest fields and external journal/checkpoints from the
state hash to avoid cycles. Outer signed event binds audit prefix and revision.
Original IAM record hashes remain unchanged. Canonical row-group manifest must be
explicitly approved under A04/A05 before a source assembler is implemented.

In this assessor, fresh_state means a protected fresh committed-primary observation,
not an old repeatable-read snapshot. Carry separate read_checkpoint_digest and
fresh_checkpoint_digest when revisions differ. An old coherent read whose original
checkpoint verifies is content evidence only: if the fresh head matches the latest
checkpoint but differs from that read, TC-P02 returns TRUST_REVISION_STALE. Only a
fresh committed head behind the independently current checkpoint indicates
TRUST_ROLLBACK_DETECTED. Never call normal concurrent snapshot staleness proof of
DB restoration or use a historical checkpoint as the current pin.

The coordinator writes durable pending intent before authority DML; commits graph/
revision/audit atomically in DB; publishes the verified external checkpoint; then
clears pending. This is not atomic across DB/filesystem. Pending, uncertain commit,
missing proof or unsupported journal state means deny. Older DB than independent
checkpoint means rollback detected; same revision with differing authenticated
checkpoint digest means conflict; missing canonical rows means incomplete state;
well-shaped but different state digest means mismatch. No cached older anchor.

| Trusted observation combination | Deterministic eligibility result |
| --- | --- |
| Current equal state/checkpoint; verified CLEAR; no other failure | Eligible for further identity/provenance/policy checks only |
| Any verified pending or uncertain state | Recovery incomplete; no new gate |
| Same revision/epoch with divergent checkpoint claims | Checkpoint conflict; do not choose by timestamp |
| DB revision below latest trusted checkpoint | Rollback detected; no automatic restore/regrant |
| Pending with absent operation/old head | Ambiguous failed commit versus restore; recovery incomplete, independent quorum required |
| Unavailable journal/unknown source/root/unsupported generation | Deny; no inferred clear/valid state |

Simultaneous host/pin/journal compromise or co-restore lies outside the proposed
local guarantee. A01 must accept that boundary or select an independent witness.
No checkpoint, lock or signature algorithm is implemented by this specification.

## 5. D02 interfaces — human identity, session and approval

### TC-H01 — VerifiedIdentityContext/v1

Reuse PrincipalIdentity/HUMAN and AuthenticationReference/SESSION for the existing
IAM projection. Add only the missing independently verified sidecar evidence:
exact trusted IdP issuer/subject/audience; rooted enrollment reference/digest and
tenant/principal; internal session UUID and durable session generation; authenticated
session-state proof/source; issued/authenticated/observed/idle-expiry/absolute-expiry
aware times; verified assurance methods/policy; current principal/enrollment/
session revocation references. No token, password, email-as-identity or recovery code.

assess_identity(identity; trusted_idp_registration, enrollment, current_session,
request, at) checks exact source/key/assurance, tenant/kind and session/reference
binding against independent protected inputs. It never contacts an IdP or session
store by itself; a future separately approved adapter supplies authenticated fresh
observations. Token claims/session rows do not attest their own verification.

Local OIDC/WebAuthn, idle 15 minutes, absolute eight hours and fresh step-up within
five minutes are A02 candidates, not deployed requirements. No unexpired JWT,
process-local session map, group/email claim or successful login supplies a role,
tenant membership or issuer authorization. Missing current session/enrollment means
deny. Use stable issuer/subject enrollment separately from a transient session UUID;
never manufacture an api_key_id for a human to pass current key-only admission.

API_KEY_SERVICE retains existing key UUID/principal/reference equality. Production
identity proof additionally requires the independently enrolled credential-binding
digest proposed by D04, current key ownership/revocation and principal state. A DB
administrator replacing key_hash must not mint the same principal's identity. Use
the existing hash utility in the protected authentication boundary; no raw verifier
or key enters source snapshots. This proof/storage does not exist yet.

A completed session revocation first refuses new attestations and serializes
invalidation with all affected tenant gates before acknowledging completion.
Pending propagation, unknown current generation or unavailable identity state denies
new gates. IdP notifications alone are not atomic with PostgreSQL and cannot cancel
already ordered work. Issuer authentication at original issuance and current issuer
principal/key validity are separate from the requester's live session. Identity
service/storage and root bootstrap remain separate trust boundaries, both unapproved.

### TC-H02 — step-up, approval and audit projection

Step-up evidence is a bounded part of VerifiedIdentityContext/v1, not an alternate
permission/approval model: session/principal/tenant, assurance/authentication time,
exact canonical request/ProposedOperation/resource/parameter digests, challenge ID,
nonce, expiry, consumption state and authenticated identity-source proof. Candidate
challenge lifetime is 60 seconds, one-time use tracked durably; a pure assessor
cannot claim to consume a challenge. Reuse/revocation/expiry or altered operation
means deny. Privileged authorization is checked separately by unchanged IAM-02.

Reuse ApprovalRecord/validate_approval. Require a separately authenticated HUMAN
approver, not requester/executor, current approver authority, exact unchanged
operation/resource/approver representation and trusted source proof. A changed
session binding or grant graph cannot be patched into an old approval: deny/reapprove.
MVA-1 forbids such runtime workflows; no default approval or omission of required
checks is permitted because its approval table is deferred.

Reuse existing IAMAuditMetadata, AdmissionAudit and DecisionAudit rather than a new
audit schema. The proposed projection to current record_audit_event uses verified
service/system/api_key emitter type/ID, tenant, exact action/resource, correlation,
policy/state/operation/proof digests and stable reason. Verified human/session/root
intent references belong in bounded whitelisted details; never emit a human actor_type
unsupported by current AuditLog. Unknown actor/tenant is not attributed to a victim
supplied by the request. Failed authority mutation gets no revision advancement;
audit-only failure recording follows rollback when independently attributable and
available. DB outage cannot guarantee durable failure audit. No audit code is changed.

## 6. TC-L01 — D03 isolated verification target

| Interface | Required candidate input/evidence |
| --- | --- |
| IsolatedTargetSpec/v1 | Owner-authorized exact run/database/instance ID, approved PostgreSQL version, private socket path/parent, new storage/volume identity, network/mount policy, credential-source references and expected role capabilities; no credentials/DSN values |
| IndependentLauncherEvidence | Attested server/process/container identity, socket/storage ownership and paths, fresh run/volume, no production mounts or network, no external Wazuh/Ollama/IdP dependencies; originates outside candidate DB |
| ConnectedTargetEvidence | Future comparison of actual DB/server/run/login/version with that exact already-approved endpoint; actual nonowner ownership/privilege/RLS observations, bounded and sanitized |
| assess_target(spec; launcher, optional_connected_evidence, action_scope) | Pure validation returns pre-connect eligibility or specific approved-test eligibility, never opens a connection, starts a process, grants roles or authorizes generic teardown |

Pre-connect order: reject protected database names ai_soc/ai_soc_test; require exact
independently approved instance/database/socket/storage, not a prefix or DB marker;
reject symlink/path/mount/network/credential-source escape; reject defaults/.env/
.pgpass/service-file fallback; require explicit action authorization. Do not probe
protected databases to establish exclusion. Any missing proof denies before connection.

Only after a separately approved future harness connects to the attested lab may
it verify ConnectedTargetEvidence, then authorize the exact test scope. Rootless
private-socket PostgreSQL 16 is the candidate; dedicated VM/namespace is an explicit
alternative. Existing RolePlan accepts only protected names and AGENTS requires
ai_soc_test: A03 must approve a specific new-target/harness exception, not weaken
those old guards or use app.db/config's eager default connection.

Split NOLOGIN ownership/migration capability from tenant runtime/executor, read-only
provider, writer and harness logins. Verify actual nonowner login properties, fixed
tenant RLS/FKs, no SUPERUSER/BYPASSRLS/ownership/cross-tenant role switch/PUBLIC leak,
and restricted command execution. Reader never receives lock-column UPDATE. Final
write gate's necessary locking privilege needs explicit review because current
created_at UPDATE grants permit real timestamp changes. Claimed role labels are
not proof of effective privileges.

Teardown requires independently approved run identity, stopped/fenced clients,
preserved results and an explicit destructive-cleanup authorization. A passed
preflight is not permission to delete volumes/roles, and missing credentials do not
justify reusing production secrets. These interfaces neither exist nor connect now.

## 7. D04 interfaces — source, proof and execution gate

### TC-P01 — issuer/source/state and restricted profile

Reuse the proposed IssuanceRecord/v1 and AuthorityState/v1 from the decision package.
Required issuance fields: exact tenant/source/subject/issuer, purpose from current
RecordType subset, original canonical issued-record digest, finite source window,
authentication/authorization-at-issuance evidence, role ceiling and independently
approved key/root version/signature domain. Independently protected source registration
binds provider/tenant/source, connection identity, root/profile/policy pins and issuer/
verifier scopes; a request cannot select any of them.

assess_issuance(record; source_registration, root, actor, state, at) checks current
issuer principal/key/revocation/scope, exact purpose/subject/content binding, self-issue
restrictions and role ceiling. Root-approved signature proves origin only for that
scope/content, not the actor's requested permission. Unknown issuer, missing proof,
unsupported purpose or contradictory source denies, with no fallback to synthesized
issuers, assumed ACTIVE states or default roles.

MVA-1 itself is unapproved A05: explicit API_KEY_SERVICE principal, service_integration
assignment, only evidence.metadata.read, teamless evidence, explicit owner/classification/
resource scope, ALL_TENANT_TEAMS mode with independently issued TEAM_SCOPE receipt.
It does not mean every tenant resource/team is readable. Restrict and pin the schema/
profile/policy so team/human-runtime/general-admin/raw/export/approval-dependent/
external actions cannot be enabled. Missing table/query/component evidence is never
converted to empty trusted authority. The 16 retained/six deferred/one merged
proposal needs the explicit dependency-closed FK and source projection changes in
the existing minimum-schema review. No schema is expanded or implemented here.

### TC-P02 — VerifiedAuthorityRead/v1 and admission handoff

This proposed output is new production-only evidence, not a subclass/renamed
ProviderSnapshot or SyntheticAuthority. Required bindings: protocol/profile/source/
provider/tenant/incarnation; verified identity-context digest; exact request/
operation/resource/policy/IAMSnapshot digests; immutable validated graph; source/
root/issuance/checkpoint references; persistent revision/epoch; trusted aware
observation/evaluation/expiry; all ten component epochs; real transaction ID/read-only/
isolation consistency evidence; relevant current revocations and observed approval
absence/presence. No client may submit trusted verification booleans as these inputs.

assess_read(read; protected_context, source, checkpoint, fresh_head, at) must verify
complete state before selecting the request graph. Dedicated read-only repeatable-read
transaction observes a coherent view, with strict complete row schemas and no lazy
loads; real transaction observations are supplied by the protected source wrapper,
not declarations parsed from the request. A separate fresh committed primary head/
checkpoint observation checks tenant/source/incarnation/profile/root/revision/epoch
and journal state. Bind both the original read checkpoint and the independently
current checkpoint explicitly; distinguish normal stale read from actual fresh-head
rollback as in TC-R03. Same old repeatable-read view, cache or random UUID is not currency.

Keep current runtime ceilings: snapshot <=60 seconds, revocation observation age
0–15 seconds, verifier/issuer-anchor/runtime receipt <=300 seconds, with exact
bound evaluation time. Validity is clipped only by forming a **new independently
verified short-lived attestation** after authenticating original source bytes and
current state. Bind its exact projected IAM contract digest. Never edit the original
signed bytes or claim their signature covers a retimestamped receipt; no refresh
of expired/revoked source authority. Expiry is the minimum of all relevant lifetimes.

Future production handoff must supply these proofs through protected composition,
then reuse the graph/issuer/request/approval checks presently implemented in IAM-03A
and the unchanged IAM-02 evaluator. Current admit accepts exact synthetic origin
and API-key objects only: **do not feed production rows into its synthetic registry**.
A reviewed production admission entry point/output classification and shared pure
validation extraction are required, preserving existing ordering/semantics. HUMAN
admission uses principal/session proof, not a fabricated api_key_id. Current APIs,
contracts and synthetic gate are unchanged; no authoritative output is enabled.

### TC-G01 — final execution-time gate

Proposed interface: assess_and_perform_exact_operation(verified_identity, request,
expected_operation_digest; caller_write_transaction, fresh_source, checkpoint,
policy, audit_writer). It is a transaction/effect boundary, not a pure validator,
so it is excluded from the first offline prototype and unavailable now.

Preconditions: approved operational profile/action, current trusted identity/session,
no pending publication/recovery, complete rooted source, exact operation/resource/
approval and explicit caller-owned transaction. Start READ COMMITTED, acquire tenant
FOR NO KEY UPDATE then head/domain locks in approved stable order; fresh-read after
waiting, verify complete state/checkpoint/revocations/identity, rerun admission and
IAM-02, perform only the exact allowed same-DB operation plus existing audit, hold
lock through commit. Caller owns commit/close; never invoke today's rollback-owning
reader in that write transaction. No hidden engine/session or arbitrary callback
selected by request. Denial performs no protected effect.

All key/grant/issuer/resource/policy/session invalidation writers must participate
in the same protocol. If revocation completed before gate lock, old authority denies;
if gate owns lock first it is ordered before revocation. Pending propagation or
journal publication blocks new gates. An old ALLOW is never a bearer capability;
missing gate denies. Crash/unknown commit is UNKNOWN, not an automatic rollback or
retry. Reconcile immutable operation IDs/audit before another effect. A pure function
cannot certify that a caller actually held locks or committed audit atomically.

Asynchronous processes must revalidate at dispatch. Transaction locks do not cancel
earlier work or atomically control external services; unsupported external effects
remain disabled pending separate IAM-04 design. No process-local mutex/timestamp or
once-only revision check satisfies immediate completed-revocation semantics.

## 8. Deterministic denial specification

The `TRUST_*` names below are **proposed internal assessment reasons**, not changes
to existing IAM Reason/ErrorCode or public responses. Outcome contains only fixed
reason, established safe tenant/principal/correlation refs, failed stage and input/
policy digests when independently known. No raw values, source lines, tokens, keys,
SQL/driver/IdP messages or arbitrary exception text. A denial never returns a usable
snapshot, admitted result, success audit or gate receipt.

Assessors use a documented stage order; do not choose by exception timing or input
list ordering. Shared checks: protected context and byte/depth bounds first;
inspectable tenant mismatch before authority/grant selection; strict header/version;
explicit synthetic-source rejection; then strict production-body shape; independent anchor/algorithm/signer checks; signatures/
quorum/root lifecycle; state/checkpoint/recovery; identity/session/enrollment;
issuer/revision/snapshot/request/profile; actual gate/audit/transaction result.
Collections are checked for duplicates, then sorted canonically; errors within a
stage use the fixed order in this table. Existing IAM-01/02/03A evaluator/tenant
failure precedence is not replaced by this new assessment order.

| Stage | Proposed reasons in fixed within-stage order | Condition / priority |
| --- | --- | --- |
| Context/bounds | TRUST_CONTEXT_INVALID, TRUST_INPUT_LIMIT, TRUST_TENANT_MISMATCH | Missing/invalid protected identity/time; excessive bounded input; cross-tenant reference before issuer/grant lookup |
| Header/source/shape | TRUST_SCHEMA_UNSUPPORTED, TRUST_SYNTHETIC_SOURCE, TRUST_RECORD_INVALID | Unknown protocol/schema encoding; explicitly synthetic source rejected before parsing production body; then malformed/missing/extra fields |
| Root signatures | TRUST_ANCHOR_UNKNOWN, TRUST_ALGORITHM_UNSUPPORTED, TRUST_SIGNATURES_MISSING, TRUST_SIGNER_UNKNOWN, TRUST_SIGNER_DUPLICATE, TRUST_SIGNATURE_INVALID, TRUST_QUORUM_INSUFFICIENT | Independent pin required; empty signature list distinct from too few valid distinct signers; all supplied signatures must be valid |
| Root lifecycle | TRUST_ROOT_REVOKED, TRUST_ROOT_STALE | Revoked root/set/key or old/contradictory manifest generation under independent current pin |
| Checkpoint/recovery/state | TRUST_CHECKPOINT_CONFLICT, TRUST_RECOVERY_INCOMPLETE, TRUST_ROLLBACK_DETECTED, TRUST_STATE_INCOMPLETE, TRUST_STATE_DIGEST_MISMATCH | Conflicting authenticated equal-generation claims; pending/unavailable recovery; behind independent checkpoint; omitted rows; complete but different digest |
| Human/identity | TRUST_IDENTITY_INVALID, TRUST_ASSURANCE_INSUFFICIENT, TRUST_SESSION_REVOKED, TRUST_SESSION_STALE, TRUST_ENROLLMENT_MISSING, TRUST_BINDING_MISMATCH | Unknown/kind/source identity; missing MFA; revoked or expired/old session; absent tenant enrollment; key/session/operation/step-up mismatch |
| Issuance/currency/request | TRUST_ISSUER_UNAUTHORIZED, TRUST_REVISION_STALE, TRUST_SNAPSHOT_STALE, TRUST_REQUEST_UNSUPPORTED, TRUST_PROFILE_UNSUPPORTED | Wrong issuer scope/purpose; changed/unknown epoch; age/time/expiry; action/version outside current catalog; feature not allowed by independently approved profile |
| Execution | TRUST_GATE_REQUIRED, TRUST_AUDIT_UNAVAILABLE, TRUST_EXECUTION_UNKNOWN | No actual approved gate; missing atomic audit capability; uncertain commit outcome—never converted to success |
| Target/teardown branch | TRUST_TARGET_PROTECTED, TRUST_TARGET_UNVERIFIED, TRUST_PRIVILEGE_MISMATCH, TRUST_TEARDOWN_UNAUTHORIZED | D03's own preflight order after bounded context/shape; protected name before any connection, independent isolation before role proof, explicit cleanup authorization |

TC-G01 additionally distinguishes UNKNOWN from DENIED: a lost commit
acknowledgement may mean the business effect and success audit already committed.
UNKNOWN returns no success permission and blocks retries pending reconciliation;
it must not claim that rollback occurred or the effect is absent.

Pure request/profile preflight may reject a known catalog-invalid action or a
feature outside an independently approved profile before any graph/deferred-table
query. It returns only negative eligibility, never authority. Combined proof
validation still honors earlier context/root failures when both are present;
profile rejection must not be implemented by querying an absent table and treating
it as empty. Direct preflight tests explicitly exercise that branch in isolation.

Domain-specific assessors evaluate only their declared branch and common context
checks. For example assess_root does not validate session state or invent a gate;
assess_target does not create root quorum. A combined handoff evaluates applicable
branches in the fixed trust order, then current IAM admission/policy in their
existing order. Administrative approval readiness is separate PENDING/BLOCKED,
not a cryptographic success or an owner-approved runtime flag.

Future mapping can reuse existing UNVERIFIED_ORIGIN, ISSUER_UNTRUSTED,
REVOCATION_UNVERIFIED, STALE_SNAPSHOT, RECORDS_INVALID, POLICY_FAILURE or adapter
INVALID_REQUEST/read/cleanup categories without exposing private reasons. That
mapping and any new public category require approval; do not broaden an enum now.

## 9. Implementation phases and test boundary

| Phase | Future scope; every phase needs its own authorization |
| --- | --- |
| O1 | TRUST-02 root-envelope structural/canonical/quorum bookkeeping with deterministic TEST_ONLY verifier port; A01/A04 accepted subset required. No real crypto, keys, filesystem journal, DB, IdP or production success |
| O2 | Approved root crypto/proof and recovery/journal state-machine implementation/testing; operational key custody and journal I/O remain separately gated |
| O3 | D02 human/session/enrollment/step-up and D03 launcher/target contracts offline using explicit synthetic observations; no live services |
| O4 | D04 source/state/projection/production admission contract implementation after A01/A02/A04/A05; fake rows only until isolated scope authorized |
| I1 | Separately approved IAM-03D disposable DB/roles/migrations/isolation/concurrency/audit/rollback verification; A03 and target guard mandatory |
| E1 | Separately approved IAM-04 execution integration and end-to-end identity/revocation/effect verification; no external action merely because a proof parses |

Offline positive tests may return STRUCTURAL_TEST_ONLY assessment, never operational
VerifiedAuthorityRead, AdmissionOutcome/POLICY_ALLOW or an execution token. A fake
signature verifier is not evidence of cryptographic validity. No test definitions,
code or keys are created in TRUST-01. The [matrix](iam03c-trust-verification-matrix.md)
specifies future inputs/denials/evidence and separates offline from I1/E1 proof.

## 10. Unresolved decisions and validation status

A01 quorum/custodians/custody/independent storage; A02 provider/MFA/session/recovery;
A03 exact disposable/guard exception/roles; A04 precise production framing/projection/
complete-state/gate; and A05 restricted schema/FKs all remain PENDING. This document's
field/framing/limit/denial refinements need review as part of those approvals. Hardware,
IdP, identity storage and real production-key verification are not selected by fiat.

The existing proposed 23 tables and 16/6/1 reduction are not approved. Real database
isolation, concurrency, complete-state proof, cryptography, session revocation and
recovery behavior remain unverified. No production Python, SQLAlchemy model, IAM
contract, audit writer, session lifecycle, API, is_current or secret configuration
changes. Validation for this milestone is documentation/reference/status/whitespace
and input/index preservation only; prior 402/1,936/164 results are historical.

**IAM-03C-TRUST-01: COMPLETE — documentation only.**  
**OWNER APPROVALS: PENDING**  
**TRUST IMPLEMENTATION: NO-GO**  
**SCHEMA IMPLEMENTATION: NO-GO**  
**OPERATIONAL IAM: NO-GO**  
**NEXT STEP: Recommendation only — owner evidence for the scoped A01/A04 subset, then separate TRUST-02 authorization.**
